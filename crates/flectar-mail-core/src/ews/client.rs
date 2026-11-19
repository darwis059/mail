//! Minimal EWS (Exchange Web Services) SOAP client for on-prem Exchange (NTLM or Basic auth).

use std::fmt;
use std::time::Duration;
use tokio::sync::Mutex;

use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};

use super::{AuthMode, ntlm};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};

/// MAPI PR_FLAG_STATUS (2 = flagged).
const PROP_FLAG_STATUS: &str = "0x1090";
/// MAPI PR_LAST_VERB_EXECUTED (102 reply, 103 reply all, 104 forward).
const PROP_LAST_VERB: &str = "0x1081";
/// MAPI PR_MESSAGE_FLAGS (1 = read; clearing "unsent" so APPENDed mail is not a draft).
const PROP_MESSAGE_FLAGS: &str = "0x0E07";

/// Returned (wrapped in anyhow) when Exchange rejects the credentials.
#[derive(Debug)]
pub struct AuthFailed;

impl fmt::Display for AuthFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Exchange rejected the username or password")
    }
}

impl std::error::Error for AuthFailed {}

pub struct EwsConfig {
    pub url: String,
    pub insecure: bool,
    /// Windows domain for logins given without `DOMAIN\` or `@`.
    pub default_domain: Option<String>,
    pub auth: AuthMode,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Unknown,
    Basic,
    Ntlm { authed: bool },
}

pub struct EwsClient {
    http: reqwest::Client,
    url: String,
    domain: String,
    user: String,
    pass: String,
    state: Mutex<State>,
}

/// -> (domain, user)
///
/// A UPN always keeps its full spelling and has an empty NTLM domain.
fn split_login(login: &str, default_domain: Option<&str>) -> (String, String) {
    let login = login.trim();
    if let Some((d, u)) = login.split_once('\\') {
        return (d.to_string(), u.to_string());
    }
    match (
        login.rsplit_once('@'),
        default_domain.filter(|d| !d.is_empty()),
    ) {
        (Some(_), _) => (String::new(), login.to_string()),
        (None, d) => (d.unwrap_or("").to_string(), login.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::split_login;

    #[test]
    fn login_forms() {
        let s = |l, d| split_login(l, d);
        assert_eq!(
            s("pusat\\bob", Some("other")),
            ("pusat".into(), "bob".into())
        );
        assert_eq!(s("bob", Some("pusat")), ("pusat".into(), "bob".into()));
        assert_eq!(
            s("bob@pln.co.id", Some("pusat")),
            ("".into(), "bob@pln.co.id".into())
        );
        assert_eq!(
            s(" bob@pln.co.id ", Some("pusat")),
            ("".into(), "bob@pln.co.id".into())
        );
        assert_eq!(
            s("bob@pln.co.id", None),
            ("".into(), "bob@pln.co.id".into())
        );
        assert_eq!(s("bob", None), ("".into(), "bob".into()));
    }
}

#[derive(Clone, Debug)]
pub struct Folder {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct ItemInfo {
    pub id: String,
    pub is_read: bool,
    pub flagged: bool,
    pub answered: bool,
    pub forwarded: bool,
    pub draft: bool,
    pub received: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug)]
pub enum FlagChange {
    Read(bool),
    Flagged(bool),
    Answered(bool),
    Forwarded(bool),
}

/// Well-known folder ids, resolved once per login.
#[derive(Clone, Debug, Default)]
pub struct WellKnown {
    pub root: String,
    pub inbox: Option<String>,
    pub drafts: Option<String>,
    pub sent: Option<String>,
    pub trash: Option<String>,
    pub junk: Option<String>,
}

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn child_text<'a>(n: Node<'a, '_>, name: &str) -> Option<&'a str> {
    child(n, name).and_then(|c| c.text())
}

fn item_ids_xml(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!(r#"<t:ItemId Id="{}"/>"#, xml_escape(id)))
        .collect()
}

fn ext_uri(tag: &str) -> String {
    format!(r#"<t:ExtendedFieldURI PropertyTag="{tag}" PropertyType="Integer"/>"#)
}

fn same_tag(a: &str, b: &str) -> bool {
    let parse =
        |s: &str| u32::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok();
    parse(a).is_some() && parse(a) == parse(b)
}

/// One `*ResponseMessage` element: success flag, error text, and the node.
struct Resp<'a, 'i> {
    ok: bool,
    code: String,
    text: String,
    node: Node<'a, 'i>,
}

fn response_messages<'a, 'i>(doc: &'a Document<'i>) -> Vec<Resp<'a, 'i>> {
    doc.descendants()
        .filter(|n| n.is_element() && n.tag_name().name().ends_with("ResponseMessage"))
        .map(|n| Resp {
            ok: n.attribute("ResponseClass") != Some("Error"),
            code: child_text(n, "ResponseCode").unwrap_or("").to_string(),
            text: child_text(n, "MessageText").unwrap_or("").to_string(),
            node: n,
        })
        .collect()
}

fn first_error(doc: &Document) -> Result<()> {
    let messages = response_messages(doc);
    if messages.is_empty() {
        bail!("EWS reply is missing its operation result");
    }
    for r in messages {
        if !r.ok {
            bail!("EWS error {}: {}", r.code, r.text);
        }
    }
    Ok(())
}

// Draining permits the HTTP pool to reuse the TCP connection for NTLM.
async fn drain(mut response: reqwest::Response) -> reqwest::Result<()> {
    while response.chunk().await?.is_some() {}
    Ok(())
}

impl EwsClient {
    /// `login` may be `DOMAIN\user`, `user@domain` (UPN) or a bare `user` (gets the default domain).
    /// Each client has its own single-connection HTTP pool, because NTLM authenticates a connection.
    pub fn new(cfg: &EwsConfig, login: &str, pass: &str) -> Result<Self> {
        let (domain, user) = split_login(login, cfg.default_domain.as_deref());
        let http = reqwest::Client::builder()
            .http1_only()
            .pool_max_idle_per_host(1)
            .tls_danger_accept_invalid_certs(cfg.insecure)
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("FlectarMail/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let state = match cfg.auth {
            AuthMode::Auto => State::Unknown,
            AuthMode::Basic => State::Basic,
            AuthMode::Ntlm => State::Ntlm { authed: false },
        };
        Ok(Self {
            http,
            url: cfg.url.clone(),
            domain,
            user,
            pass: pass.to_string(),
            state: Mutex::new(state),
        })
    }

    /// Stable key for this mailbox, e.g. `pusat\user`.
    pub fn account(&self) -> String {
        if self.domain.is_empty() {
            self.user.to_lowercase()
        } else {
            format!("{}\\{}", self.domain, self.user).to_lowercase()
        }
    }

    async fn post(&self, body: String, auth: Option<String>) -> Result<reqwest::Response> {
        let mut req = self
            .http
            .post(&self.url)
            .header("Content-Type", "text/xml; charset=utf-8")
            .body(body);
        if let Some(a) = auth {
            let mut value = reqwest::header::HeaderValue::from_str(&a)
                .context("invalid EWS authorization value")?;
            value.set_sensitive(true);
            req = req.header(AUTHORIZATION, value);
        }
        req.send()
            .await
            .with_context(|| format!("cannot reach EWS at {}", self.url))
    }

    fn basic_header(&self) -> String {
        let user = if self.domain.is_empty() {
            self.user.clone()
        } else {
            format!("{}\\{}", self.domain, self.user)
        };
        format!("Basic {}", B64.encode(format!("{user}:{}", self.pass)))
    }

    /// NTLM handshake on one kept-alive connection; returns the response to the real request.
    async fn ntlm(&self, envelope: &str) -> Result<reqwest::Response> {
        // Send the real body: IIS answers an empty POST with 411 Length Required.
        let r1 = self
            .post(
                envelope.to_string(),
                Some(format!("NTLM {}", B64.encode(ntlm::negotiate()))),
            )
            .await?;
        if r1.status() != StatusCode::UNAUTHORIZED {
            bail!("NTLM negotiate: unexpected HTTP {}", r1.status());
        }
        let challenge = r1
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix("NTLM "))
            .map(str::to_string);
        drain(r1).await.context("reading NTLM challenge response")?;
        let challenge = challenge.ok_or_else(|| anyhow!("Exchange sent no NTLM challenge"))?;
        let ch = ntlm::Challenge::parse(&B64.decode(challenge.trim())?)?;
        let t3 = ntlm::authenticate(&ch, &self.user, &self.domain, &self.pass)?;
        self.post(
            envelope.to_string(),
            Some(format!("NTLM {}", B64.encode(t3))),
        )
        .await
    }

    async fn call(&self, body: &str) -> Result<String> {
        let envelope = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
<soap:Header><t:RequestServerVersion Version="Exchange2010_SP2"/></soap:Header>
<soap:Body>{body}</soap:Body>
</soap:Envelope>"#
        );
        // The guard covers the entire exchange, including reading response bodies.
        // A pool size of one alone does not prevent concurrent TCP connections.
        let mut guard = self.state.lock().await;
        let state = *guard;
        let mut used = state;
        let mut resp = match state {
            State::Basic => {
                self.post(envelope.clone(), Some(self.basic_header()))
                    .await?
            }
            State::Ntlm { authed: false } => self.ntlm(&envelope).await?,
            // Auth probe, or a connection NTLM already authenticated.
            State::Unknown | State::Ntlm { authed: true } => {
                self.post(envelope.clone(), None).await?
            }
        };
        if resp.status() == StatusCode::UNAUTHORIZED
            && matches!(state, State::Unknown | State::Ntlm { authed: true })
        {
            let offers: Vec<String> = resp
                .headers()
                .get_all(WWW_AUTHENTICATE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|v| v.split(' ').next().unwrap_or("").to_ascii_lowercase())
                .collect();
            drain(resp)
                .await
                .context("reading authentication response")?;
            let use_ntlm = state != State::Unknown || offers.iter().any(|o| o == "ntlm");
            if use_ntlm {
                used = State::Ntlm { authed: false };
                resp = self.ntlm(&envelope).await?;
            } else if offers.iter().any(|o| o == "basic") {
                used = State::Basic;
                resp = self
                    .post(envelope.clone(), Some(self.basic_header()))
                    .await?;
            } else {
                bail!("Exchange offers neither NTLM nor Basic authentication");
            }
        }
        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let _ = drain(resp).await;
            if matches!(*guard, State::Ntlm { .. }) {
                *guard = State::Ntlm { authed: false };
            }
            return Err(anyhow!(AuthFailed));
        }
        *guard = match used {
            State::Ntlm { .. } => State::Ntlm { authed: true },
            other => other,
        };
        let limit = if body.starts_with("<m:GetItem>") {
            192 * 1024 * 1024
        } else {
            16 * 1024 * 1024
        };
        let text = crate::http_body::text(resp, limit, "EWS response").await?;
        if !status.is_success() {
            // SOAP faults come back as HTTP 500 with a faultstring.
            let fault = Document::parse(&text)
                .ok()
                .and_then(|d| {
                    d.descendants()
                        .find(|n| n.tag_name().name() == "faultstring")
                        .and_then(|n| n.text().map(str::to_string))
                })
                .unwrap_or_else(|| "unexpected HTTP response".to_owned());
            bail!("EWS HTTP {status}: {fault}");
        }
        Ok(text)
    }

    /// Resolves the well-known folders. Also serves as the credential check at LOGIN.
    pub async fn well_known(&self) -> Result<WellKnown> {
        let names = [
            "msgfolderroot",
            "inbox",
            "drafts",
            "sentitems",
            "deleteditems",
            "junkemail",
        ];
        let ids: String = names
            .iter()
            .map(|n| format!(r#"<t:DistinguishedFolderId Id="{n}"/>"#))
            .collect();
        let body = format!(
            r#"<m:GetFolder><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape><m:FolderIds>{ids}</m:FolderIds></m:GetFolder>"#
        );
        let xml = self.call(&body).await?;
        let doc = Document::parse(&xml)?;
        let found: Vec<Option<String>> = response_messages(&doc)
            .into_iter()
            .map(|r| {
                r.ok.then(|| {
                    r.node
                        .descendants()
                        .find(|n| n.tag_name().name() == "FolderId")
                        .and_then(|n| n.attribute("Id"))
                        .map(str::to_string)
                })
                .flatten()
            })
            .collect();
        let get = |i: usize| found.get(i).cloned().flatten();
        Ok(WellKnown {
            root: get(0).ok_or_else(|| anyhow!("mailbox root folder not found"))?,
            inbox: get(1),
            drafts: get(2),
            sent: get(3),
            trash: get(4),
            junk: get(5),
        })
    }

    /// All mail folders below the mailbox root.
    pub async fn find_folders(&self) -> Result<Vec<Folder>> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let body = format!(
                r#"<m:FindFolder Traversal="Deep"><m:FolderShape><t:BaseShape>Default</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="folder:ParentFolderId"/><t:FieldURI FieldURI="folder:FolderClass"/></t:AdditionalProperties></m:FolderShape><m:IndexedPageFolderView MaxEntriesReturned="500" Offset="{offset}" BasePoint="Beginning"/><m:ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/></m:ParentFolderIds></m:FindFolder>"#
            );
            let xml = self.call(&body).await?;
            let doc = Document::parse(&xml)?;
            first_error(&doc)?;
            let root = doc
                .descendants()
                .find(|n| n.tag_name().name() == "RootFolder")
                .ok_or_else(|| anyhow!("FindFolder: no RootFolder"))?;
            if let Some(folders) = child(root, "Folders") {
                for f in folders.children().filter(|n| n.is_element()) {
                    // Only plain mail folders: skip calendar, contacts, tasks, search folders.
                    if f.tag_name().name() != "Folder" {
                        continue;
                    }
                    let class = child_text(f, "FolderClass").unwrap_or("");
                    if !(class.is_empty() || class.starts_with("IPF.Note")) {
                        continue;
                    }
                    let Some(id) = child(f, "FolderId").and_then(|n| n.attribute("Id")) else {
                        continue;
                    };
                    out.push(Folder {
                        id: id.to_string(),
                        parent_id: child(f, "ParentFolderId")
                            .and_then(|n| n.attribute("Id"))
                            .map(str::to_string),
                        name: child_text(f, "DisplayName").unwrap_or("").to_string(),
                    });
                }
            }
            match root.attribute("IncludesLastItemInRange") {
                Some("true") => break,
                Some("false") => {}
                _ => bail!("EWS paging response is missing its completion marker"),
            }
            let next = root
                .attribute("IndexedPagingOffset")
                .and_then(|s| s.parse().ok())
                .or_else(|| offset.checked_add(500))
                .filter(|next| *next > offset)
                .ok_or_else(|| anyhow!("EWS paging offset did not advance"))?;
            offset = next;
        }
        Ok(out)
    }

    /// Every item in a folder, oldest first.
    pub async fn find_items(&self, folder_id: &str) -> Result<Vec<ItemInfo>> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        let fid = xml_escape(folder_id);
        let (flag, verb) = (ext_uri(PROP_FLAG_STATUS), ext_uri(PROP_LAST_VERB));
        loop {
            let body = format!(
                r#"<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="message:IsRead"/><t:FieldURI FieldURI="item:DateTimeReceived"/><t:FieldURI FieldURI="item:IsDraft"/>{flag}{verb}</t:AdditionalProperties></m:ItemShape><m:IndexedPageItemView MaxEntriesReturned="1000" Offset="{offset}" BasePoint="Beginning"/><m:SortOrder><t:FieldOrder Order="Ascending"><t:FieldURI FieldURI="item:DateTimeReceived"/></t:FieldOrder></m:SortOrder><m:ParentFolderIds><t:FolderId Id="{fid}"/></m:ParentFolderIds></m:FindItem>"#
            );
            let xml = self.call(&body).await?;
            let doc = Document::parse(&xml)?;
            first_error(&doc)?;
            let root = doc
                .descendants()
                .find(|n| n.tag_name().name() == "RootFolder")
                .ok_or_else(|| anyhow!("FindItem: no RootFolder"))?;
            if let Some(items) = child(root, "Items") {
                for it in items.children().filter(|n| n.is_element()) {
                    let Some(id) = child(it, "ItemId").and_then(|n| n.attribute("Id")) else {
                        continue;
                    };
                    let mut info = ItemInfo {
                        id: id.to_string(),
                        is_read: child_text(it, "IsRead")
                            .map(|s| s == "true")
                            .unwrap_or(true),
                        flagged: false,
                        answered: false,
                        forwarded: false,
                        draft: child_text(it, "IsDraft") == Some("true"),
                        received: child_text(it, "DateTimeReceived")
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .map(|d| d.with_timezone(&Utc))
                            .unwrap_or_else(Utc::now),
                    };
                    for ep in it
                        .children()
                        .filter(|n| n.tag_name().name() == "ExtendedProperty")
                    {
                        let tag = child(ep, "ExtendedFieldURI")
                            .and_then(|n| n.attribute("PropertyTag"))
                            .unwrap_or("");
                        let val: i64 = child_text(ep, "Value")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        if same_tag(tag, PROP_FLAG_STATUS) {
                            info.flagged = val == 2;
                        } else if same_tag(tag, PROP_LAST_VERB) {
                            info.answered = val == 102 || val == 103;
                            info.forwarded = val == 104;
                        }
                    }
                    out.push(info);
                }
            }
            match root.attribute("IncludesLastItemInRange") {
                Some("true") => break,
                Some("false") => {}
                _ => bail!("EWS paging response is missing its completion marker"),
            }
            let next = root
                .attribute("IndexedPagingOffset")
                .and_then(|s| s.parse().ok())
                .or_else(|| offset.checked_add(1000))
                .filter(|next| *next > offset)
                .ok_or_else(|| anyhow!("EWS paging offset did not advance"))?;
            offset = next;
        }
        Ok(out)
    }

    /// Raw RFC 822 content per item id, in the same order. A failed item gives an `Err`.
    pub async fn get_mime(&self, ids: &[String]) -> Result<Vec<Result<Vec<u8>>>> {
        let body = format!(
            r#"<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape><m:ItemIds>{}</m:ItemIds></m:GetItem>"#,
            item_ids_xml(ids)
        );
        let xml = self.call(&body).await?;
        let doc = Document::parse(&xml)?;
        let resps = response_messages(&doc);
        if resps.len() != ids.len() {
            bail!(
                "GetItem returned {} responses for {} items",
                resps.len(),
                ids.len()
            );
        }
        Ok(resps
            .into_iter()
            .map(|r| {
                if !r.ok {
                    bail!("{}: {}", r.code, r.text);
                }
                let b64: String = r
                    .node
                    .descendants()
                    .find(|n| n.tag_name().name() == "MimeContent")
                    .and_then(|n| n.text())
                    .ok_or_else(|| anyhow!("item has no MIME content"))?
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                Ok(B64.decode(b64.as_bytes())?)
            })
            .collect())
    }

    pub async fn update_flags(&self, changes: &[(String, Vec<FlagChange>)]) -> Result<()> {
        let mut xml_changes = String::new();
        for (id, ch) in changes {
            let mut updates = String::new();
            for c in ch {
                let (tag, set) = match *c {
                    FlagChange::Read(v) => {
                        updates.push_str(&format!(
                            r#"<t:SetItemField><t:FieldURI FieldURI="message:IsRead"/><t:Message><t:IsRead>{v}</t:IsRead></t:Message></t:SetItemField>"#
                        ));
                        continue;
                    }
                    FlagChange::Flagged(v) => (PROP_FLAG_STATUS, v.then_some(2)),
                    FlagChange::Answered(v) => (PROP_LAST_VERB, v.then_some(102)),
                    FlagChange::Forwarded(v) => (PROP_LAST_VERB, v.then_some(104)),
                };
                let uri = ext_uri(tag);
                match set {
                    Some(val) => updates.push_str(&format!(
                        r#"<t:SetItemField>{uri}<t:Message><t:ExtendedProperty>{uri}<t:Value>{val}</t:Value></t:ExtendedProperty></t:Message></t:SetItemField>"#
                    )),
                    None => updates.push_str(&format!(r#"<t:DeleteItemField>{uri}</t:DeleteItemField>"#)),
                }
            }
            if !updates.is_empty() {
                xml_changes.push_str(&format!(
                    r#"<t:ItemChange><t:ItemId Id="{}"/><t:Updates>{updates}</t:Updates></t:ItemChange>"#,
                    xml_escape(id)
                ));
            }
        }
        if xml_changes.is_empty() {
            return Ok(());
        }
        let body = format!(
            r#"<m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AlwaysOverwrite"><m:ItemChanges>{xml_changes}</m:ItemChanges></m:UpdateItem>"#
        );
        let xml = self.call(&body).await?;
        first_error(&Document::parse(&xml)?)
    }

    /// Moves items to Deleted Items (or soft-deletes them if they are already there).
    pub async fn delete_items(&self, ids: &[String]) -> Result<()> {
        let body = format!(
            r#"<m:DeleteItem DeleteType="MoveToDeletedItems"><m:ItemIds>{}</m:ItemIds></m:DeleteItem>"#,
            item_ids_xml(ids)
        );
        let xml = self.call(&body).await?;
        let doc = Document::parse(&xml)?;
        let results = response_messages(&doc);
        if results.len() != ids.len() {
            bail!(
                "DeleteItem returned {} results for {} items",
                results.len(),
                ids.len()
            );
        }
        for r in results {
            if !r.ok && r.code != "ErrorItemNotFound" {
                bail!("EWS error {}: {}", r.code, r.text);
            }
        }
        Ok(())
    }

    pub async fn move_or_copy(
        &self,
        ids: &[String],
        to_folder: &str,
        copy: bool,
    ) -> Result<Vec<String>> {
        let op = if copy { "CopyItem" } else { "MoveItem" };
        let body = format!(
            r#"<m:{op}><m:ToFolderId><t:FolderId Id="{}"/></m:ToFolderId><m:ItemIds>{}</m:ItemIds></m:{op}>"#,
            xml_escape(to_folder),
            item_ids_xml(ids)
        );
        let xml = self.call(&body).await?;
        let doc = Document::parse(&xml)?;
        first_error(&doc)?;
        Ok(doc
            .descendants()
            .filter(|n| n.tag_name().name() == "ItemId")
            .filter_map(|n| n.attribute("Id").map(str::to_owned))
            .collect())
    }

    /// Sends a raw RFC 822 message. Exchange takes To/Cc/Bcc from the headers; `extra_bcc`
    /// adds envelope recipients that are not in them. `save_copy` stores it in Sent Items.
    pub async fn send_mime(
        &self,
        mime: &[u8],
        extra_bcc: &[String],
        save_copy: bool,
    ) -> Result<()> {
        let (disposition, saved) = if save_copy {
            (
                "SendAndSaveCopy",
                r#"<m:SavedItemFolderId><t:DistinguishedFolderId Id="sentitems"/></m:SavedItemFolderId>"#,
            )
        } else {
            ("SendOnly", "")
        };
        let bcc = if extra_bcc.is_empty() {
            String::new()
        } else {
            let list: String = extra_bcc
                .iter()
                .map(|a| {
                    format!(
                        "<t:Mailbox><t:EmailAddress>{}</t:EmailAddress></t:Mailbox>",
                        xml_escape(a)
                    )
                })
                .collect();
            format!("<t:BccRecipients>{list}</t:BccRecipients>")
        };
        let body = format!(
            r#"<m:CreateItem MessageDisposition="{disposition}">{saved}<m:Items><t:Message><t:MimeContent>{}</t:MimeContent>{bcc}</t:Message></m:Items></m:CreateItem>"#,
            B64.encode(mime)
        );
        let xml = self.call(&body).await?;
        first_error(&Document::parse(&xml)?)
    }

    /// Stores a raw RFC 822 message in a folder (IMAP APPEND).
    pub async fn create_item(
        &self,
        folder_id: &str,
        mime: &[u8],
        seen: bool,
        draft: bool,
    ) -> Result<String> {
        let flags = if draft {
            String::new()
        } else {
            let uri = ext_uri(PROP_MESSAGE_FLAGS);
            format!(
                r#"<t:ExtendedProperty>{uri}<t:Value>{}</t:Value></t:ExtendedProperty>"#,
                seen as u8
            )
        };
        let body = format!(
            r#"<m:CreateItem MessageDisposition="SaveOnly"><m:SavedItemFolderId><t:FolderId Id="{}"/></m:SavedItemFolderId><m:Items><t:Message><t:MimeContent>{}</t:MimeContent>{flags}</t:Message></m:Items></m:CreateItem>"#,
            xml_escape(folder_id),
            B64.encode(mime)
        );
        let xml = self.call(&body).await?;
        let doc = Document::parse(&xml)?;
        first_error(&doc)?;
        doc.descendants()
            .find(|n| n.tag_name().name() == "ItemId")
            .and_then(|n| n.attribute("Id"))
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("CreateItem returned no item id"))
    }
}
