//! Direct client integration against the reference connection-authenticated mock.

use flectar_mail_core::ews::{
    AuthMode,
    client::{AuthFailed, EwsClient, EwsConfig, FlagChange},
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

const M: &str = "http://schemas.microsoft.com/exchange/services/2006/messages";
const T: &str = "http://schemas.microsoft.com/exchange/services/2006/types";

const MSG1: &str = "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: Hello\r\nDate: Mon, 16 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nFirst body\r\n";
const MSG2: &str = "From: Carol <carol@example.com>\r\nTo: bob@example.com\r\nSubject: Second\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n";

#[derive(Default)]
struct MockState {
    /// Speak NTLM (like webmail.pln.co.id) instead of Basic.
    ntlm: bool,
    ntlm_handshakes: usize,
    deleted: Vec<String>,
    requests: Vec<String>,
    connections: usize,
    close_after_success: bool,
}

const CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn field(m: &[u8], at: usize) -> &[u8] {
    let len = u16::from_le_bytes([m[at], m[at + 1]]) as usize;
    let off = u32::from_le_bytes(m[at + 4..at + 8].try_into().unwrap()) as usize;
    &m[off..off + len]
}

fn hmac_md5(key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<md5::Md5> as KeyInit>::new_from_slice(key).unwrap();
    for d in data {
        mac.update(d);
    }
    mac.finalize().into_bytes().to_vec()
}

/// Type 2 message with an empty target info block.
fn ntlm_challenge() -> Vec<u8> {
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&[0, 0, 0, 0, 48, 0, 0, 0]); // target name: empty
    m.extend_from_slice(&0xA289_0205u32.to_le_bytes());
    m.extend_from_slice(&CHALLENGE);
    m.extend_from_slice(&[0; 8]);
    m.extend_from_slice(&[4, 0, 4, 0, 48, 0, 0, 0]); // target info at 48
    m.extend_from_slice(&[0; 4]); // MsvAvEOL
    m
}

/// Checks a type 3 message for user "bob", domain "PUSAT", password "secret" (NTLMv2).
fn ntlm_valid(m: &[u8]) -> bool {
    use md4::Digest;
    let (nt, domain, user) = (field(m, 20), field(m, 28), field(m, 36));
    if domain != utf16("PUSAT").as_slice() || user != utf16("bob").as_slice() || nt.len() < 24 {
        return false;
    }
    let nt_hash = md4::Md4::digest(utf16("secret"));
    let key = hmac_md5(&nt_hash, &[&utf16("BOBPUSAT")]);
    hmac_md5(&key, &[&CHALLENGE, &nt[16..]]) == nt[..16]
}

fn envelope(op: &str, inner: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><m:{op}Response xmlns:m="{M}" xmlns:t="{T}"><m:ResponseMessages>{inner}</m:ResponseMessages></m:{op}Response></s:Body></s:Envelope>"#
    )
}

fn ok(op: &str, inner: &str) -> String {
    format!(
        r#"<m:{op}ResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode>{inner}</m:{op}ResponseMessage>"#
    )
}

fn handle(body: &str, st: &Mutex<MockState>) -> String {
    let mut st = st.lock().unwrap();
    st.requests.push(body.to_string());
    if body.contains("<m:GetFolder>") {
        let inner: String = ["R", "I", "D", "S", "T", "J"]
            .iter()
            .map(|id| {
                ok(
                    "GetFolder",
                    &format!(
                        r#"<m:Folders><t:Folder><t:FolderId Id="{id}"/></t:Folder></m:Folders>"#
                    ),
                )
            })
            .collect();
        envelope("GetFolder", &inner)
    } else if body.contains("<m:FindFolder") {
        let f = |id: &str, parent: &str, name: &str| {
            format!(
                r#"<t:Folder><t:FolderId Id="{id}"/><t:ParentFolderId Id="{parent}"/><t:FolderClass>IPF.Note</t:FolderClass><t:DisplayName>{name}</t:DisplayName></t:Folder>"#
            )
        };
        let folders = [
            f("I", "R", "Posteingang"),
            f("S", "R", "Sent Items"),
            f("T", "R", "Deleted Items"),
            f("P", "I", "Projekte Ü"),
        ]
        .concat()
            + r#"<t:CalendarFolder><t:FolderId Id="C"/><t:ParentFolderId Id="R"/><t:DisplayName>Calendar</t:DisplayName></t:CalendarFolder>"#;
        envelope(
            "FindFolder",
            &ok(
                "FindFolder",
                &format!(
                    r#"<m:RootFolder IncludesLastItemInRange="true"><t:Folders>{folders}</t:Folders></m:RootFolder>"#
                ),
            ),
        )
    } else if body.contains("<m:FindItem") {
        let mut items = String::new();
        if body.contains(r#"<t:FolderId Id="I"/>"#) {
            let received = (chrono::Utc::now() - chrono::TimeDelta::days(1)).to_rfc3339();
            if !st.deleted.contains(&"m1".to_string()) {
                items += &format!(
                    r#"<t:Message><t:ItemId Id="m1"/><t:IsRead>true</t:IsRead><t:DateTimeReceived>{received}</t:DateTimeReceived><t:IsDraft>false</t:IsDraft><t:ExtendedProperty><t:ExtendedFieldURI PropertyTag="0x1090" PropertyType="Integer"/><t:Value>2</t:Value></t:ExtendedProperty></t:Message>"#
                );
            }
            if !st.deleted.contains(&"m2".to_string()) {
                items += &format!(
                    r#"<t:Message><t:ItemId Id="m2"/><t:IsRead>false</t:IsRead><t:DateTimeReceived>{received}</t:DateTimeReceived><t:IsDraft>false</t:IsDraft></t:Message>"#
                );
            }
        }

        if body.contains(r#"Offset="0""#) {
            envelope(
                "FindItem",
                &ok(
                    "FindItem",
                    &format!(
                        r#"<m:RootFolder IncludesLastItemInRange="false" IndexedPagingOffset="1000"><t:Items>{items}</t:Items></m:RootFolder>"#
                    ),
                ),
            )
        } else {
            envelope(
                "FindItem",
                &ok(
                    "FindItem",
                    r#"<m:RootFolder IncludesLastItemInRange="true"><t:Items/></m:RootFolder>"#,
                ),
            )
        }
    } else if body.contains("<m:GetItem>") {
        let mut inner = String::new();
        for (id, msg) in [("m1", MSG1), ("m2", MSG2)] {
            if body.contains(&format!(r#"<t:ItemId Id="{id}"/>"#)) {
                inner += &ok(
                    "GetItem",
                    &format!(
                        r#"<m:Items><t:Message><t:MimeContent CharacterSet="UTF-8">{}</t:MimeContent></t:Message></m:Items>"#,
                        B64.encode(msg)
                    ),
                );
            }
        }
        envelope("GetItem", &inner)
    } else if body.contains("<m:UpdateItem") {
        envelope("UpdateItem", &ok("UpdateItem", ""))
    } else if body.contains("<m:CreateItem") {
        envelope(
            "CreateItem",
            &ok(
                "CreateItem",
                r#"<m:Items><t:Message><t:ItemId Id="created"/></t:Message></m:Items>"#,
            ),
        )
    } else if body.contains("<m:MoveItem") || body.contains("<m:CopyItem") {
        let op = if body.contains("<m:MoveItem") {
            "MoveItem"
        } else {
            "CopyItem"
        };
        envelope(
            op,
            &ok(
                op,
                r#"<m:Items><t:Message><t:ItemId Id="moved"/></t:Message></m:Items>"#,
            ),
        )
    } else if body.contains("<m:DeleteItem") {
        if body.contains(r#"<t:ItemId Id="missing"/>"#) {
            return envelope(
                "DeleteItem",
                r#"<m:DeleteItemResponseMessage ResponseClass="Error"><m:ResponseCode>ErrorItemNotFound</m:ResponseCode><m:MessageText>Already gone</m:MessageText></m:DeleteItemResponseMessage>"#,
            );
        }
        for id in ["m1", "m2"] {
            if body.contains(&format!(r#"<t:ItemId Id="{id}"/>"#)) {
                st.deleted.push(id.to_string());
            }
        }
        envelope("DeleteItem", &ok("DeleteItem", ""))
    } else {
        panic!("unexpected EWS request: {body}");
    }
}

fn serve_http(mut s: TcpStream, st: Arc<Mutex<MockState>>) {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    st.lock().unwrap().connections += 1;
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut authed = false; // NTLM authenticates the connection
    loop {
        let (mut len, mut auth) = (0usize, String::new());
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            let (k, v) = line.split_once(':').unwrap();
            match k.to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().unwrap(),
                "authorization" => auth = v.trim().to_string(),
                _ => {}
            }
        }
        let mut body = vec![0; len];
        r.read_exact(&mut body).unwrap();
        let ntlm = st.lock().unwrap().ntlm;
        let mut challenge = None;
        let ok = if ntlm {
            match auth.strip_prefix("NTLM ").map(|t| B64.decode(t).unwrap()) {
                Some(m) if m[8] == 1 => {
                    assert!(!body.is_empty(), "IIS needs the real SOAP payload");
                    st.lock().unwrap().ntlm_handshakes += 1;
                    challenge = Some(B64.encode(ntlm_challenge()));
                    false
                }
                Some(m) if m[8] == 3 => {
                    authed = ntlm_valid(&m);
                    authed
                }
                _ => authed,
            }
        } else {
            auth == format!("Basic {}", B64.encode("bob:secret"))
        };
        let close = ok && st.lock().unwrap().close_after_success;
        let resp = if let Some(c) = challenge {
            format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {c}\r\nContent-Length: 4\r\n\r\nAUTH"
            )
        } else if !ok {
            let offer = if ntlm {
                "WWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM"
            } else {
                "WWW-Authenticate: Basic realm=\"x\""
            };
            format!("HTTP/1.1 401 Unauthorized\r\n{offer}\r\nContent-Length: 4\r\n\r\nAUTH")
        } else {
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains("Exchange2010_SP2"));
            let xml = handle(body, &st);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nConnection: {}\r\nContent-Length: {}\r\n\r\n{xml}",
                if close { "close" } else { "keep-alive" },
                xml.len()
            )
        };
        s.write_all(resp.as_bytes()).unwrap();
        if close {
            return;
        }
    }
}

fn server(ntlm: bool) -> (String, Arc<Mutex<MockState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(MockState {
        ntlm,
        ..Default::default()
    }));
    let shared = state.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || serve_http(stream, shared));
        }
    });
    (url, state)
}

fn client(url: String, ntlm: bool, password: &str) -> EwsClient {
    EwsClient::new(
        &EwsConfig {
            url,
            insecure: false,
            default_domain: ntlm.then(|| "PUSAT".into()),
            auth: AuthMode::Auto,
        },
        "bob",
        password,
    )
    .unwrap()
}

#[tokio::test]
async fn ntlm_connection_reuse_roles_paging_and_mutations() {
    let (url, st) = server(true);
    let c = client(url, true, "secret");
    let known = c.well_known().await.unwrap();
    assert_eq!(known.inbox.as_deref(), Some("I"));
    assert_eq!(known.drafts.as_deref(), Some("D"));
    assert_eq!(known.sent.as_deref(), Some("S"));
    assert_eq!(known.trash.as_deref(), Some("T"));
    assert_eq!(known.junk.as_deref(), Some("J"));
    let folders = c.find_folders().await.unwrap();
    assert!(
        folders
            .iter()
            .any(|f| f.id == "I" && f.name == "Posteingang")
    );
    assert!(!folders.iter().any(|f| f.id == "C"));
    let items = c.find_items("I").await.unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[0].flagged && items[0].is_read);
    assert!(!items[1].is_read);
    let raw = c.get_mime(&["m1".into(), "m2".into()]).await.unwrap();
    assert_eq!(raw[0].as_ref().unwrap(), MSG1.as_bytes());
    c.update_flags(&[(
        "m1".into(),
        vec![
            FlagChange::Read(false),
            FlagChange::Flagged(false),
            FlagChange::Answered(true),
        ],
    )])
    .await
    .unwrap();
    assert_eq!(
        c.move_or_copy(&["m1".into()], "T", false).await.unwrap(),
        ["moved"]
    );
    assert_eq!(
        c.move_or_copy(&["m2".into()], "S", true).await.unwrap(),
        ["moved"]
    );
    c.delete_items(&["m1".into()]).await.unwrap();
    c.delete_items(&["missing".into()]).await.unwrap();
    assert_eq!(
        c.create_item("D", MSG1.as_bytes(), true, true)
            .await
            .unwrap(),
        "created"
    );
    c.create_item("S", MSG1.as_bytes(), true, false)
        .await
        .unwrap();
    c.send_mime(
        b"From: bob@example.com\r\nSubject: private\r\n\r\nHello",
        &["hidden@example.com".into()],
        true,
    )
    .await
    .unwrap();
    let st = st.lock().unwrap();
    assert_eq!(st.connections, 1);
    assert_eq!(st.ntlm_handshakes, 1);
    assert!(st.requests.iter().any(|s| s.contains(r#"Offset="1000""#)));
    let flags = st
        .requests
        .iter()
        .find(|s| s.contains("<m:UpdateItem"))
        .unwrap();
    assert!(flags.contains("AlwaysOverwrite") && flags.contains("<t:IsRead>false"));
    assert!(flags.contains("<t:DeleteItemField>") && flags.contains("0x1090"));
    assert!(!flags.contains("ChangeKey"));
    let send = st.requests.last().unwrap();
    assert!(send.contains("SendAndSaveCopy") && send.contains("sentitems"));
    assert!(send.contains("<t:BccRecipients><t:Mailbox><t:EmailAddress>hidden@example.com"));
    assert!(
        st.requests
            .iter()
            .any(|s| s.contains("0x0E07") && s.contains("<t:Value>1"))
    );
}

#[tokio::test]
async fn basic_and_authentication_failure() {
    let (url, _) = server(false);
    assert!(client(url, false, "secret").well_known().await.is_ok());
    let (url, st) = server(true);
    let error = client(url, true, "wrong-mock-password")
        .well_known()
        .await
        .unwrap_err();
    assert!(error.is::<AuthFailed>());
    assert_eq!(st.lock().unwrap().ntlm_handshakes, 1);
}

#[tokio::test]
async fn concurrent_calls_share_one_authenticated_connection() {
    let (url, st) = server(true);
    let c = client(url, true, "secret");
    let (a, b) = tokio::join!(c.well_known(), c.find_folders());
    a.unwrap();
    b.unwrap();
    let st = st.lock().unwrap();
    assert_eq!(st.connections, 1);
    assert_eq!(st.ntlm_handshakes, 1);
}

#[tokio::test]
async fn a_new_connection_authenticates_again() {
    let (url, state) = server(true);
    state.lock().unwrap().close_after_success = true;
    let client = client(url, true, "secret");
    client.well_known().await.unwrap();
    client.find_folders().await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.connections, 2);
    assert_eq!(state.ntlm_handshakes, 2);
}

#[cfg(all(debug_assertions, desktop))]
#[tokio::test]
async fn account_sync_persists_exchange_identity_and_reuses_mime() {
    use flectar_mail_core::{
        Core,
        accounts::credentials::DevelopmentFileCredentialStore,
        config::Paths,
        ews::EwsSettings,
        models::{
            AddPasswordAccountArgs, ConnectionSecurity, MailConnectionSettings, MailProtocol, View,
        },
    };

    let (url, server) = server(true);
    let dir = tempfile::tempdir().unwrap();
    let credentials = Arc::new(DevelopmentFileCredentialStore::new(
        dir.path().join("credentials.json"),
    ));
    let core = Core::start_mail_ui_with_credentials(Paths::for_tests(dir.path()), credentials)
        .await
        .unwrap();
    let account = core
        .add_account_password(AddPasswordAccountArgs {
            email: "bob@example.com".into(),
            display_name: None,
            username: "bob".into(),
            password: "secret".into(),
            mail_protocol: MailProtocol::Ews,
            jmap_url: String::new(),
            incoming_host: String::new(),
            incoming_port: 0,
            smtp_host: String::new(),
            smtp_port: 0,
            connection: MailConnectionSettings::new(
                ConnectionSecurity::Tls,
                ConnectionSecurity::Tls,
            ),
            ews: EwsSettings {
                url,
                default_domain: Some("PUSAT".into()),
                ..Default::default()
            },
        })
        .await
        .unwrap();
    for _ in 0..2 {
        core.sync_accounts(Some(&[account.id])).await.unwrap();
        let folders = core.list_folders(Some(account.id)).await.unwrap();
        assert!(
            folders
                .iter()
                .any(|f| f.role.as_deref() == Some("inbox") && f.display_name == "Posteingang")
        );
        let listed = core
            .list_threads(View::Inbox, None, Some(account.id), None, None, (None, 50))
            .await
            .unwrap();
        assert_eq!(listed.threads.len(), 2);
    }
    let state = server.lock().unwrap();
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|r| r.contains("<m:GetItem>"))
            .count(),
        1
    );
    assert_eq!(
        state.ntlm_handshakes, 2,
        "one probe and one account connection"
    );
}
