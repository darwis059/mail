//! EWS owns a single serialized connection for sync, actions and priority reads.
use super::{
    client::{EwsClient, FlagChange, ItemInfo},
    map_error,
};
use crate::{
    accounts::credentials::{self, Slot},
    db::repo,
    error::{CoreError, Result},
    events::CoreEvent,
    models::{AccountConfig, AccountSettings, now_ms, roles},
    sync::{
        engine::{PriorityFetchCmd, SyncCmd, SyncCtx, caught_up, set_state, set_state_error},
        ingest,
    },
};
use rusqlite::{OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, watch};

pub(crate) fn spawn(
    ctx: SyncCtx,
    config: AccountConfig,
    rx: mpsc::Receiver<SyncCmd>,
    body_rx: mpsc::Receiver<PriorityFetchCmd>,
    settings: watch::Receiver<AccountSettings>,
) -> Vec<tokio::task::JoinHandle<()>> {
    vec![tokio::spawn(run(ctx, config, rx, body_rx, settings))]
}

async fn run(
    ctx: SyncCtx,
    mut config: AccountConfig,
    mut rx: mpsc::Receiver<SyncCmd>,
    mut body_rx: mpsc::Receiver<PriorityFetchCmd>,
    mut settings: watch::Receiver<AccountSettings>,
) {
    let mut client = None;
    let live_since = ingest::live_since(now_ms());
    let mut waiters = Vec::new();
    loop {
        let started = now_ms();
        let result = async {
            if client.is_none() {
                let password =
                    credentials::load_async(ctx.credentials.clone(), config.id, Slot::Password)
                        .await?;
                client = Some(config.settings.ews.client(&config.username, &password)?);
            }
            let c = client.as_ref().unwrap();
            set_state(&ctx, config.id, "syncing").await;
            sync_folders(&ctx, config.id, c).await?;
            execute_actions(&ctx, &config, c).await?;
            let folders = ctx
                .db
                .read({
                    let id = config.id;
                    move |db| repo::folders::list(db, Some(id))
                })
                .await?;
            for folder in folders {
                sync_folder(&ctx, &config, c, folder, live_since).await?;
            }
            caught_up(&ctx, config.id, started).await;
            crate::sync::engine::settle_waiting_rules(&ctx, config.id).await;
            Ok::<_, CoreError>(())
        }
        .await;
        let auth_failed = matches!(result, Err(CoreError::Auth(_) | CoreError::NeedsReauth));
        match &result {
            Ok(()) => set_state(&ctx, config.id, "idle").await,
            Err(e) if auth_failed => {
                set_state_error(&ctx, config.id, "needs_reauth", &e.to_string()).await
            }
            Err(e) => set_state_error(&ctx, config.id, "offline", &e.to_string()).await,
        }
        for waiter in waiters.drain(..) {
            let waiter: tokio::sync::oneshot::Sender<std::result::Result<(), String>> = waiter;
            let _ = waiter.send(result.as_ref().map(|_| ()).map_err(ToString::to_string));
        }
        let delay = tokio::time::sleep(std::time::Duration::from_secs(
            config.settings.ews.poll_seconds.max(1),
        ));
        tokio::pin!(delay);
        loop {
            tokio::select! {
                _ = &mut delay, if !auth_failed => break,
                changed = settings.changed() => {
                    if changed.is_err() { return; }
                    config.settings = settings.borrow_and_update().clone();
                    client = None;
                    break;
                }
                cmd = rx.recv() => match cmd {
                    None | Some(SyncCmd::Shutdown) => return,
                    Some(SyncCmd::SyncNow { complete }) => { waiters.extend(complete); break; }
                    Some(_) if !auth_failed => break,
                    Some(_) => {}
                },
                cmd = body_rx.recv() => {
                    let Some(cmd) = cmd else { return; };
                    if !auth_failed && let Some(c) = &client { priority(&ctx, config.id, c, cmd).await; }
                }
            }
        }
    }
}

async fn remote_folder(ctx: &SyncCtx, account: i64, folder: i64) -> Result<String> {
    ctx.db
        .read(move |db| {
            Ok(db.query_row(
                "SELECT remote_id FROM ews_folders WHERE account_id=?1 AND folder_id=?2",
                params![account, folder],
                |r| r.get(0),
            )?)
        })
        .await
}

async fn sync_folders(ctx: &SyncCtx, account: i64, c: &EwsClient) -> Result<()> {
    let known = c.well_known().await.map_err(map_error)?;
    let folders = c.find_folders().await.map_err(map_error)?;
    ctx.db.write(move |db| {
        let tx = db.transaction()?;
        let by_id: HashMap<_, _> = folders.iter().map(|f| (f.id.as_str(), f)).collect();
        let mut locals = HashMap::new();
        for f in &folders {
            let role = [(known.inbox.as_ref(), roles::INBOX), (known.drafts.as_ref(), roles::DRAFTS),
                (known.sent.as_ref(), roles::SENT), (known.trash.as_ref(), roles::TRASH), (known.junk.as_ref(), roles::SPAM)]
                .into_iter().find_map(|(id, role)| (id == Some(&f.id)).then_some(role));
            let mut names = vec![f.name.clone()];
            let mut parent = f.parent_id.as_deref();
            let mut seen = HashSet::from([f.id.as_str()]);
            while let Some(p) = parent.and_then(|id| by_id.get(id)) {
                if !seen.insert(&p.id) { return Err(CoreError::Other("EWS folder hierarchy contains a cycle".into())); }
                names.push(p.name.clone()); parent = p.parent_id.as_deref();
            }
            names.reverse();
            let path = names.join(" / ");
            let existing: Option<i64> = tx.query_row(
                "SELECT folder_id FROM ews_folders WHERE account_id=?1 AND remote_id=?2",
                params![account, f.id],
                |r| r.get(0),
            ).optional()?;
            let local = if let Some(id) = existing {
                tx.execute("UPDATE folders SET path=?2,role=?3,missing_on_server=0 WHERE id=?1", params![id,path,role])?; id
            } else {
                let id = repo::folders::upsert_discovered(&tx, account, &path, Some(" / "), role, true,
                    repo::folders::FolderPermissions {can_create_children:false,can_rename:false,can_delete:false})?;
                tx.execute("INSERT INTO ews_folders VALUES(?1,?2,?3)", params![id,account,f.id])?; id
            };
            locals.insert(f.id.clone(), local);
        }
        tx.execute("UPDATE folders SET missing_on_server=1 WHERE account_id=?1", [account])?;
        for f in &folders {
            let id = locals[&f.id];
            let parent = f.parent_id.as_ref().and_then(|p| locals.get(p));
            tx.execute("UPDATE folders SET parent_id=?2,missing_on_server=0,backfill_done=1 WHERE id=?1", params![id,parent])?;
        }
        tx.execute("UPDATE accounts SET can_create_top_level_mailbox=0 WHERE id=?1", [account])?;
        tx.commit()?; Ok(())
    }).await?;
    ctx.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
    Ok(())
}

async fn sync_folder(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &EwsClient,
    folder: repo::folders::Folder,
    live_since: i64,
) -> Result<()> {
    let remote = remote_folder(ctx, config.id, folder.id).await?;
    // Only a complete successful listing is allowed to remove vanished messages.
    let items = c.find_items(&remote).await.map_err(map_error)?;
    let fid = folder.id;
    let known: HashSet<String> = ctx
        .db
        .read(move |db| {
            let mut stmt = db.prepare(
                "SELECT remote_id FROM ews_items WHERE folder_id=?1
                 UNION SELECT json_extract(payload,'$.ewsItemId') FROM pending_actions
                 WHERE account_id=(SELECT account_id FROM folders WHERE id=?1)
                 AND kind='delete_draft' AND state IN ('pending','inflight')
                 AND json_extract(payload,'$.ewsItemId') IS NOT NULL",
            )?;
            Ok(stmt
                .query_map([fid], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?)
        })
        .await?;
    let cutoff = config.settings.mail_history.cutoff_ms_at(now_ms());
    let missing: Vec<_> = items
        .iter()
        .filter(|i| {
            !known.contains(&i.id)
                && (i.draft || cutoff.is_none_or(|cutoff| i.received.timestamp_millis() >= cutoff))
        })
        .cloned()
        .collect();
    for batch in missing.chunks(20) {
        let ids = batch.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        let mimes = c.get_mime(&ids).await.map_err(map_error)?;
        for (item, raw) in batch.iter().zip(mimes) {
            ingest_message(
                ctx,
                config.id,
                &folder,
                item.clone(),
                raw.map_err(map_error)?,
                live_since,
            )
            .await?;
        }
    }
    let account = config.id;
    let present: HashMap<_, _> = items
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect();
    let paths = ctx
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            let mut stmt = tx
                .prepare("SELECT e.message_id,e.remote_id FROM ews_items e WHERE e.folder_id=?1")?;
            let stored = stmt
                .query_map([fid], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            let mut paths = Vec::new();
            for (id, remote) in stored {
                let pending: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pending_actions WHERE message_id=?1
                 AND state IN ('pending','inflight'))",
                    [id],
                    |r| r.get(0),
                )?;
                if pending {
                    continue;
                }
                if !present.contains_key(&remote) {
                    if let Some(row) = repo::messages::get_row(&tx, id)? {
                        paths.extend(row.raw_path);
                        repo::messages::delete(&tx, id)?;
                        if let Some(tid) = row.thread_id {
                            repo::threads::recompute(&tx, tid)?;
                        }
                    }
                } else if let Some(item) = present.get(&remote) {
                    let changed = tx.execute(
                        "UPDATE messages SET is_read=?2,is_starred=?3,is_draft=?4
                     WHERE id=?1 AND (is_read<>?2 OR is_starred<>?3 OR is_draft<>?4)",
                        params![id, item.is_read, item.flagged, item.draft],
                    )?;
                    tx.execute(
                        "UPDATE ews_items SET answered=?2,forwarded=?3 WHERE message_id=?1",
                        params![id, item.answered, item.forwarded],
                    )?;
                    if changed != 0
                        && let Some(tid) =
                            repo::messages::get_row(&tx, id)?.and_then(|r| r.thread_id)
                    {
                        repo::threads::recompute(&tx, tid)?;
                    }
                }
            }
            tx.execute(
                "UPDATE folders SET backfill_done=1 WHERE id=?1 AND account_id=?2",
                params![fid, account],
            )?;
            tx.commit()?;
            Ok(paths)
        })
        .await?;
    for path in paths {
        let _ = tokio::fs::remove_file(path).await;
    }
    ctx.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
    Ok(())
}

async fn ingest_message(
    ctx: &SyncCtx,
    account: i64,
    folder: &repo::folders::Folder,
    item: ItemInfo,
    raw: Vec<u8>,
    live_since: i64,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let size = raw.len() as i64;
    let key = Sha256::digest(item.id.as_bytes());
    let path = ctx.paths.mail_dir(account).join(format!("{key:x}.ews.eml"));
    crate::file_io::write_atomic(&path, &raw, "EWS MIME cache").await?;
    let parsed = tokio::task::spawn_blocking(move || ingest::parse_or_text(&raw))
        .await
        .map_err(|error| CoreError::Other(format!("EWS MIME parsing task: {error}")))?;
    let folder = folder.clone();
    let write_path = path.to_string_lossy().into_owned();
    let result = ctx
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            let mut importer = ingest::Importer::new(&tx, account)?;
            // Only adopt the local snapshot created by a successful submission.
            let adopt: Option<(i64, String)> = if folder.role.as_deref() == Some(roles::SENT) {
                tx.query_row(
                    "SELECT m.id, m.raw_path FROM messages m
                 WHERE m.account_id=?1 AND m.message_id=?2 AND m.is_outgoing=1 AND m.is_draft=0
                   AND m.raw_path LIKE '%.outgoing.eml'
                   AND NOT EXISTS (SELECT 1 FROM ews_items e WHERE e.message_id=m.id)
                 ORDER BY m.id DESC LIMIT 1",
                    params![account, parsed.headers.message_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
            } else {
                None
            };
            let (id, old_path, imported) = if let Some((id, old_path)) = adopt {
                tx.execute(
                    "UPDATE messages SET folder_id=?2 WHERE id=?1",
                    params![id, folder.id],
                )?;
                (id, Some(old_path), None)
            } else {
                let imported = importer.insert(
                    &tx,
                    &parsed.headers,
                    &ingest::Delivery {
                        folder_id: folder.id,
                        folder_role: folder.role.as_deref(),
                        uid: None,
                        received_ms: Some(item.received.timestamp_millis()),
                        seen: item.is_read,
                        flagged: item.flagged,
                        draft: item.draft,
                        has_attachments: !parsed.attachments.is_empty(),
                        size: Some(size),
                        receipt_handled: false,
                    },
                )?;
                importer.learn_contacts(&tx, &parsed.headers, &imported)?;
                (imported.message_id, None, Some(imported))
            };
            tx.execute(
            "INSERT INTO ews_items (message_id,account_id,folder_id,remote_id,answered,forwarded)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![id, account, folder.id, item.id, item.answered, item.forwarded],
        )?;
            let mut changed = ingest::store_body(&tx, id, &write_path, &parsed)?;
            if let Some(imported) = imported {
                let live = folder.role.as_deref() == Some(roles::INBOX)
                    && item.received.timestamp_millis() >= live_since;
                importer.announce(&tx, &imported, live)?;
            }
            if let Some(tid) = repo::messages::get_row(&tx, id)?.and_then(|row| row.thread_id) {
                repo::threads::recompute(&tx, tid)?;
                changed.push(tid);
            }
            let (tids, notified) = importer.finish(&tx)?;
            changed.extend(tids);
            changed.sort_unstable();
            changed.dedup();
            tx.commit()?;
            Ok((changed, old_path, notified))
        })
        .await;
    match result {
        Ok((thread_ids, old_path, notified)) => {
            if let Some(old_path) = old_path {
                let _ = tokio::fs::remove_file(old_path).await;
            }
            ctx.bus.emit(CoreEvent::MailUpdated { thread_ids });
            if !notified.is_empty() {
                ctx.bus.emit(CoreEvent::MailNew {
                    account_id: account,
                    thread_ids: notified,
                });
            }
            Ok(())
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(path).await;
            Err(error)
        }
    }
}

async fn store_raw(ctx: &SyncCtx, account: i64, id: i64, raw: Vec<u8>) -> Result<()> {
    let parsed = crate::mime::parse_message(&raw)?;
    let path = ctx.paths.mail_dir(account).join(format!("{id}.ews.eml"));
    crate::file_io::write_atomic(&path, &raw, "EWS MIME cache").await?;
    let path = path.to_string_lossy().into_owned();
    ctx.db
        .write(move |db| {
            let tx = db.transaction()?;
            ingest::store_body(&tx, id, &path, &parsed)?;
            if let Some(tid) = repo::messages::get_row(&tx, id)?.and_then(|r| r.thread_id) {
                repo::threads::recompute(&tx, tid)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
}

async fn fetch_raw(ctx: &SyncCtx, account: i64, c: &EwsClient, id: i64) -> Result<Vec<u8>> {
    let (path, remote) = ctx
        .db
        .read(move |db| {
            Ok(db.query_row(
                "SELECT m.raw_path,e.remote_id FROM messages m
             JOIN ews_items e ON e.message_id=m.id
             WHERE m.id=?1 AND e.account_id=?2",
                params![id, account],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?)),
            )?)
        })
        .await?;
    if let Some(path) = path
        && let Ok(raw) = crate::file_io::read(path, MAX_MESSAGE_BYTES, "EWS MIME cache").await
    {
        return Ok(raw);
    }
    let raw = c
        .get_mime(&[remote])
        .await
        .map_err(map_error)?
        .remove(0)
        .map_err(map_error)?;
    store_raw(ctx, account, id, raw.clone()).await?;
    Ok(raw)
}

async fn priority(ctx: &SyncCtx, account: i64, c: &EwsClient, cmd: PriorityFetchCmd) {
    match cmd {
        PriorityFetchCmd::EwsOriginal {
            message_id,
            complete,
        } => {
            let _ = complete.send(fetch_raw(ctx, account, c, message_id).await);
        }
        PriorityFetchCmd::EwsAppend {
            folder_id,
            raw,
            seen,
            flagged,
            complete,
        } => {
            let result = async {
                let folder = remote_folder(ctx, account, folder_id).await?;
                let id = c
                    .create_item(&folder, &raw, seen, false)
                    .await
                    .map_err(map_error)?;
                if flagged {
                    c.update_flags(&[(id, vec![FlagChange::Flagged(true)])])
                        .await
                        .map_err(map_error)?;
                }
                Ok(())
            }
            .await;
            let _ = complete.send(result);
        }

        PriorityFetchCmd::Body(id) => {
            if let Err(e) = fetch_raw(ctx, account, c, id).await {
                tracing::warn!(account_id=account,error=%e,"EWS body fetch failed");
                let _ = ctx
                    .db
                    .write(move |db| repo::messages::set_body_state(db, id, "none"))
                    .await;
            }
            ctx.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
        }
        PriorityFetchCmd::Attachment {
            attachment_id,
            complete,
        } => {
            let result = async {
                let (id, part) = ctx
                    .db
                    .read(move |db| {
                        Ok(db.query_row(
                            "SELECT message_id,part_id FROM attachments WHERE id=?1",
                            [attachment_id],
                            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                        )?)
                    })
                    .await?;
                crate::mime::extract_attachment(&fetch_raw(ctx, account, c, id).await?, &part)
                    .map(|(bytes, _)| bytes)
            }
            .await;
            let _ = complete.send(result.map_err(|e: CoreError| e.to_string()));
        }
        PriorityFetchCmd::Search { complete, .. } => {
            let _ = complete.send(Err(
                "EWS server search is not supported; search downloaded mail instead".into(),
            ));
        }
    }
}

async fn execute_actions(ctx: &SyncCtx, config: &AccountConfig, c: &EwsClient) -> Result<()> {
    let account = config.id;
    let actions = ctx
        .db
        .read(move |db| repo::actions::due(db, account, now_ms(), 100))
        .await?;
    for action in actions {
        let aid = action.id;
        if !ctx
            .db
            .write(move |db| repo::actions::try_claim(db, aid))
            .await?
        {
            continue;
        }
        let outcome = execute_action(ctx, config, c, &action).await;
        match outcome {
            Ok(()) => {
                ctx.db
                    .write(move |db| repo::actions::set_state(db, aid, "done", None))
                    .await?;
                ctx.bus.emit(CoreEvent::ActionState {
                    action_id: aid,
                    state: "done".into(),
                    error: None,
                });
            }
            Err(error) => {
                let message = error.to_string();
                let auth = matches!(error, CoreError::Auth(_) | CoreError::NeedsReauth);
                let terminal = matches!(error, CoreError::SendUncertain(_)) || action.attempts >= 7;
                let saved = message.clone();
                ctx.db
                    .write(move |db| {
                        if terminal {
                            repo::actions::set_state(db, aid, "failed", Some(&saved))
                        } else {
                            repo::actions::bump_attempt(db, aid, now_ms() + 30_000, &saved)
                        }
                    })
                    .await?;
                if terminal {
                    ctx.bus.emit(CoreEvent::ActionState {
                        action_id: aid,
                        state: "failed".into(),
                        error: Some(message),
                    });
                }
                if auth {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

async fn item_id(ctx: &SyncCtx, account: i64, id: i64) -> Result<Option<String>> {
    ctx.db
        .read(move |db| {
            Ok(db
                .query_row(
                    "SELECT remote_id FROM ews_items WHERE account_id=?1 AND message_id=?2",
                    params![account, id],
                    |r| r.get(0),
                )
                .optional()?)
        })
        .await
}

async fn execute_action(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &EwsClient,
    action: &repo::actions::PendingAction,
) -> Result<()> {
    let account = config.id;
    let id = action.message_id.unwrap_or_default();
    match action.kind.as_str() {
        "send" => crate::queue::send_action(ctx, config, action, Some(c)).await,
        "save_draft" => {
            let id = action.payload["draftId"].as_i64().unwrap_or(id);
            let folder = ctx
                .db
                .read(move |db| repo::folders::by_role(db, account, roles::DRAFTS))
                .await?
                .ok_or_else(|| CoreError::NotFound("Exchange Drafts folder".into()))?;
            let (_, raw) = build_draft_message(ctx, config, id).await?;
            let previous = item_id(ctx, account, id).await?;
            let remote = c
                .create_item(
                    &remote_folder(ctx, account, folder.id).await?,
                    &raw,
                    true,
                    true,
                )
                .await
                .map_err(map_error)?;
            let fid = folder.id;
            let discard = remote.clone();
            let saved = ctx
                .db
                .write(move |db| {
                    let tx = db.transaction()?;
                    tx.execute(
                        "INSERT INTO ews_items(message_id,account_id,folder_id,remote_id)
                     VALUES(?1,?2,?3,?4) ON CONFLICT(message_id) DO UPDATE SET
                     folder_id=excluded.folder_id,remote_id=excluded.remote_id",
                        params![id, account, fid, remote],
                    )?;
                    if let Some(old) = previous {
                        repo::actions::enqueue(
                            &tx,
                            account,
                            "delete_draft",
                            None,
                            None,
                            &serde_json::json!({"ewsItemId":old}),
                            None,
                        )?;
                    }
                    tx.commit()?;
                    Ok(())
                })
                .await;
            if let Err(error) = saved {
                if let Err(cleanup) = c.delete_items(&[discard]).await {
                    tracing::warn!(account_id=account,error=%cleanup,"Exchange draft cleanup failed");
                }
                return Err(error);
            }
            Ok(())
        }
        "mark_read" | "mark_unread" | "star" | "unstar" => {
            let Some(remote) = item_id(ctx, account, id).await? else {
                return Ok(());
            };
            let flag = match action.kind.as_str() {
                "mark_read" => FlagChange::Read(true),
                "mark_unread" => FlagChange::Read(false),
                "star" => FlagChange::Flagged(true),
                _ => FlagChange::Flagged(false),
            };
            c.update_flags(&[(remote, vec![flag])])
                .await
                .map_err(map_error)
        }
        "archive" | "unarchive" | "trash" | "spam" | "not_spam" | "move" | "copy" => {
            let Some(remote) = item_id(ctx, account, id).await? else {
                return Err(CoreError::NotFound("Exchange item for move".into()));
            };
            if action.kind == "trash" {
                c.delete_items(&[remote]).await.map_err(map_error)?;
                // DeleteItem supplies no replacement id; discover the new Trash copy.
                return crate::sync::finish_permanent_delete(ctx, Some(id)).await;
            }
            let target = action.payload["targetFolderId"]
                .as_i64()
                .ok_or_else(|| CoreError::NotFound("Exchange move target".into()))?;
            let destination = remote_folder(ctx, account, target).await?;
            let copy = action.kind == "copy";
            let ids = c
                .move_or_copy(&[remote], &destination, copy)
                .await
                .map_err(map_error)?;
            if !copy {
                let new_id = ids.into_iter().next().ok_or_else(|| {
                    CoreError::Other("Exchange move returned no new item id".into())
                })?;
                ctx.db
                    .write(move |db| {
                        let tx = db.transaction()?;
                        tx.execute(
                            "UPDATE ews_items SET remote_id=?2,folder_id=?3 WHERE message_id=?1",
                            params![id, new_id, target],
                        )?;
                        tx.execute(
                            "UPDATE messages SET folder_id=?2 WHERE id=?1",
                            params![id, target],
                        )?;
                        tx.commit()?;
                        Ok(())
                    })
                    .await?;
            }
            Ok(())
        }
        "delete_permanently" | "remove_transferred" | "delete_draft" => {
            if let Some(remote) = action.payload["ewsItemId"]
                .as_str()
                .map(str::to_owned)
                .or(item_id(ctx, account, id).await?)
            {
                c.delete_items(&[remote]).await.map_err(map_error)?;
            }
            crate::sync::finish_permanent_delete(ctx, Some(id)).await
        }
        "mark_folder_read" | "empty_trash" => {
            let fid = action.payload["folderId"]
                .as_i64()
                .ok_or_else(|| CoreError::NotFound("Exchange folder".into()))?;
            let remote = remote_folder(ctx, account, fid).await?;
            let items = c.find_items(&remote).await.map_err(map_error)?;
            if action.kind == "empty_trash" {
                let folder = ctx.db.read(move |db| repo::folders::get(db, fid)).await?;
                if folder.as_ref().and_then(|f| f.role.as_deref()) != Some(roles::TRASH) {
                    return Err(CoreError::Other("not a Trash folder".into()));
                }
                for batch in items.chunks(100) {
                    c.delete_items(&batch.iter().map(|i| i.id.clone()).collect::<Vec<_>>())
                        .await
                        .map_err(map_error)?;
                }
            } else {
                let before = action.payload["before"].as_i64().unwrap_or_else(now_ms);
                let changes: Vec<_> = items
                    .into_iter()
                    .filter(|i| !i.is_read && i.received.timestamp_millis() <= before)
                    .map(|i| (i.id, vec![FlagChange::Read(true)]))
                    .collect();
                for batch in changes.chunks(100) {
                    c.update_flags(batch).await.map_err(map_error)?;
                }
            }
            Ok(())
        }
        "snooze" | "unsnooze" | "show_in" | "add_label" | "remove_label" => Ok(()),
        other => Err(CoreError::Other(format!("unsupported EWS action: {other}"))),
    }
}

/// Record the ambiguous-send boundary before transmission; never blindly replay it.
pub(crate) async fn submit(
    ctx: &SyncCtx,
    action: &repo::actions::PendingAction,
    c: &EwsClient,
    recipients: &[String],
    raw: &[u8],
) -> Result<()> {
    if action.payload["ewsSubmitting"].as_bool() == Some(true) {
        return Err(CoreError::SendUncertain(
            "Exchange submission was interrupted; check Sent before sending again".into(),
        ));
    }
    let headers = crate::mime::parse_header_block(raw)?;
    let mut listed: HashSet<_> = headers
        .to
        .iter()
        .chain(&headers.cc)
        .chain(&headers.bcc)
        .map(|a| a.email.to_lowercase())
        .collect();
    let extra: Vec<_> = recipients
        .iter()
        .filter(|r| listed.insert(r.to_lowercase()))
        .cloned()
        .collect();
    let aid = action.id;
    ctx.db.write(move |db| {
        db.execute(
            "UPDATE pending_actions SET payload=json_set(payload,'$.ewsSubmitting',json('true')) WHERE id=?1",
            [aid],
        )?;
        Ok(())
    }).await?;
    match c.send_mime(raw, &extra, true).await {
        Ok(()) => Ok(()),
        Err(error) if error.is::<super::client::AuthFailed>() => {
            ctx.db.write(move |db| {
                db.execute(
                    "UPDATE pending_actions SET payload=json_remove(payload,'$.ewsSubmitting') WHERE id=?1",
                    [aid],
                )?;
                Ok(())
            }).await?;
            Err(map_error(error))
        }
        Err(error) => Err(CoreError::SendUncertain(format!(
            "Exchange submission was not confirmed: {error}"
        ))),
    }
}

const MAX_MESSAGE_BYTES: usize = 128 * 1024 * 1024;
use crate::models::Address;
async fn build_draft_message(
    ctx: &SyncCtx,
    config: &AccountConfig,
    draft_id: i64,
) -> Result<(String, Vec<u8>)> {
    let (detail, reply_to, bcc, mut references, in_reply_to, stored_message_id, attachments) = ctx
        .db
        .read(move |conn| {
            let detail = repo::messages::detail(conn, draft_id)?;
            let reply_to =
                repo::sender_identities::get_verified(conn, detail.account_id, &detail.from.email)?
                    .and_then(|identity| identity.reply_to());
            let (bcc_json, stored_message_id): (String, Option<String>) = conn.query_row(
                "SELECT bcc_json,message_id FROM messages WHERE id=?1 AND is_draft=1",
                params![draft_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let (references, in_reply_to) = repo::messages::draft_reply_headers(conn, draft_id)?;
            let mut stmt = conn.prepare(
                "SELECT file_path,filename,mime_type FROM draft_attachments WHERE draft_id=?1",
            )?;
            let attachments = stmt
                .query_map(params![draft_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let bcc = serde_json::from_str::<Vec<Address>>(&bcc_json)?;
            Ok((
                detail,
                reply_to,
                bcc,
                references,
                in_reply_to,
                stored_message_id,
                attachments,
            ))
        })
        .await?;
    references.sort();
    references.dedup();

    let max_upload = MAX_MESSAGE_BYTES;
    let mut estimated_size = detail
        .text_body
        .as_ref()
        .map_or(0_u64, |body| body.len() as u64)
        .saturating_add(
            detail
                .html_body
                .as_ref()
                .map_or(0_u64, |body| body.len() as u64),
        )
        .saturating_add(64 * 1024);
    let staging_root = tokio::fs::canonicalize(ctx.paths.draft_attachments_dir())
        .await
        .ok();
    let mut outgoing_attachments = Vec::new();
    for (path, filename, mime_type) in attachments {
        let canonical = tokio::fs::canonicalize(&path)
            .await
            .map_err(|error| CoreError::Other(format!("attachment {filename}: {error}")))?;
        if !staging_root
            .as_ref()
            .is_some_and(|root| canonical.starts_with(root))
        {
            return Err(CoreError::Other(format!(
                "attachment {filename}: refusing file outside the staging area"
            )));
        }
        let attachment_size = tokio::fs::metadata(&canonical).await?.len();
        estimated_size = estimated_size
            .saturating_add((attachment_size.saturating_add(2) / 3).saturating_mul(4))
            .saturating_add(2048);
        if estimated_size > max_upload as u64 {
            return Err(CoreError::Other(format!(
                "message exceeds the server or local upload limit of {} MiB",
                max_upload.div_ceil(1024 * 1024)
            )));
        }
        outgoing_attachments.push(crate::mime::OutgoingAttachment {
            mime_type: mime_type.unwrap_or_else(|| crate::queue::mime_guess_from_name(&filename)),
            filename,
            bytes: crate::file_io::read(
                canonical,
                usize::try_from(attachment_size).unwrap_or(MAX_MESSAGE_BYTES),
                "draft attachment",
            )
            .await?,
        });
    }
    let domain = detail
        .from
        .email
        .rsplit_once('@')
        .map(|(_, value)| value)
        .unwrap_or("localhost");
    let (receipt_to, importance) = ctx
        .db
        .read(move |conn| {
            Ok((
                repo::messages::receipt_to(conn, draft_id)?,
                repo::messages::importance(conn, draft_id)?,
            ))
        })
        .await?;
    let outgoing = crate::mime::OutgoingMessage {
        from: detail.from.clone(),
        reply_to,
        to: &detail.to,
        cc: &detail.cc,
        bcc: &bcc,
        subject: &detail.subject,
        body_text: detail.text_body.as_deref().unwrap_or_default(),
        body_html: detail.html_body.as_deref(),
        in_reply_to: in_reply_to.as_deref(),
        references: &references,
        message_id: stored_message_id.as_deref(),
        message_id_domain: domain,
        attachments: outgoing_attachments,
        receipt_to: &receipt_to,
        importance,
    };
    let security_recipients = outgoing
        .to
        .iter()
        .chain(outgoing.cc)
        .chain(outgoing.bcc)
        .cloned()
        .collect();
    let (message_id, raw) = crate::mime::build_message_owned(outgoing)?;
    let raw =
        crate::mail_security::protect_draft(&ctx.db, config.id, draft_id, raw, security_recipients)
            .await?;
    if raw.len() > max_upload {
        return Err(CoreError::Other(format!(
            "message exceeds the server or local upload limit of {} MiB",
            max_upload.div_ceil(1024 * 1024)
        )));
    }
    let message_id = message_id.trim_matches(['<', '>']).to_owned();
    let stable_id = message_id.clone();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "UPDATE messages SET message_id=?2 WHERE id=?1 AND is_draft=1",
                params![draft_id, stable_id],
            )?;
            Ok(())
        })
        .await?;
    Ok((message_id, raw))
}
