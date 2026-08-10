// crates/kestreld/src/api/logs.rs
//
//! `GET /containers/:id/logs?follow&tail&since` (Task 11) — reads
//! `<data_dir>/containers/<id>/output.jsonl`, the durable log file
//! `kestrel-shim` (Task 2, `kestrel-shim/src/daemon.rs::write_log_line`)
//! owns and appends to for the lifetime of the container. Every line in
//! that file is already a complete, standalone JSON object shaped
//! `{"ts":"<rfc3339>","stream":"stdout"|"stderr","msg":"..."}`.
//!
//! ## Response format (non-`follow`): newline-delimited, not a JSON array
//!
//! The plan explicitly leaves this an open choice ("pick one, document
//! it"). This picks newline-delimited (`Content-Type:
//! application/x-ndjson`) because it matches `output.jsonl`'s own on-disk
//! shape byte-for-byte — no re-wrapping into a `[...]` array, no need to
//! buffer the whole filtered set into one `serde_json::Value` tree before
//! responding, and a client can stream-parse it exactly the way `tail -f`
//! would, one line at a time. Each returned line is passed straight
//! through from the file with no re-serialization.
//!
//! ## `since` filtering: plain string comparison, not a datetime parse
//!
//! Comparing `ts` fields against `?since=<rfc3339>` is done with a plain
//! lexicographic `&str` comparison (`line_ts_at_or_after` below), not a
//! real RFC3339 parse. This is deliberately not a shortcut: `kestrel-
//! shim`'s own `rfc3339_now()` (`kestrel-shim/src/daemon.rs`) always
//! produces a *fixed-width, zero-padded, UTC (`Z`-suffixed)* timestamp
//! (`YYYY-MM-DDTHH:MM:SS.ffffffZ`) — for that one canonical shape,
//! lexicographic byte ordering and chronological ordering are provably
//! identical, so no datetime-parsing dependency is needed at all. This
//! mirrors the exact reasoning `rfc3339_now`'s own doc comment gives for
//! not depending on `chrono`/`time` in the first place — this endpoint
//! just extends that same "no new datetime dependency" choice to the read
//! side. A `since` value NOT in that canonical shape (a non-UTC offset, a
//! different fractional-second width, ...) is not guaranteed to compare
//! correctly — acceptable here since the intended use is comparing
//! against timestamps this same system produced.
//!
//! ## `tail`/`since`: whole-file read, not (yet) streamed
//!
//! `read_filtered_lines` reads `output.jsonl` fully into memory, splits it
//! into lines, then applies `since`/`tail` — a documented, not-yet-
//! optimized approach for very large log files, matching the plan's own
//! explicit allowance ("just read fully if simplicity is preferred for now
//! with a documented note"). This is also what makes the `follow=true`
//! handoff below race-free: see that section for why reading fully (and
//! getting an exact byte count back) matters, not just memory-bounding.
//!
//! ## `follow=true`: SSE, poll-based (not inotify), matching this
//! project's established convention — and the historical/live handoff's
//! real race condition
//!
//! After the filtered historical set is sent, the handler switches to
//! Server-Sent Events: it polls `fs::metadata` for file-size growth every
//! ~200ms (spec'd explicitly by the plan) and emits each newly-appended,
//! complete line as its own SSE `data:` event. This is the same "poll on
//! a plain interval instead of a kernel notification mechanism" posture
//! `kestrel-cgroup`'s `PsiWatcher` (`crates/kestrel-cgroup/src/psi.rs`)
//! established for pressure-stall watching — `PsiWatcher` blocks in
//! `poll(2)` on a kernel-provided PSI trigger fd (a mechanism that has no
//! equivalent for "a plain file grew"), so this endpoint's size-polling
//! loop is the closest analogous choice for *this* kind of watch, not a
//! literal reuse of that code.
//!
//! **A real bug found and fixed during this task's own testing**: the
//! obvious-looking implementation has the live-follow loop independently
//! `fs::metadata`-`stat` the file for its OWN starting byte offset (`pos`)
//! once it starts running, separately from whatever `read_filtered_lines`
//! already consumed to build the historical set. Between those two reads
//! — historical finishing, and the follow loop's own first `stat` — there
//! is a real, non-empty window (spawning the background task, sending
//! every historical line through a bounded channel, tokio scheduling
//! delays under load) during which the shim can append MORE data. A fresh
//! `stat` at that point already reflects those bytes, so the follow loop's
//! `pos` starts past them — they were never part of "historical" (already
//! read before they existed) and are now never treated as "new" either
//! (already counted in the follow loop's baseline). The result: silently
//! dropped log lines, reproduced empirically as a genuine, non-flaky-once-
//! isolated test failure (`test_logs_follow_delivers_historical_then_live_
//! appended_lines`, under concurrent `cargo test` load, where the gap
//! widens enough to matter). The fix: `read_filtered_lines` returns the
//! EXACT number of bytes it read (the whole file's length, since it always
//! reads to EOF regardless of `tail`/`since` filtering the returned set),
//! and `get_logs` hands that number directly to the follow loop as its
//! starting `pos` — closing the gap to zero, since nothing is ever
//! re-`stat`-ed in between.

use std::convert::Infallible;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{Path as PathParam, Query, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::Stream;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::api::AppError;
use crate::AppState;

/// How often the `follow=true` path re-`stat`s `output.jsonl` for growth.
/// Spec'd directly by the plan ("poll `fs::metadata` for size growth every
/// ~200ms").
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// `?follow=true` (axum's `Query` extractor needs an explicit value —
    /// a bare `?follow` with no `=value` does not deserialize as a `bool`
    /// — matching this crate's existing `DeleteQuery::force` convention,
    /// `crates/kestreld/src/api/containers.rs`).
    #[serde(default)]
    pub follow: bool,
    /// `?tail=N` — return only the last `N` lines of the (possibly
    /// `since`-filtered) set.
    #[serde(default)]
    pub tail: Option<usize>,
    /// `?since=<rfc3339>` — see this module's doc comment for the exact
    /// comparison semantics.
    #[serde(default)]
    pub since: Option<String>,
}

/// `GET /containers/:id/logs?follow&tail&since`.
pub async fn get_logs(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Response, AppError> {
    // Real `404` for an unknown id, matching every other endpoint's
    // `get_registered`-style convention (`api::containers`) — a container
    // whose registry entry has already been removed (e.g. `DELETE`) must
    // not fall through to a confusing "empty log file" response.
    if !state.registry.read().await.contains_key(&id) {
        return Err(AppError::not_found(format!("container {id} not found")));
    }

    let log_path = state.data_dir.join("containers").join(&id).join("output.jsonl");
    let (historical, read_through) =
        read_filtered_lines(&log_path, query.tail, query.since.as_deref()).await?;

    if query.follow {
        // `read_through` is the EXACT byte length of `output.jsonl` that
        // `read_filtered_lines` accounted for — see this module's doc
        // comment ("A real bug found...") for why handing this precise
        // number to the follow loop, rather than letting it re-`stat` the
        // file itself, is what makes the historical/live handoff race-free.
        let stream = build_follow_stream(log_path, historical, read_through);
        Ok(Sse::new(stream).keep_alive(KeepAlive::default()).into_response())
    } else {
        Ok(ndjson_response(historical))
    }
}

/// Builds the non-`follow` response: the filtered lines, newline-joined,
/// with a trailing newline (so the body is itself a valid, directly-
/// concatenable `.jsonl` fragment) — see this module's doc comment for why
/// this shape was chosen over a JSON array.
fn ndjson_response(lines: Vec<String>) -> Response {
    let mut body = lines.join("\n");
    if !lines.is_empty() {
        body.push('\n');
    }
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/x-ndjson")], body).into_response()
}

/// Drains every complete, `\n`-terminated line out of `buf`, leaving any
/// dangling trailing bytes (a line the writer hasn't finished — i.e. a
/// write caught mid-`write_all`, see this module's doc comment) behind in
/// `buf`, untouched, for a later call to pick up once the rest of the line
/// has been written. Shared by `read_filtered_lines` (called once against
/// the whole file's bytes) and `follow_and_send` (called against its own
/// persistent `partial` buffer on every poll) so this "never treat an
/// unterminated trailing line as complete" rule can't drift out of sync
/// between the two call sites — it was fixed in `follow_and_send` first and
/// `read_filtered_lines` had silently regressed from it before this fix.
fn drain_complete_lines(buf: &mut Vec<u8>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Some(nl_idx) = buf.iter().position(|&b| b == b'\n') {
        let line_bytes: Vec<u8> = buf.drain(..=nl_idx).collect();
        lines.push(String::from_utf8_lossy(&line_bytes[..line_bytes.len() - 1]).into_owned());
    }
    lines
}

/// Reads and filters `output.jsonl` per `tail`/`since`, returning the
/// filtered lines AND the exact byte offset this read accounted for as
/// COMPLETE, newline-terminated lines — NOT necessarily the whole file's
/// length. If the file's tail is a dangling partial line (the shim's
/// `write_all` for that line hadn't finished when this read landed — see
/// this module's doc comment for the full "torn write" scenario this
/// guards against), that partial line is excluded from both the returned
/// lines and the returned byte offset, so a later read starting from that
/// offset re-reads it from its own start once it's complete, rather than
/// ever treating the torn fragment as a real line. A missing log file
/// (container created but nothing written yet, or `follow`ing a container
/// whose shim hasn't opened the file for the first time yet — see
/// `kestrel-shim/src/daemon.rs::run`, which creates it unconditionally very
/// early, so this is mostly defensive) is treated as "no lines yet, zero
/// bytes", not an error.
///
/// Reads the whole file into memory in one shot rather than streaming —
/// see this module's doc comment for why (both the plan's own allowance
/// for this simplification, AND why an exact byte count matters for
/// `follow=true`'s race-free handoff).
async fn read_filtered_lines(
    path: &Path,
    tail: Option<usize>,
    since: Option<&str>,
) -> anyhow::Result<(Vec<String>, u64)> {
    let mut bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let total_len = bytes.len() as u64;

    // `drain_complete_lines` leaves any dangling, not-yet-`\n`-terminated
    // trailing bytes behind in `bytes` — so whatever's left in `bytes`
    // afterward is exactly the torn partial line (if any) that must NOT be
    // counted as read. `read_through` therefore stops at the last complete
    // line's end, not at EOF of the raw read.
    let mut lines = drain_complete_lines(&mut bytes);
    let read_through = total_len - bytes.len() as u64;

    if let Some(since) = since {
        lines.retain(|line| line_ts_at_or_after(line, since));
    }
    if let Some(n) = tail {
        let start = lines.len().saturating_sub(n);
        lines.drain(..start);
    }

    Ok((lines, read_through))
}

/// `true` iff `line`'s `ts` field, compared lexicographically against
/// `since`, is `>=` it — see this module's doc comment for why plain
/// string comparison is correct for the shim's canonical timestamp shape.
/// A malformed line (shouldn't happen — the shim only ever writes valid
/// JSON — but defensive against a hand-edited/corrupt file) is excluded
/// rather than panicking or aborting the whole read.
fn line_ts_at_or_after(line: &str, since: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(v) => v
            .get("ts")
            .and_then(|t| t.as_str())
            .map(|ts| ts >= since)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Builds the SSE stream for `follow=true`: a background task first
/// forwards every already-filtered historical line into an internal
/// channel, then hands off to `follow_and_send`'s poll loop — seeded with
/// `read_through` (the exact byte offset `read_filtered_lines` already
/// accounted for, see this module's doc comment for why that, and not a
/// fresh `stat`, is what this loop starts from) — for new appends; the
/// returned `Stream` just drains that channel one line per SSE `Event`.
fn build_follow_stream(
    log_path: PathBuf,
    historical: Vec<String>,
    read_through: u64,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(256);

    tokio::spawn(async move {
        for line in historical {
            if tx.send(line).await.is_err() {
                return; // client already gone
            }
        }
        if let Err(e) = follow_and_send(&log_path, read_through, &tx).await {
            tracing::warn!(
                path = %log_path.display(),
                error = %e,
                "logs follow loop ended with an error"
            );
        }
    });

    futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|line| (Ok(Event::default().data(line)), rx))
    })
}

/// Polls `path`'s size every `FOLLOW_POLL_INTERVAL`, starting from `pos`
/// (the caller's already-accounted-for byte offset — see `build_follow_
/// stream`'s doc comment for why this must NOT be independently re-`stat`-
/// ed here). Whenever the file has grown past `pos`, reads exactly the
/// newly-appended bytes, splits them into complete lines (holding back any
/// trailing partial line — a write in progress — until a later poll
/// completes it), and sends each complete line into `tx`. Returns once the
/// client disconnects (`tx` closed) — this is the normal, expected way
/// this loop ends, not an error; it otherwise runs forever (there is no
/// "container exited" signal this endpoint currently reacts to on its own
/// — the SSE connection simply stays open, matching a plain `tail -f`'s
/// own behavior of not exiting when the watched process does).
async fn follow_and_send(
    path: &Path,
    mut pos: u64,
    tx: &tokio::sync::mpsc::Sender<String>,
) -> anyhow::Result<()> {
    let mut partial: Vec<u8> = Vec::new();
    let mut interval = tokio::time::interval(FOLLOW_POLL_INTERVAL);
    interval.tick().await; // first tick fires immediately; consume it before the real polling loop

    loop {
        interval.tick().await;
        if tx.is_closed() {
            return Ok(());
        }

        let len = match tokio::fs::metadata(path).await {
            Ok(m) => m.len(),
            Err(_) => continue, // momentarily missing/racy — keep polling
        };
        if len <= pos {
            continue;
        }

        let mut file = tokio::fs::File::open(path)
            .await
            .context("reopening output.jsonl for follow")?;
        file.seek(SeekFrom::Start(pos)).await.context("seeking output.jsonl")?;
        let mut buf = vec![0u8; (len - pos) as usize];
        file.read_exact(&mut buf).await.context("reading appended output.jsonl bytes")?;
        pos = len;

        partial.extend_from_slice(&buf);
        for line in drain_complete_lines(&mut partial) {
            if tx.send(line).await.is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use crate::registry::{ContainerHandle, ContainerMeta};

    use super::*;

    fn make_state(data_dir: PathBuf, id: &str) -> Arc<AppState> {
        let mut map = HashMap::new();
        map.insert(
            id.to_string(),
            ContainerHandle {
                id: id.to_string(),
                bundle_path: PathBuf::new(),
                meta: ContainerMeta::default(),
            },
        );
        Arc::new(AppState {
            run_dir: PathBuf::new(),
            data_dir,
            registry: Arc::new(RwLock::new(map)),
            shim_path: PathBuf::new(),
            runtime_path: PathBuf::new(),
            stop_grace_period_s: 10,
            metrics_rx: tokio::sync::Mutex::new(tokio::sync::mpsc::channel(1).1),
            event_bus: crate::events::new_bus(),
            last_status_map: crate::metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: crate::api::introspect::SeccompLog::new(),
        })
    }

    fn write_output_jsonl(data_dir: &Path, id: &str, lines: &[&str]) {
        let dir = data_dir.join("containers").join(id);
        std::fs::create_dir_all(&dir).expect("mkdir container log dir");
        let mut content = lines.join("\n");
        content.push('\n');
        std::fs::write(dir.join("output.jsonl"), content).expect("write output.jsonl");
    }

    fn line(ts: &str, stream: &str, msg: &str) -> String {
        serde_json::json!({ "ts": ts, "stream": stream, "msg": msg }).to_string()
    }

    async fn body_text(response: Response) -> String {
        let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    #[tokio::test]
    async fn test_logs_without_follow_returns_ndjson_of_all_lines() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        let l0 = line("2026-08-08T00:00:00.000000Z", "stdout", "one");
        let l1 = line("2026-08-08T00:00:01.000000Z", "stdout", "two");
        let l2 = line("2026-08-08T00:00:02.000000Z", "stderr", "three");
        write_output_jsonl(data_dir.path(), id, &[&l0, &l1, &l2]);

        let state = make_state(data_dir.path().to_path_buf(), id);
        let app = crate::build_router(state);
        let request = Request::builder()
            .uri(format!("/containers/{id}/logs"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-ndjson"
        );
        let body = body_text(response).await;
        assert_eq!(body, format!("{l0}\n{l1}\n{l2}\n"));
    }

    #[tokio::test]
    async fn test_logs_tail_returns_only_last_n_lines() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        let l0 = line("2026-08-08T00:00:00.000000Z", "stdout", "one");
        let l1 = line("2026-08-08T00:00:01.000000Z", "stdout", "two");
        let l2 = line("2026-08-08T00:00:02.000000Z", "stderr", "three");
        write_output_jsonl(data_dir.path(), id, &[&l0, &l1, &l2]);

        let state = make_state(data_dir.path().to_path_buf(), id);
        let app = crate::build_router(state);
        let request = Request::builder()
            .uri(format!("/containers/{id}/logs?tail=2"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert_eq!(body, format!("{l1}\n{l2}\n"));
    }

    #[tokio::test]
    async fn test_logs_since_filters_by_timestamp() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        let l0 = line("2026-08-08T00:00:00.000000Z", "stdout", "one");
        let l1 = line("2026-08-08T00:00:01.000000Z", "stdout", "two");
        let l2 = line("2026-08-08T00:00:02.000000Z", "stderr", "three");
        write_output_jsonl(data_dir.path(), id, &[&l0, &l1, &l2]);

        let state = make_state(data_dir.path().to_path_buf(), id);
        let app = crate::build_router(state);
        let request = Request::builder()
            .uri(format!("/containers/{id}/logs?since=2026-08-08T00:00:01.000000Z"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert_eq!(body, format!("{l1}\n{l2}\n"));
    }

    /// Reproduces the exact "torn write" scenario this fix addresses: a
    /// read of `output.jsonl` lands precisely mid-`write_all` for a log
    /// line (matching `kestrel-shim`'s own `write_log_line`), so the file
    /// on disk ends with a non-empty, non-`\n`-terminated fragment rather
    /// than a complete line. Drives the real HTTP endpoint (no `follow`)
    /// twice: once while the write is "torn" (the fragment must be
    /// excluded from the response, not returned as malformed/corrupt
    /// data), and once after the shim "finishes" the write (the
    /// previously-torn line must now come back whole, exactly once — not
    /// duplicated, not still fragmented).
    #[tokio::test]
    async fn test_logs_excludes_torn_trailing_line_and_recovers_it_intact_once_written() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        let l0 = line("2026-08-08T00:00:00.000000Z", "stdout", "one");
        write_output_jsonl(data_dir.path(), id, &[&l0]);

        let l1 = line("2026-08-08T00:00:01.000000Z", "stdout", "two");
        let split_at = l1.len() / 2;
        let (first_half, second_half) = l1.split_at(split_at);

        let path = data_dir.path().join("containers").join(id).join("output.jsonl");
        {
            use std::io::Write;
            // A real O_APPEND write of only HALF of `l1`'s bytes, and
            // crucially no trailing '\n' — this is exactly what the file
            // looks like if a read lands mid-`write_all`.
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open output.jsonl for append");
            f.write_all(first_half.as_bytes()).expect("append torn first half");
        }

        let state = make_state(data_dir.path().to_path_buf(), id);
        let app = crate::build_router(state.clone());
        let request = Request::builder()
            .uri(format!("/containers/{id}/logs"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        // Only the one complete line — the torn fragment must not appear
        // anywhere in the response, whole or partial.
        assert_eq!(body, format!("{l0}\n"));
        assert!(!body.contains(first_half), "torn fragment leaked into response: {body:?}");

        // The shim "finishes" the write: the rest of the line's bytes, then
        // its own terminating '\n' (mirroring `write_log_line`'s two
        // separate `write_all` calls).
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open output.jsonl for append");
            f.write_all(second_half.as_bytes()).expect("append torn second half");
            f.write_all(b"\n").expect("append trailing newline");
        }

        let app = crate::build_router(state);
        let request = Request::builder()
            .uri(format!("/containers/{id}/logs"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        // The previously-torn line must now be back, complete and exactly
        // once — not duplicated (which would happen if the first read's
        // `read_through` had already consumed the fragment's bytes) and
        // not still fragmented.
        assert_eq!(body, format!("{l0}\n{l1}\n"));
    }

    /// Unit-level companion to the endpoint test above: exercises
    /// `read_filtered_lines` directly to pin down the exact byte-offset
    /// contract the `follow=true` handoff depends on (see this module's
    /// doc comment's "A real bug found..." section) — `read_through` must
    /// stop at the end of the last COMPLETE line, not at the raw read's
    /// EOF, so that a later reader (another call to this function, or
    /// `follow_and_send`'s poll loop) starting from `read_through` re-reads
    /// the torn fragment's bytes from their own start rather than skipping
    /// past them.
    #[tokio::test]
    async fn test_read_filtered_lines_read_through_stops_before_torn_trailing_line() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        let l0 = line("2026-08-08T00:00:00.000000Z", "stdout", "one");
        write_output_jsonl(data_dir.path(), id, &[&l0]);

        let l1 = line("2026-08-08T00:00:01.000000Z", "stdout", "two");
        let split_at = l1.len() / 2;
        let (first_half, second_half) = l1.split_at(split_at);

        let path = data_dir.path().join("containers").join(id).join("output.jsonl");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open output.jsonl for append");
            f.write_all(first_half.as_bytes()).expect("append torn first half");
        }

        let (lines, read_through) =
            read_filtered_lines(&path, None, None).await.expect("read_filtered_lines");

        // The torn fragment is excluded from the returned lines...
        assert_eq!(lines, vec![l0.clone()]);
        // ...and `read_through` stops exactly at the end of `l0` + its
        // '\n' — NOT at EOF of the raw read (which would additionally
        // include every byte of the still-incomplete fragment).
        let expected_read_through = (l0.len() + 1) as u64;
        assert_eq!(read_through, expected_read_through);

        // Simulate the shim finishing the write.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open output.jsonl for append");
            f.write_all(second_half.as_bytes()).expect("append torn second half");
            f.write_all(b"\n").expect("append trailing newline");
        }

        // A follow-loop-style continuation: read only the bytes from
        // `read_through` onward (exactly what `follow_and_send` does with
        // its own `pos`) and confirm the fragment's remainder plus the
        // newly-written bytes reassemble into `l1`, whole and exactly
        // once — not a duplicate of any part of `l0`, not a corrupted
        // half-line.
        let full_bytes = std::fs::read(&path).expect("read output.jsonl after completing write");
        let mut tail = full_bytes[read_through as usize..].to_vec();
        let recovered = drain_complete_lines(&mut tail);
        assert_eq!(recovered, vec![l1]);
        assert!(tail.is_empty(), "leftover unconsumed bytes after recovering the line: {tail:?}");
    }

    #[tokio::test]
    async fn test_logs_unknown_container_is_404() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let state = make_state(data_dir.path().to_path_buf(), "some-other-id");
        let app = crate::build_router(state);
        let request = Request::builder()
            .uri("/containers/does-not-exist/logs")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Reads SSE frames from `body` until the accumulated text (since this
    /// call started — NOT including anything a prior call already drained)
    /// contains `needle`, bounded by `timeout`. Returns the body back so
    /// callers can chain further reads (e.g. historical-set-then-live-
    /// append) against the exact same, still-open stream without skipping
    /// or re-reading any bytes — the real proof that `follow=true`
    /// delivers a live-appended line within a bounded time, not just that
    /// the historical set was sent.
    async fn collect_sse_until(mut body: Body, needle: &str, timeout: Duration) -> (String, Body) {
        let mut acc = String::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!("timed out waiting for SSE stream to contain {needle:?}; got so far: {acc:?}");
            }
            let frame = tokio::time::timeout(remaining, body.frame())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for next SSE frame; got so far: {acc:?}"))
                .expect("SSE body stream ended unexpectedly")
                .expect("reading SSE frame");
            if let Some(data) = frame.data_ref() {
                acc.push_str(&String::from_utf8_lossy(data));
            }
            if acc.contains(needle) {
                return (acc, body);
            }
        }
    }

    #[tokio::test]
    async fn test_logs_follow_delivers_historical_then_live_appended_lines() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        let l0 = line("2026-08-08T00:00:00.000000Z", "stdout", "one");
        write_output_jsonl(data_dir.path(), id, &[&l0]);

        let state = make_state(data_dir.path().to_path_buf(), id);
        let app = crate::build_router(state);
        let request = Request::builder()
            .uri(format!("/containers/{id}/logs?follow=true"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();

        // The historical line must show up first, quickly (no need to wait
        // out a poll interval for it).
        let (acc, body) = collect_sse_until(body, "\"msg\":\"one\"", Duration::from_secs(5)).await;
        assert!(acc.contains("\"msg\":\"one\""));

        // Append a new line directly to the file (simulating the shim
        // writing more container output) mid-request, then confirm the SSE
        // stream delivers it live, within a bounded time (well over the
        // 200ms poll interval, comfortably bounded). `collect_sse_until`
        // hands ownership of the body back, so this second call continues
        // reading from exactly where the first left off — no lines are
        // skipped or re-read.
        //
        // Uses a real O_APPEND open (matching exactly what `kestrel-shim`
        // itself does, `kestrel-shim/src/daemon.rs::run`'s `OpenOptions::
        // new().append(true)`), NOT a read-modify-write-the-whole-file
        // `std::fs::write` — that alternative would briefly TRUNCATE the
        // file (its own `File::create`-equivalent `O_TRUNC` open happens
        // before the new bytes are written), which can race the follow
        // loop's own read into observing a shorter-than-`pos` length and
        // is not representative of how the real shim ever touches this
        // file.
        let l1 = line("2026-08-08T00:00:05.000000Z", "stdout", "two-live");
        let path = data_dir.path().join("containers").join(id).join("output.jsonl");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open output.jsonl for append");
            f.write_all(l1.as_bytes()).expect("append live line");
            f.write_all(b"\n").expect("append trailing newline");
        }

        let (acc2, _body) = collect_sse_until(body, "\"msg\":\"two-live\"", Duration::from_secs(5)).await;
        assert!(acc2.contains("\"msg\":\"two-live\""));
    }
}
