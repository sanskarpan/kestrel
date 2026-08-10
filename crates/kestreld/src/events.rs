// crates/kestreld/src/events.rs
//
//! Phase 9 Task 14: the real event bus (SPEC.md §13's `### Events`
//! section) and `GET /events` SSE endpoint.
//!
//! This is the ONLY module in the daemon allowed to construct an [`Event`]
//! from a [`crate::metrics::MetricsSignal`] — `metrics.rs`'s own module
//! doc comment says so explicitly, and its `MetricsSignal` type is
//! deliberately shaped differently from this one so the two can't be
//! confused for each other. `spawn_consumer` below is that one real
//! consumer: it drains `AppState.metrics_rx` (Task 13's single 1Hz
//! poller's signal channel) for the daemon's entire lifetime and
//! translates each signal into zero or one [`Event`], published onto this
//! module's [`EventBus`].
//!
//! ## The `StatusTransition` -> `Event` mapping, and why it's NOT one-to-one
//!
//! `MetricsSignal::StatusTransition{from, to}` is a raw diff of
//! `state.json`'s `status` field between two sampler ticks. Naively
//! mapping every distinct `(from, to)` pair to its own `Event` would
//! double-publish: `POST /containers/:id/start`, `.../pause`, and
//! `.../unpause` (`api::containers`, Task 9) already publish
//! `ContainerStart`/`ContainerPause`/`ContainerUnpause` directly, the
//! moment their own `kestrel-runtime` subcommand succeeds — which is
//! exactly the same real-world occurrence the sampler would ALSO observe
//! as `Created`->`Running`, `Running`->`Paused`, or `Paused`->`Running` on
//! its very next tick. Translating those same transitions here too would
//! mean every one of those three actions produces the same event twice on
//! the bus.
//!
//! So this function translates exactly ONE case: any transition landing
//! on `Status::Stopped` (`Running`->`Stopped` in the common case, but also
//! `Created`->`Stopped`/`Paused`->`Stopped` — e.g. an external `kill -9`
//! before `start`, or while paused) becomes `Event::ContainerDie`. This is
//! deliberately a death-adjacent event no ORDINARY handler publishes
//! directly: `POST .../stop` only sends signals and polls for `Stopped`
//! before returning `200`, `POST .../kill` sends a signal and returns
//! immediately without knowing when (or if) the process actually dies,
//! and a container can die with no HTTP call involved at all (OOM kill,
//! an operator's own `kill -9`, a crash) — the sampler's own re-read of
//! `state.json` is the ordinary source for `ContainerDie`.
//!
//! **One deliberate exception**: `api::containers::delete_container`
//! ALSO publishes `Event::ContainerDie` directly, but only via
//! `metrics::check_terminal_transition` against the SAME shared
//! `metrics::LastStatusMap` this module's own `spawn_consumer` translation
//! pipeline is fed from — see that type's own doc comment for the real,
//! reproduced race this closes (`kestrel-runtime delete` removes
//! `state.json` entirely, so a stop-then-immediately-delete sequence can
//! outrun the sampler's next tick and silently lose the death forever).
//! Sharing the map is what keeps this from being a second, independent
//! publisher: whichever of the two (the periodic tick, or this one
//! synchronous pre-delete check) observes the transition FIRST is the
//! sole publisher for that occurrence, by construction — not a
//! coincidence this doc comment's own dedup guarantee depends on.
//!
//! Every other `(from, to)` pair (`Creating`->`Created`, `Created`->`Running`,
//! `Running`->`Paused`, `Paused`->`Running`) is either not a real SPEC.md
//! event at all (`Creating`->`Created` — nothing in the plan's Step 1 list
//! corresponds to "the runtime finished creating") or already published
//! directly by the owning handler, and is intentionally ignored here.
//!
//! `MetricsSignal::StatusTransition` itself carries no `exit_code` — only
//! `from`/`to` statuses (see that variant's own doc comment in
//! `metrics.rs`) — so `ContainerDie`'s `exit_code` is filled in with a
//! fresh, real read of `state.json` (`registry::read_state`) at
//! translation time, the same "state.json is the one source of truth"
//! convention every other read path in this crate already follows.
//!
//! `MetricsSignal::Oom`/`PsiThreshold`/`CgroupThrottle` have no such
//! ambiguity — nothing else in the daemon ever publishes
//! `ContainerOom`/`PsiThreshold`/`CgroupThrottle`, so each one maps
//! straight across, one signal to one event.

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use futures_util::Stream;
use tokio::sync::broadcast;

use crate::metrics::{CgroupResource, MetricsSignal};
use crate::{registry, AppState};

/// Bounded, not unbounded — matches `metrics::SIGNAL_CHANNEL_CAPACITY`'s
/// own reasoning: `broadcast::Sender::send` never blocks regardless (a
/// `tokio::sync::broadcast` channel drops the OLDEST unread message per
/// lagging receiver rather than ever blocking the sender), but a bound
/// still caps how much a slow/absent SSE subscriber can force this
/// channel to buffer per-subscriber before it starts reporting
/// [`broadcast::error::RecvError::Lagged`] to that subscriber specifically
/// — see `get_events`'s own handling of that error.
const EVENT_BUS_CAPACITY: usize = 1024;

/// SPEC.md §13's `### Events` section, verbatim: `container.create|start|
/// die|oom|pause|unpause|destroy`, `image.pull.progress|pull.done`,
/// `net.attach|detach`, `copyup`, `seccomp.violation`, `psi.threshold`,
/// `cgroup.throttle`. `image.pull.*`/`net.*`/`copyup`/`seccomp.violation`
/// have no publisher yet (Tasks 15/16/17/20's job) — defined now so this
/// enum's shape never has to change again, only grow real callers.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "container.create")]
    ContainerCreate { id: String },
    #[serde(rename = "container.start")]
    ContainerStart { id: String },
    #[serde(rename = "container.die")]
    ContainerDie { id: String, exit_code: Option<i32> },
    #[serde(rename = "container.oom")]
    ContainerOom { id: String },
    #[serde(rename = "container.pause")]
    ContainerPause { id: String },
    #[serde(rename = "container.unpause")]
    ContainerUnpause { id: String },
    #[serde(rename = "container.destroy")]
    ContainerDestroy { id: String },
    #[serde(rename = "image.pull.progress")]
    ImagePullProgress { reference: String, detail: String },
    #[serde(rename = "image.pull.done")]
    ImagePullDone { reference: String },
    #[serde(rename = "net.attach")]
    NetAttach { id: String },
    #[serde(rename = "net.detach")]
    NetDetach { id: String },
    #[serde(rename = "copyup")]
    CopyUp { id: String, path: String, size_bytes: u64 },
    #[serde(rename = "seccomp.violation")]
    SeccompViolation { id: String, syscall: String },
    #[serde(rename = "psi.threshold")]
    PsiThreshold { id: String, resource: String },
    #[serde(rename = "cgroup.throttle")]
    CgroupThrottle { id: String },
}

pub type EventBus = broadcast::Sender<Event>;

/// Builds a fresh, real event bus — called exactly once at daemon
/// startup (`main()`); every HTTP handler and `spawn_consumer` below share
/// the one clone stored on `AppState`.
pub fn new_bus() -> EventBus {
    broadcast::channel(EVENT_BUS_CAPACITY).0
}

/// Publishes `event` onto `bus`. `broadcast::Sender::send` errors only
/// when there are currently zero subscribers — an entirely ordinary,
/// expected state (no client has an open `GET /events` connection right
/// now) matching `metrics::publish`'s own "a receiver-less channel is not
/// an operational problem" posture, so this deliberately discards that
/// error rather than logging it at any level that would page anyone.
pub(crate) fn publish(bus: &EventBus, event: Event) {
    let _ = bus.send(event);
}

/// `GET /events` — SSE. Subscribes a fresh `Receiver` (each connected
/// client gets its own, independent, full copy of every event published
/// from this point forward — `broadcast`'s whole point), then forwards
/// every [`Event`] as `data: <json>\n\n`.
///
/// [`broadcast::error::RecvError::Lagged`] (this ONE subscriber fell more
/// than `EVENT_BUS_CAPACITY` events behind — e.g. a slow client, or a
/// burst of PSI-threshold/throttle signals) is handled by logging and
/// resuming from the next still-buffered event, never by ending the
/// stream: one dropped event must never kill an otherwise-healthy SSE
/// connection out from under a client who's simply gotten a little
/// behind.
pub async fn get_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let rx = state.event_bus.subscribe();
    Sse::new(event_stream(rx)).keep_alive(KeepAlive::default())
}

/// `stream::unfold`, not a hand-rolled `Stream` impl — same shape
/// `api::logs::build_follow_stream` already established for turning a
/// polling/`recv`-driven loop into an SSE body: each call awaits exactly
/// one more item (or, on `Lagged`, loops internally until it gets a real
/// one) before yielding.
fn event_stream(
    rx: broadcast::Receiver<Event>,
) -> impl Stream<Item = Result<SseEvent, std::convert::Infallible>> {
    futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event).unwrap_or_else(|e| {
                        // Every `Event` variant is plain, always-serializable
                        // data (Strings/Options/numbers) — this branch is not
                        // expected to ever actually run; defensive only.
                        tracing::error!(error = %e, "failed to serialize Event for SSE — dropping it");
                        String::new()
                    });
                    if data.is_empty() {
                        continue;
                    }
                    return Some((Ok(SseEvent::default().data(data)), rx));
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "GET /events subscriber lagged — some events were dropped; continuing");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

fn cgroup_resource_name(resource: CgroupResource) -> &'static str {
    match resource {
        CgroupResource::Cpu => "cpu",
        CgroupResource::Memory => "memory",
        CgroupResource::Io => "io",
    }
}

/// Translates one [`MetricsSignal`] into zero or one [`Event`] — see this
/// module's own doc comment for the full `StatusTransition` reasoning.
/// `run_dir` is needed only for the `ContainerDie` case's real
/// `state.json` re-read (`MetricsSignal::StatusTransition` itself carries
/// no `exit_code`).
async fn translate_signal(run_dir: &Path, signal: MetricsSignal) -> Option<Event> {
    match signal {
        MetricsSignal::StatusTransition { id, from: _, to } => {
            if to != kestrel_oci::state::Status::Stopped {
                // Creating->Created isn't a real SPEC.md event;
                // Created->Running / Running->Paused / Paused->Running are
                // already published directly by their owning handler
                // (start/pause/unpause, `api::containers`) — see this
                // module's doc comment for why re-publishing them here
                // would double-publish the same real-world occurrence.
                return None;
            }
            let exit_code = registry::read_state(run_dir, &id).await.ok().and_then(|s| s.exit_code);
            Some(Event::ContainerDie { id, exit_code })
        }
        MetricsSignal::Oom { id, .. } => Some(Event::ContainerOom { id }),
        MetricsSignal::PsiThreshold { id, resource, .. } => {
            Some(Event::PsiThreshold { id, resource: cgroup_resource_name(resource).to_string() })
        }
        MetricsSignal::CgroupThrottle { id, .. } => Some(Event::CgroupThrottle { id }),
    }
}

/// Spawns the Task 13 signal-channel consumer as a detached background
/// task — the ONLY consumer of `AppState.metrics_rx` for the daemon's
/// entire lifetime (that field's own doc comment on `AppState`). Holds
/// the `tokio::sync::Mutex` lock for the whole task's life: this is the
/// sole intended consumer, so there is no contention to avoid by
/// re-acquiring it per message.
///
/// Runs forever, same "no cancellation mechanism yet" posture as
/// `metrics::spawn` itself (that function's own doc comment) — a later
/// graceful-shutdown task (Phase 9 Task 21) is the natural place to add
/// one for both.
pub fn spawn_consumer(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut rx = state.metrics_rx.lock().await;
        while let Some(signal) = rx.recv().await {
            if let Some(event) = translate_signal(&state.run_dir, signal).await {
                publish(&state.event_bus, event);
            }
        }
        // `None`: the metrics sampler's own task ended (it shouldn't —
        // `metrics::spawn`'s loop has no exit path either — but if it
        // ever does, e.g. a future refactor adds one, there is nothing
        // left to consume; let this task end quietly rather than spin).
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(id: &str, from: kestrel_oci::state::Status, to: kestrel_oci::state::Status) -> MetricsSignal {
        MetricsSignal::StatusTransition { id: id.to_string(), from, to }
    }

    /// The core of this task's own mapping decision: a transition TO
    /// `Stopped` becomes `ContainerDie`, with a real `exit_code` read back
    /// from `state.json` (not `None` just because the signal itself
    /// didn't carry one).
    #[tokio::test]
    async fn test_running_to_stopped_becomes_container_die_with_real_exit_code() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let id = "c1";
        write_state(run_dir.path(), id, kestrel_oci::state::Status::Stopped, Some(137));

        let event = translate_signal(
            run_dir.path(),
            transition(id, kestrel_oci::state::Status::Running, kestrel_oci::state::Status::Stopped),
        )
        .await;
        match event {
            Some(Event::ContainerDie { id: got_id, exit_code }) => {
                assert_eq!(got_id, id);
                assert_eq!(exit_code, Some(137));
            }
            other => panic!("expected Some(ContainerDie{{exit_code: Some(137)}}), got {other:?}"),
        }
    }

    /// A container that dies before ever reaching `Running` (e.g. an
    /// external `kill -9` against a `Created`-but-not-started container)
    /// must still produce `ContainerDie` — `to == Stopped` is the whole
    /// condition, not `from == Running`.
    #[tokio::test]
    async fn test_created_to_stopped_also_becomes_container_die() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let id = "c2";
        write_state(run_dir.path(), id, kestrel_oci::state::Status::Stopped, Some(137));

        let event = translate_signal(
            run_dir.path(),
            transition(id, kestrel_oci::state::Status::Created, kestrel_oci::state::Status::Stopped),
        )
        .await;
        assert!(matches!(event, Some(Event::ContainerDie { .. })));
    }

    /// The double-publish guard this whole module exists to enforce:
    /// `Created`->`Running`, `Running`->`Paused`, and `Paused`->`Running`
    /// must all translate to `None` here — those three are published
    /// directly by their owning HTTP handler (`api::containers::
    /// start_container`/`pause_container`/`unpause_container`), and
    /// re-publishing them from the transition signal too would emit the
    /// same real-world occurrence twice on the bus.
    #[tokio::test]
    async fn test_start_pause_unpause_transitions_are_not_translated() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        for (from, to) in [
            (kestrel_oci::state::Status::Creating, kestrel_oci::state::Status::Created),
            (kestrel_oci::state::Status::Created, kestrel_oci::state::Status::Running),
            (kestrel_oci::state::Status::Running, kestrel_oci::state::Status::Paused),
            (kestrel_oci::state::Status::Paused, kestrel_oci::state::Status::Running),
        ] {
            let event = translate_signal(run_dir.path(), transition("c3", from, to)).await;
            assert!(event.is_none(), "expected {from:?}->{to:?} to translate to None, got {event:?}");
        }
    }

    #[tokio::test]
    async fn test_oom_signal_becomes_container_oom_event() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let event = translate_signal(
            run_dir.path(),
            MetricsSignal::Oom { id: "c4".to_string(), oom_kill_count: 1 },
        )
        .await;
        assert!(matches!(event, Some(Event::ContainerOom { id }) if id == "c4"));
    }

    #[tokio::test]
    async fn test_psi_threshold_signal_becomes_psi_threshold_event_with_resource_name() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let event = translate_signal(
            run_dir.path(),
            MetricsSignal::PsiThreshold { id: "c5".to_string(), resource: CgroupResource::Memory, avg10: 12.3 },
        )
        .await;
        match event {
            Some(Event::PsiThreshold { id, resource }) => {
                assert_eq!(id, "c5");
                assert_eq!(resource, "memory");
            }
            other => panic!("expected Some(PsiThreshold{{resource: \"memory\"}}), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_cgroup_throttle_signal_becomes_cgroup_throttle_event() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let event = translate_signal(
            run_dir.path(),
            MetricsSignal::CgroupThrottle { id: "c6".to_string(), nr_throttled: 3 },
        )
        .await;
        assert!(matches!(event, Some(Event::CgroupThrottle { id }) if id == "c6"));
    }

    /// A `ContainerDie` translation whose `state.json` is unreadable
    /// (raced a concurrent delete, e.g.) must not panic — `exit_code`
    /// degrades to `None` rather than the whole translation failing.
    #[tokio::test]
    async fn test_container_die_with_unreadable_state_json_degrades_to_none_exit_code() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let event = translate_signal(
            run_dir.path(),
            transition("nonexistent", kestrel_oci::state::Status::Running, kestrel_oci::state::Status::Stopped),
        )
        .await;
        match event {
            Some(Event::ContainerDie { id, exit_code }) => {
                assert_eq!(id, "nonexistent");
                assert_eq!(exit_code, None);
            }
            other => panic!("expected Some(ContainerDie{{exit_code: None}}), got {other:?}"),
        }
    }

    /// Proves `spawn_consumer`'s wiring end to end WITHOUT needing root or
    /// a real container: a plain `MetricsSignal` sent into `AppState.
    /// metrics_rx`'s sender half must come back out translated as the
    /// right `Event` on a subscriber of `AppState.event_bus`. No
    /// `#[ignore]` — this needs no privileged syscalls at all, just the
    /// two channels `spawn_consumer` bridges.
    #[tokio::test]
    async fn test_spawn_consumer_translates_and_publishes_a_real_signal() {
        let run_dir = tempfile::tempdir().expect("tempdir");
        let (metrics_tx, metrics_rx) = tokio::sync::mpsc::channel::<MetricsSignal>(16);
        let registry: crate::registry::Registry =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        let state = std::sync::Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: run_dir.path().to_path_buf(),
            registry,
            shim_path: std::path::PathBuf::new(),
            runtime_path: std::path::PathBuf::new(),
            stop_grace_period_s: 10,
            metrics_rx: tokio::sync::Mutex::new(metrics_rx),
            event_bus: new_bus(),
            last_status_map: crate::metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: crate::api::introspect::SeccompLog::new(),
        });
        let mut sub = state.event_bus.subscribe();
        spawn_consumer(state.clone());

        metrics_tx.send(MetricsSignal::Oom { id: "abc".to_string(), oom_kill_count: 1 }).await.unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), sub.recv())
            .await
            .expect("spawn_consumer never translated/published the signal within 5s")
            .expect("event_bus subscriber recv");
        assert!(matches!(event, Event::ContainerOom { id } if id == "abc"));
    }

    /// `Event`'s `#[serde(tag = "type")]` wire shape, pinned down directly
    /// against SPEC.md §13's literal event-type strings — a rename typo
    /// here would silently break every real client parsing `GET /events`.
    #[test]
    fn test_event_json_tags_match_spec() {
        let cases: Vec<(Event, &str)> = vec![
            (Event::ContainerCreate { id: "x".into() }, "container.create"),
            (Event::ContainerStart { id: "x".into() }, "container.start"),
            (Event::ContainerDie { id: "x".into(), exit_code: Some(0) }, "container.die"),
            (Event::ContainerOom { id: "x".into() }, "container.oom"),
            (Event::ContainerPause { id: "x".into() }, "container.pause"),
            (Event::ContainerUnpause { id: "x".into() }, "container.unpause"),
            (Event::ContainerDestroy { id: "x".into() }, "container.destroy"),
            (Event::ImagePullProgress { reference: "x".into(), detail: "y".into() }, "image.pull.progress"),
            (Event::ImagePullDone { reference: "x".into() }, "image.pull.done"),
            (Event::NetAttach { id: "x".into() }, "net.attach"),
            (Event::NetDetach { id: "x".into() }, "net.detach"),
            (Event::CopyUp { id: "x".into(), path: "p".into(), size_bytes: 1 }, "copyup"),
            (Event::SeccompViolation { id: "x".into(), syscall: "s".into() }, "seccomp.violation"),
            (Event::PsiThreshold { id: "x".into(), resource: "cpu".into() }, "psi.threshold"),
            (Event::CgroupThrottle { id: "x".into() }, "cgroup.throttle"),
        ];
        for (event, expected_type) in cases {
            let json: serde_json::Value = serde_json::to_value(&event).expect("serialize Event");
            assert_eq!(json["type"], expected_type, "unexpected wire tag for {event:?}");
        }
    }

    /// Real proof of the `Lagged` handling `get_events`'s own doc comment
    /// promises: a subscriber that falls behind by more than
    /// `EVENT_BUS_CAPACITY` events must keep receiving events afterward
    /// (via `event_stream`'s internal retry-on-`Lagged` loop), not have
    /// its stream silently end.
    #[tokio::test]
    async fn test_event_stream_survives_lagged_receiver() {
        let (tx, rx) = broadcast::channel::<Event>(4);
        // Publish far more than the channel's capacity BEFORE the stream
        // ever polls — guarantees a real `Lagged` on the first `recv()`.
        for i in 0..20 {
            let _ = tx.send(Event::ContainerCreate { id: format!("c{i}") });
        }
        let mut stream = std::pin::pin!(event_stream(rx));
        use futures_util::StreamExt;
        // The stream must survive the internal `Lagged` and still yield a
        // real `Ok(..)` item — not end (`None`) and not propagate the
        // `Lagged` error out through the `Infallible` item type (it
        // couldn't even compile if it tried).
        let first = stream.next().await;
        assert!(
            matches!(first, Some(Ok(_))),
            "stream must survive a Lagged receiver and still yield a later Ok event, got {first:?}"
        );

        // The bus (and stream) must still be genuinely alive afterward —
        // a freshly published event is still delivered.
        let _ = tx.send(Event::ContainerCreate { id: "after-lag".to_string() });
        let second = stream.next().await;
        assert!(
            matches!(second, Some(Ok(_))),
            "stream produced no further events after recovering from Lagged, got {second:?}"
        );
    }

    // -------------------------------------------------------------------
    // Root-gated integration test: `GET /events` end to end, driving a
    // real create+start+stop cycle through the real HTTP router and
    // asserting the exact expected event sequence arrives, in order, with
    // no duplicates — the property this task's whole `StatusTransition`-
    // vs-handler-direct split (this module's own top-level doc comment)
    // exists to make possible.
    //
    // Reuses the exact real-artifact conventions `metrics.rs`'s own
    // integration tests established (real, statically-linked
    // `kestrel-init` + `lifecycle_fixture`) — duplicated rather than
    // imported, matching this crate's established "test infra lives in
    // each test module that needs it" precedent (see `metrics.rs`'s own
    // `build_lifecycle_synthetic_rootfs` doc comment for the full
    // reasoning).
    //
    // Prerequisites (build once before running):
    // ```text
    // make build-kestrel-init-static build-lifecycle-fixture-static
    // cargo build -p kestrel-shim -p kestrel-runtime --bins
    // ```

    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use crate::registry::Registry;
    use crate::{build_router, metrics, resolve_sibling_binary};

    struct MountGuard(PathBuf);
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount").arg(&self.0).status();
        }
    }

    /// Kills (SIGKILL) and reaps a container's real `kestrel-init` pid on
    /// drop — a panic in any assertion must not leak the process.
    struct ProcessGuard(nix::unistd::Pid);
    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.0, None);
        }
    }

    /// Same reasoning as `metrics.rs`'s own `real_data_dir`: the REAL
    /// `kestrel-init` hardcodes `/var/lib/kestrel` as its own `data_dir`,
    /// so the host-side `data_dir` these tests pass to `kestrel-runtime
    /// create` must match byte-for-byte.
    fn real_data_dir() -> PathBuf {
        PathBuf::from("/var/lib/kestrel")
    }

    fn target_debug_dir() -> PathBuf {
        let current_exe = std::env::current_exe().expect("current_exe");
        current_exe
            .parent()
            .expect("current_exe has a parent dir (deps/)")
            .parent()
            .expect("deps/ dir has a parent dir (target/debug/)")
            .to_path_buf()
    }

    fn resolve_test_binary(name: &str) -> PathBuf {
        resolve_sibling_binary(name).unwrap_or_else(|e| {
            panic!(
                "{e}\nRun `cargo build -p kestrel-shim -p kestrel-runtime -p kestrel-init \
                 -p kestrel-net --bins` (or `cargo build --workspace`) first."
            )
        })
    }

    fn install_real_kestrel_init_at_target_debug() {
        let real = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aarch64-unknown-linux-gnu/debug/kestrel-init");
        assert!(
            real.exists(),
            "real statically-linked kestrel-init not found at {} — run `make \
             build-kestrel-init-static` first.",
            real.display()
        );
        let target_debug_dir = target_debug_dir();
        let target = target_debug_dir.join("kestrel-init");
        let tmp = target_debug_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
        std::fs::copy(&real, &tmp).expect("copy real kestrel-init to tmp");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::rename(&tmp, &target).expect("rename tmp into place as target/debug/kestrel-init");
    }

    fn static_lifecycle_fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture")
    }

    fn build_lifecycle_synthetic_rootfs(dest: &Path) {
        std::fs::create_dir_all(dest).expect("mkdir synthetic rootfs dir");
        let fixture_path = static_lifecycle_fixture_path();
        assert!(
            fixture_path.exists(),
            "static lifecycle_fixture artifact not found at {} — run `make \
             build-lifecycle-fixture-static` first.",
            fixture_path.display()
        );
        std::fs::copy(&fixture_path, dest.join("fixture")).unwrap_or_else(|e| {
            panic!("copy {} to {}: {e}", fixture_path.display(), dest.join("fixture").display())
        });
        std::fs::set_permissions(dest.join("fixture"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod fixture binary");
    }

    fn mount_cgroups(data_dir: &Path) -> MountGuard {
        let cgroups_mount = data_dir.join("cgroups");
        std::fs::create_dir_all(&cgroups_mount).expect("mkdir cgroups mountpoint");
        let mount_status = std::process::Command::new("mount")
            .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
            .status()
            .expect("spawning mount(8)");
        assert!(
            mount_status.success(),
            "mounting a second cgroup2 view at {} failed — this test must run as root",
            cgroups_mount.display()
        );
        MountGuard(cgroups_mount)
    }

    async fn poll_until<T, F: FnMut() -> Option<T>>(timeout: Duration, mut probe: F) -> Option<T> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(v) = probe() {
                return Some(v);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn unpin_default_namespaces(run_dir: &Path, id: &str) {
        let ns_dir = run_dir.join(id).join("ns");
        for ns in [
            kestrel_ns::types::NsType::Pid,
            kestrel_ns::types::NsType::Net,
            kestrel_ns::types::NsType::Ipc,
            kestrel_ns::types::NsType::Uts,
            kestrel_ns::types::NsType::Cgroup,
            kestrel_ns::types::NsType::Mount,
        ] {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
        }
    }

    fn cleanup_real_container_artifacts(id: &str) {
        let data_dir = real_data_dir();
        let layer_store = kestrel_rootfs::snapshot::LayerStore::new(data_dir.clone());
        let _ = std::fs::remove_dir_all(layer_store.layer_dir(&format!("bundle-{id}")));
        let _ = std::fs::remove_dir_all(data_dir.join("bundles").join(id));
        let _ = std::fs::remove_dir_all(data_dir.join("snapshots").join(id));
        let _ = std::fs::remove_dir_all(data_dir.join("containers").join(id));
    }

    async fn call_router_json(
        app: axum::Router,
        method: &str,
        uri: String,
        body: serde_json::Value,
    ) -> (StatusCode, Vec<u8>) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
        (status, bytes.to_vec())
    }

    async fn call_router_empty(app: axum::Router, method: &str, uri: String) -> (StatusCode, Vec<u8>) {
        let request = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
        (status, bytes.to_vec())
    }

    /// Reads SSE `data: <json>` events from `body`, filtering to those
    /// whose `"id"` matches `container_id`, until `stop_pred` returns
    /// `true` for a just-parsed event (or `timeout` elapses). Axum's own
    /// `Event::data()` formatting (confirmed empirically, and consistent
    /// with `api::logs`'s own SSE follow tests relying on the same shape)
    /// emits single-line JSON as exactly one `data: <json>\n\n` block per
    /// event, so splitting the accumulated text on blank lines is a safe,
    /// exact framing here — non-`data:` lines (e.g. axum's own periodic
    /// `KeepAlive` comment lines) are silently skipped, not treated as
    /// malformed.
    async fn collect_matching_events(
        body: &mut Body,
        container_id: &str,
        timeout: Duration,
        stop_pred: impl Fn(&serde_json::Value) -> bool,
    ) -> Vec<serde_json::Value> {
        let mut collected = Vec::new();
        let mut acc = String::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!("timed out waiting for expected SSE event sequence; collected so far: {collected:?}");
            }
            let frame = tokio::time::timeout(remaining, body.frame())
                .await
                .unwrap_or_else(|_| {
                    panic!("timed out waiting for next SSE frame; collected so far: {collected:?}")
                })
                .expect("SSE body stream ended unexpectedly")
                .expect("reading SSE frame");
            if let Some(data) = frame.data_ref() {
                acc.push_str(&String::from_utf8_lossy(data));
            }
            while let Some(idx) = acc.find("\n\n") {
                let chunk: String = acc.drain(..idx + 2).collect();
                for line in chunk.lines() {
                    let Some(json_str) = line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:"))
                    else {
                        continue; // keep-alive/comment lines, blank lines, etc.
                    };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str.trim()) else {
                        continue;
                    };
                    if v.get("id").and_then(|x| x.as_str()) != Some(container_id) {
                        continue; // a different, concurrently-run test's own container
                    }
                    let is_stop = stop_pred(&v);
                    collected.push(v);
                    if is_stop {
                        return collected;
                    }
                }
            }
        }
    }

    /// Real, end-to-end proof of this whole task: a client subscribed to
    /// `GET /events` BEFORE a create+start+stop cycle sees exactly
    /// `container.create` -> `container.start` -> `container.die`, in
    /// that order, for the SAME container id, with no duplicates.
    /// `container.die` genuinely comes from Task 13's status-transition
    /// sampler via `spawn_consumer` (there is no direct "the container
    /// died" call anywhere in `api::containers` — see this module's own
    /// doc comment for why); `container.create`/`container.start` come
    /// directly from their own handlers. Seeing exactly three events, in
    /// this order, with no duplicates, is the real proof that these two
    /// publish paths (direct handler calls, and the translated signal
    /// channel) don't double-fire for the same real-world occurrence.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_events_sse_sees_create_start_die_in_order_with_no_duplicates() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        // Fast tick so the sampler observes the Running -> Stopped
        // transition (and this test's own `container.die` assertion)
        // well within its own timeout budget.
        let last_status_map = crate::metrics::new_last_status_map();
        let metrics_rx = metrics::spawn(
            registry.clone(),
            run_dir.path().to_path_buf(),
            data_dir.join("cgroups"),
            Duration::from_millis(100),
            150_000,
            1_000_000,
            last_status_map.clone(),
        );
        let state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: tokio::sync::Mutex::new(metrics_rx),
            event_bus: new_bus(),
            last_status_map,
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: crate::api::introspect::SeccompLog::new(),
        });
        spawn_consumer(state.clone());
        let app = build_router(state.clone());

        // ---- subscribe BEFORE triggering anything, so the very first
        // event published for this (not-yet-created) container is
        // genuinely captured, not raced. ----
        let events_request = Request::builder().method("GET").uri("/events").body(Body::empty()).unwrap();
        let events_response = app.clone().oneshot(events_request).await.expect("GET /events oneshot");
        assert_eq!(events_response.status(), StatusCode::OK);
        let mut events_body = events_response.into_body();

        // ---- create ----
        let create_body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "sleep", "30"],
        });
        let (create_status, create_resp) =
            call_router_json(app.clone(), "POST", "/containers".to_string(), create_body).await;
        assert_eq!(
            create_status,
            StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_resp)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_resp).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        // ---- start ----
        let (start_status, start_resp) =
            call_router_empty(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(start_status, StatusCode::OK, "start failed: {}", String::from_utf8_lossy(&start_resp));

        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // Same "wait for the real entrypoint pid, not kestrel-init's own"
        // precedent every other real-container test in this crate follows
        // before signaling it (`main.rs`'s own Task 9 tests).
        poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path).ok().filter(|s| s.pid != created.pid)
        })
        .await
        .expect("state.json's pid was never updated to the entrypoint's real pid");

        // A real, load-bearing settle wait — NOT cosmetic: without it this
        // test is racy. `metrics::spawn` (above) was started before this
        // container existed at all, matching production's own boot-time
        // ordering, but `MetricsSignal::StatusTransition`'s own contract
        // (`metrics.rs`'s own doc comment) never fires on the sampler's
        // FIRST-EVER observation of a given id — that tick just records a
        // baseline. If this whole create->start->stop sequence finished
        // faster than one 100ms tick interval, the sampler's very first
        // observation of this id could land AFTER it's already `Stopped`,
        // silently swallowing the entire lifecycle with no signal ever
        // firing. `metrics.rs`'s own root-gated tests hit this exact race
        // and fix it the same way (see e.g. `test_status_transition_fires_
        // on_externally_killed_container`'s own "Let the sampler observe
        // the Running baseline at least once before..." comment): wait
        // comfortably longer than one tick interval so the sampler has
        // already recorded a genuine `Running` baseline for this id before
        // triggering the transition this test actually asserts on.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // ---- stop: no SIGTERM handler in the fixture, so this dies well
        // within the grace period without needing SIGKILL. ----
        let (stop_status, stop_resp) =
            call_router_empty(app.clone(), "POST", format!("/containers/{id}/stop")).await;
        assert_eq!(stop_status, StatusCode::OK, "stop failed: {}", String::from_utf8_lossy(&stop_resp));

        // ---- the real assertion: exactly create -> start -> die, in
        // order, no duplicates, all for this same container id. ----
        let collected = collect_matching_events(&mut events_body, &id, Duration::from_secs(15), |v| {
            v["type"] == "container.die"
        })
        .await;
        let types: Vec<String> = collected.iter().map(|v| v["type"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            types,
            vec!["container.create", "container.start", "container.die"],
            "unexpected event sequence: {collected:?}"
        );
        let die_event = collected.last().unwrap();
        assert_eq!(
            die_event["exit_code"], 143,
            "expected exit_code 143 (128 + SIGTERM) from a plain signal death, got {die_event:?}"
        );

        // ---- cleanup ----
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }

    fn write_state(run_dir: &Path, id: &str, status: kestrel_oci::state::Status, exit_code: Option<i32>) {
        let dir = run_dir.join(id);
        std::fs::create_dir_all(&dir).expect("mkdir container run dir");
        let state = kestrel_oci::state::State {
            oci_version: "1.0.2".to_string(),
            id: id.to_string(),
            status,
            pid: None,
            bundle: dir.clone(),
            annotations: Default::default(),
            exit_code,
        };
        state.write_atomic(&dir.join("state.json")).expect("write state.json");
    }
}
