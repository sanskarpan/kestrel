use serde::{Deserialize, Serialize};

use crate::runtime::Spec;

/// Wraps `Spec` with a flatten catch-all so fields the installed
/// `oci-spec` version doesn't model yet (future schema additions, vendor
/// extensions) survive a parse-then-reserialize round trip instead of being
/// silently dropped. Use this wherever a `config.json` gets read and later
/// re-written (e.g. `kestreld` normalizing a bundle) — use plain `Spec`
/// wherever the value is only ever read once and never written back out.
///
/// # Warning: never insert a key into `extra` that collides with one of
/// `Spec`'s own field names (e.g. "ociVersion", "root", "process", ...).
/// `#[serde(flatten)]` correctly deduplicates on DESERIALIZE (a key can
/// only be claimed by one flattened field), but NOT on serialize — each
/// flattened field independently emits whatever it holds, so a collision
/// produces a JSON object with a duplicate key. Most parsers (including a
/// subsequent `RawSpec` parse of that same output) will silently pick one
/// value and discard the other on re-read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawSpec {
    #[serde(flatten)]
    pub spec: Spec,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
