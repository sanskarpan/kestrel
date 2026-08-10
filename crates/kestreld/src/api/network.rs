// crates/kestreld/src/api/network.rs
//
//! `GET /containers/:id/network` and `GET /system/topology` (Task 17
//! Steps 4-5): both are pure reads of `kestreld`'s own persisted
//! bookkeeping (`registry::ContainerMeta.network` — see `crate::network`'s
//! own module doc comment on why `kestreld` bookkeeps this itself rather
//! than re-deriving it from kernel state), never touching the kernel or
//! `kestrel-net` at all.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::extract::{Path as PathParam, State};
use axum::Json;
use serde::Serialize;

use crate::api::containers::get_registered;
use crate::api::AppError;
use crate::network::NetworkInfo;
use crate::AppState;

/// `GET /containers/:id/network` — returns the persisted `NetworkInfo`
/// directly from `meta.json` (via the registry, which reads/recovers
/// `meta.json` itself — see `registry::read_meta`/`main::recover_registry`),
/// NOT a separate file (Step 1's design keeps ONE metadata file per
/// container). `null` for a container with no bridge-mode networking
/// attached (every `network_mode` other than `"bridge"`, or a bridge-mode
/// container whose attach step hasn't completed — see `ContainerMeta.
/// network`'s own doc comment for that narrow window).
pub async fn get_container_network(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<Option<NetworkInfo>>, AppError> {
    let handle = get_registered(&state, &id).await?;
    Ok(Json(handle.meta.network))
}

#[derive(Debug, Serialize)]
pub struct TopologyContainer {
    pub id: String,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Serialize)]
pub struct TopologyBridge {
    pub name: String,
    pub subnet: String,
    pub containers: Vec<TopologyContainer>,
}

#[derive(Debug, Serialize)]
pub struct TopologyResponse {
    pub bridges: Vec<TopologyBridge>,
}

/// `GET /system/topology` — aggregates every registry entry's persisted
/// `NetworkInfo` by bridge name: `{"bridges": [{"name", "subnet",
/// "containers": [{"id","ip"}]}]}`, per Task 17 Step 5's own literal
/// shape. `subnet` comes from the daemon's OWN configured
/// `network.subnet` (`AppState.network`) rather than anything carried on
/// `NetworkInfo` itself (which doesn't record it) — every bridge-mode
/// container in this phase's scope shares the one configured bridge/
/// subnet (`kestrel-net`'s own single-shared-bridge design), so this is
/// exact, not an approximation. A registry entry with no bridge-mode
/// `NetworkInfo` (host/none/container:<id> modes, or a bridge-mode
/// container mid-attach) contributes nothing to any bridge's `containers`
/// list.
pub async fn get_topology(State(state): State<Arc<AppState>>) -> Json<TopologyResponse> {
    let handles: Vec<_> = state.registry.read().await.values().cloned().collect();

    let mut by_bridge: HashMap<String, Vec<TopologyContainer>> = HashMap::new();
    for handle in handles {
        let Some(network) = handle.meta.network else { continue };
        let (Some(bridge_name), Some(ip)) = (network.bridge_name, network.ip) else { continue };
        by_bridge
            .entry(bridge_name)
            .or_default()
            .push(TopologyContainer { id: handle.id, ip });
    }

    let bridges = by_bridge
        .into_iter()
        .map(|(name, containers)| TopologyBridge { name, subnet: state.network.subnet.clone(), containers })
        .collect();

    Json(TopologyResponse { bridges })
}
