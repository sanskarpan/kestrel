// crates/kestreld/src/api/mod.rs
//
//! HTTP API handlers. `containers` is Task 8's `POST /containers` — later
//! tasks add lifecycle (`Task 9`), exec/top (`Task 10`), logs/attach
//! (`Tasks 11-12`), and introspection/image endpoints on top, each as
//! their own submodule here.

pub mod attach;
pub mod containers;
pub mod images;
pub mod introspect;
pub mod logs;
pub mod network;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Uniform JSON error envelope for every endpoint in this module:
/// `{"error": "..."}` plus a real HTTP status code. Plain `anyhow::Error`
/// alone (via a blanket `IntoResponse`) would always map to 500, which is
/// wrong for the several genuinely client-caused failures `bundle.rs`
/// distinguishes (`BundleError::BadRequest`) — an invalid `network_mode`,
/// neither `image` nor `bundle_rootfs` given, or a `container:<id>`
/// reference to an unknown container should all be `400`, not `500`.
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    /// Task 9: every lifecycle/list/inspect endpoint needs a real `404` for
    /// an unknown container id, rather than letting that fall through to
    /// `internal`'s `500` (which `AppError::from(anyhow::Error)` would
    /// otherwise produce once `kestrel-runtime`'s own subprocess fails
    /// against a nonexistent id).
    pub fn not_found(message: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    /// Task 12: `POST /containers/:id/resize` against a non-tty container
    /// (design doc §5's non-tty carve-out — no PTY to `TIOCSWINSZ` on)
    /// needs a real `409` rather than a `500`/`400`: the request is
    /// well-formed and the container genuinely exists, it's just in a
    /// state (non-tty) that makes this specific operation permanently
    /// inapplicable — the textbook case for `409 Conflict` over `400 Bad
    /// Request` (which would imply the request body/shape itself is
    /// malformed, which it isn't) or `422`.
    pub fn conflict(message: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::internal(format!("{err:#}"))
    }
}

impl From<crate::bundle::BundleError> for AppError {
    fn from(err: crate::bundle::BundleError) -> Self {
        match err {
            crate::bundle::BundleError::BadRequest(msg) => AppError::bad_request(msg),
            crate::bundle::BundleError::Internal(e) => AppError::internal(format!("{e:#}")),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}
