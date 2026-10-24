//! Realtime fan-out: a process-local broadcast hub plus the `/events`
//! WebSocket endpoint. Single-instance (documented); a multi-replica
//! deployment bridges this through RabbitMQ — recorded, out of scope.
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Extension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::Role;
use crate::infrastructure::auth::verify_access_token;

/// Event kinds published on the hub. Payloads carry operational facts only —
/// never document numbers, embeddings, or secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HubEvent {
    /// A gate crossing was recorded.
    Crossing {
        at: chrono::DateTime<chrono::Utc>,
        site_id: Uuid,
        gate_id: Uuid,
        direction: String,
        method: String,
    },
    /// A KYC application was decided.
    KycDecided {
        at: chrono::DateTime<chrono::Utc>,
        application_id: Uuid,
        decision: String,
    },
    /// An incident case mutated (created, workflow status, assignment, evidence link).
    Incident {
        at: chrono::DateTime<chrono::Utc>,
        site_id: Uuid,
        incident_id: Uuid,
        action: String,
    },
    /// Topology changed (site or gate created).
    Topology {
        at: chrono::DateTime<chrono::Utc>,
    },
    /// Hourly entries at a gate crossed the site's surge threshold.
    Surge {
        at: chrono::DateTime<chrono::Utc>,
        site_id: Uuid,
        gate_id: Uuid,
        count: i64,
        threshold: i64,
    },
}

#[derive(Clone)]
pub struct EventHub {
    tx: tokio::sync::broadcast::Sender<String>,
}

impl EventHub {
    pub fn new() -> Self {
        // 256-deep buffer: slow consumers drop messages (lagged error) and
        // resync via normal REST reads; the stream is a hint, not the source.
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self { tx }
    }

    pub fn publish(&self, event: &HubEvent) {
        match serde_json::to_string(event) {
            Ok(text) => {
                let _ = self.tx.send(text);
            }
            Err(e) => tracing::error!(error = %e, "event serialize failed"),
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    /// JWT access token (query param because WS clients set headers poorly).
    pub token: String,
}

/// Upgrade to the event stream after verifying the query-string token with
/// the same path as bearer auth.
pub async fn events_ws(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
    ws: axum::extract::WebSocketUpgrade,
    Extension(hub): Extension<EventHub>,
) -> AppResult<impl IntoResponse> {
    let claims = verify_access_token(&state.jwt_secret, &query.token)?;
    // Same allowlist rule as bearer routes: a revoked/killed token cannot
    // open (or keep) a side channel past its TTL.
    let alive: Option<bool> =
        sqlx::query_scalar("SELECT revoked_at IS NULL AND expires_at > now() FROM access_tokens WHERE jti = $1")
            .bind(claims.jti)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
    if alive != Some(true) {
        return Err(AppError::Unauthorized("token revoked".to_owned()));
    }
    let role = Role::from_name(&claims.role)
        .ok_or_else(|| AppError::Unauthorized("unknown role".to_owned()))?;
    tracing::info!(user = %claims.username, role = %role, "event stream subscribed");
    Ok(ws.on_upgrade(move |socket| drive(socket, hub)))
}

async fn drive(socket: axum::extract::ws::WebSocket, hub: EventHub) {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};
    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut rx = hub.subscribe();
    // Forward hub messages until either side closes; ping/pong handled by axum.
    let forward = async move {
        loop {
            match rx.recv().await {
                Ok(text) => {
                    if ws_tx.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "event consumer lagged; resync via REST");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    tokio::pin!(forward);
    // Drain inbound frames (close frames matter); ignore payloads.
    let drain = async move {
        while let Some(msg) = ws_rx.next().await {
            if msg.is_err() {
                break;
            }
        }
    };
    tokio::pin!(drain);
    tokio::select! {
        _ = &mut forward => {},
        _ = &mut drain => {},
    }
}
