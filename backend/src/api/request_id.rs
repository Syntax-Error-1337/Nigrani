use axum::body::Body;
use axum::extract::Request;
use axum::http::header::HeaderName;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Stamps every response with `x-request-id` (honoring a client-sent one)
/// and injects the same id into JSON error bodies (`{"error", "request_id"}`)
/// so client reports map 1:1 to server logs.
pub async fn request_id(request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut response = next.run(request).await;
    let status = response.status();
    response.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        id.parse().expect("uuid or client id is header-safe"),
    );
    if status.is_client_error() || status.is_server_error() {
        let (mut parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024)
            .await
            .unwrap_or_default();
        let patched = match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(mut json) => {
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("request_id".into(), id.clone().into());
                }
                json.to_string()
            }
            Err(_) => bytes.escape_ascii().to_string(),
        };
        *parts.headers.get_mut(REQUEST_ID_HEADER).expect("just inserted") =
            id.parse().expect("uuid is header-safe");
        response = (parts, Body::from(patched)).into_response();
    }
    response
}
