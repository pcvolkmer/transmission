use crate::config::Config;
use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::header::HOST;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::broadcast::Sender;
use tokio::sync::{Mutex, broadcast, oneshot};
use transmission::{AgentResponse, PendingRequest, StoredRequest, create_shared_secret};
use uuid::Uuid;

pub mod config;

#[allow(clippy::expect_used)]
const CONFIG: LazyLock<Config> = LazyLock::new(|| Config::parse().expect("Failed to parse config"));

#[derive(Clone)]
pub struct AppState {
    pub pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    pub tx: Sender<EventSignal>,
}

#[derive(Clone)]
pub struct EventSignal {
    pub destination: String,
    pub uuid: String,
    pub hmac: String,
}

pub async fn handle_proxy_request_root(
    state: State<AppState>,
    Path(path): Path<String>,
    request: Request,
) -> Response {
    let path = Path((path, None));
    handle_proxy_request(state, path, request).await
}

#[allow(clippy::expect_used)]
pub async fn handle_proxy_request(
    State(state): State<AppState>,
    Path(path): Path<(String, Option<String>)>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Some(size) = body.size_hint().exact()
        && size > 10 * 1024 * 1024
    {
        return (StatusCode::PAYLOAD_TOO_LARGE, "").into_response();
    }

    let (response_tx, response_rx) = oneshot::channel();

    let uuid = Uuid::new_v4().to_string();

    let mut headers = parts.headers;
    headers.remove(HOST);
    headers.insert(
        HOST,
        HeaderValue::from_str("test").expect("Invalid host header"),
    );

    let Ok(stored_request) = StoredRequest::new(
        &uuid.clone(),
        &path.0.clone(),
        parts.method,
        path.1,
        headers,
        body,
    )
    .await
    else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "").into_response();
    };

    let hmac = if let Some(agent_config) = &CONFIG.agent(&path.0) {
        stored_request.hmac(&agent_config.shared_secret)
    } else {
        log::error!(
            "ID {} - skipping {} request for unknown agent '{}'",
            uuid,
            stored_request.method.to_ascii_uppercase(),
            stored_request.destination,
        );

        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header(
                HeaderName::from_str("X-Via").expect("X-Via name"),
                HeaderValue::from_str("transmission").expect("X-Via value"),
            )
            .body(Body::empty())
            .expect("Unable to build response");
    };

    log::info!(
        "ID {} - {} request for agent '{}' '{}'",
        uuid,
        stored_request.method.to_ascii_uppercase(),
        stored_request.destination,
        stored_request.uri
    );

    state.pending.lock().await.insert(
        uuid.clone(),
        PendingRequest {
            request: stored_request,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            response_tx: Some(response_tx),
        },
    );

    let _ = state.tx.send(EventSignal {
        destination: path.0,
        uuid: uuid.clone(),
        hmac: hmac.clone(),
    });

    let a = tokio::time::sleep(Duration::from_mins(1));
    let b = response_rx;

    let result = select! {
        () = a => {
            state.pending.lock().await.remove(&uuid.clone());
            log::warn!(
                "ID {uuid} - Timed out"
            );
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .header(HeaderName::from_str("X-Via").expect("X-Via header name"), HeaderValue::from_str("transmission").expect("X-Via header value"))
                .body(Body::empty())
                .expect("Unable to build response")
        },
        br = b => {
            if let Ok(response) = br {
                state.pending.lock().await.remove(&uuid.clone());
                let mut headers = HeaderMap::new();
                for (name, value) in response.clone().headers {
                    headers.insert(HeaderName::from_bytes(name.as_bytes()).expect("X-Via header name"), HeaderValue::from_bytes(value.as_bytes()).expect("X-Via header value"));
                }
                headers.insert(HeaderName::from_str("X-Via").expect("X-Via header name"), HeaderValue::from_str("transmission").expect("X-Via header value"));
                log::info!(
                    "ID {uuid} - Response returned"
                );
                (
                    StatusCode::from_u16(response.status).expect("Status code set"),
                    headers,
                    response.body
                ).into_response()
            } else {
                state.pending.lock().await.remove(&uuid.clone());
                log::warn!(
                    "ID {uuid} - Bad gateway"
                );
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(HeaderName::from_str("X-Via").expect("X-Via header name"), HeaderValue::from_str("transmission").expect("X-Via header value"))
                .body(Body::empty())
                .expect("Unable to build response")
            }
        },
    };

    state.pending.lock().await.remove(&uuid.clone());

    result
}

pub async fn handle_sse(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let mut rx = state.tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(message) => if message.destination == path {
                    yield Ok(Event::default().id(message.uuid).event(message.destination).data(message.hmac));
                },
                Err(broadcast::error::RecvError::Lagged(_)) => {},
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
}

#[allow(clippy::expect_used)]
pub async fn handle_pending(
    State(state): State<AppState>,
    Path(path): Path<(String, String)>,
) -> Response {
    let requests = state.clone();
    let mut pending_requests = requests.pending.lock().await;
    if let Some(pending_request) = pending_requests.get_mut(&path.1)
        && pending_request.request.destination == path.0
        && let Some(agent_config) = &CONFIG.agent(&pending_request.request.destination)
    {
        let hmac = pending_request.request.hmac(&agent_config.shared_secret);
        let Ok(shared_secret) =
            create_shared_secret(&CONFIG.secret(), &agent_config.public_key, &hmac)
        else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Crypt error").into_response();
        };

        return (
            StatusCode::OK,
            pending_request.request.encrypt_with(shared_secret),
        )
            .into_response();
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

#[allow(clippy::expect_used)]
pub async fn handle_response(
    State(state): State<AppState>,
    Path(path): Path<(String, String)>,
    request: Request,
) -> Response {
    let requests = state.clone();
    let mut pending_requests = requests.pending.lock().await;
    if let Some(pending_request) = pending_requests.get_mut(&path.1)
        && pending_request.request.destination == path.0
        && let Some(response_tx) = pending_request.response_tx.take()
        && let Some(agent_config) = &CONFIG.agent(&pending_request.request.destination)
    {
        let (_, body) = request.into_parts();
        let hmac = pending_request.request.hmac(&agent_config.shared_secret);
        let Ok(shared_secret) =
            create_shared_secret(&CONFIG.secret(), &agent_config.public_key, &hmac)
        else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Crypt error").into_response();
        };
        let Ok(response_bytes) = to_bytes(body, usize::MAX).await else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Decode error").into_response();
        };
        let Ok(agent_response) = AgentResponse::decrypt_with(
            &String::from_utf8_lossy(response_bytes.as_ref()),
            shared_secret,
        ) else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Crypt error").into_response();
        };
        let _ = response_tx.send(agent_response);
        return (StatusCode::OK, Json(pending_request.request.clone())).into_response();
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

#[tokio::main]
async fn main() -> Result<(), String> {
    #[cfg(debug_assertions)]
    {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    #[cfg(not(debug_assertions))]
    {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    let (tx, _) = broadcast::channel(10);

    let state = AppState {
        pending: Arc::new(Mutex::new(HashMap::new())),
        tx,
    };

    let pending = state.pending.clone();
    tokio::spawn(async move {
        #[allow(clippy::expect_used)]
        loop {
            tokio::time::sleep(Duration::from_mins(1)).await;
            let dangling_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .checked_sub(Duration::from_mins(1))
                .expect("Cannot find timestamp")
                .as_secs();

            let dangling_requests: Vec<String> = pending
                .lock()
                .await
                .iter()
                .filter_map(|(uuid, pending_request)| {
                    if pending_request.timestamp < dangling_timestamp {
                        Some(uuid.into())
                    } else {
                        None
                    }
                })
                .collect();

            let len = dangling_requests.len();
            if len > 0 {
                for uuid in dangling_requests {
                    pending.lock().await.remove(&uuid);
                    log::warn!("ID {uuid} - removed dangling request");
                }
            }
        }
    });

    let routes = Router::new()
        .route("/_events/{destination}", get(handle_sse))
        .route("/_proxy/{destination}", any(handle_proxy_request_root))
        .route("/_proxy/{destination}/", any(handle_proxy_request_root))
        .route("/_proxy/{destination}/{*path}", any(handle_proxy_request))
        .route("/_pending/{destination}/{uuid}", get(handle_pending))
        .route("/_pending/{destination}/{uuid}", post(handle_response))
        .with_state(state);

    match TcpListener::bind(&CONFIG.listen()).await {
        Ok(listener) => {
            log::info!("Starting application listening on '{}'", CONFIG.listen());
            if let Err(err) = axum::serve(listener, routes)
                .with_graceful_shutdown(shutdown_signal())
                .await
            {
                return Err(err.to_string());
            }
        }
        Err(err) => {
            return Err(format!(
                "Cannot listening on '{}': {}",
                CONFIG.listen(),
                err
            ));
        }
    }

    Ok(())
}

#[allow(clippy::expect_used)]
async fn shutdown_signal() {
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    terminate.await;
}
