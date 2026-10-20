use crate::config::Config;
use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use base64::Engine;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::broadcast::Sender;
use tokio::sync::{Mutex, broadcast, oneshot};
use transmission::{AgentResponse, PendingRequest, StoredRequest, create_shared_secret};
use uuid::Uuid;

pub mod config;

const CONFIG: LazyLock<Config> = LazyLock::new(|| {
    Config::parse()
        .map_err(|_| "Failed to parse config")
        .unwrap()
});

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

pub async fn handle_proxy_request(
    State(state): State<AppState>,
    Path(path): Path<(String, Option<String>)>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Some(size) = body.size_hint().exact()
        && size > 10 * 1024 * 1024
    {
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Body::empty())
            .unwrap();
    }

    let (response_tx, response_rx) = oneshot::channel();

    let uuid = Uuid::new_v4().to_string();

    let stored_request = StoredRequest {
        uuid: uuid.clone(),
        destination: path.0.clone(),
        method: parts.method.to_string(),
        uri: match path.1 {
            Some(uri) => format!("/{}", uri.to_string()),
            None => "".to_string(),
        },
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect(),
        body: base64::engine::general_purpose::STANDARD
            .encode(to_bytes(body, 10 * 1024 * 1024).await.unwrap().to_vec()),
    };

    let hmac = if let Some(agent_config) = &CONFIG.agent(&path.0) {
        stored_request.hmac(&agent_config.shared_secret)
    } else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header(
                HeaderName::from_str("X-Via").unwrap(),
                HeaderValue::from_str("transmission").unwrap(),
            )
            .body(Body::empty())
            .unwrap();
    };

    state.pending.lock().await.insert(
        uuid.clone(),
        PendingRequest {
            request: stored_request,
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
        _ = a => {
            state.pending.lock().await.remove(&uuid.clone());
            Response::builder()
            .status(StatusCode::GATEWAY_TIMEOUT)
            .header(HeaderName::from_str("X-Via").unwrap(), HeaderValue::from_str("transmission").unwrap())
            .body(Body::empty())
            .unwrap()
        },
        br = b => {
            if let Ok(response) = br {
                state.pending.lock().await.remove(&uuid.clone());
                let mut headers = HeaderMap::new();
                for (name, value) in response.clone().headers {
                    headers.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_bytes(value.as_bytes()).unwrap());
                }
                headers.insert(HeaderName::from_str("X-Via").unwrap(), HeaderValue::from_str("transmission").unwrap());
                (
                    StatusCode::from_u16(response.status).unwrap(),
                    headers,
                    response.body
                ).into_response()
            } else {
                state.pending.lock().await.remove(&uuid.clone());
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(HeaderName::from_str("X-Via").unwrap(), HeaderValue::from_str("transmission").unwrap())
                    .body(Body::empty())
                    .unwrap()
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
                } else {
                    continue;
                },
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
}

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
        let shared_secret =
            create_shared_secret(&CONFIG.secret(), &agent_config.public_key, &hmac).unwrap();

        return (
            StatusCode::OK,
            pending_request.request.encrypt_with(shared_secret),
        )
            .into_response();
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

pub async fn handle_response(
    State(state): State<AppState>,
    Path(path): Path<(String, String)>,
    request: Request,
) -> Response {
    let requests = state.clone();
    let mut pending_requests = requests.pending.lock().await;
    if let Some(pending_request) = pending_requests.get_mut(&path.1)
        && pending_request.request.destination == path.0
    {
        if let Some(response_tx) = pending_request.response_tx.take()
            && let Some(agent_config) = &CONFIG.agent(&pending_request.request.destination)
        {
            let (_, body) = request.into_parts();
            let hmac = pending_request.request.hmac(&agent_config.shared_secret);
            let shared_secret =
                create_shared_secret(&CONFIG.secret(), &agent_config.public_key, &hmac).unwrap();
            let agent_response = AgentResponse::decrypt_with(
                &String::from_utf8_lossy(to_bytes(body, 10 * 1024 * 1024).await.unwrap().as_ref()),
                shared_secret,
            )
            .unwrap();
            let _ = response_tx.send(agent_response);
            return (StatusCode::OK, Json(pending_request.request.clone())).into_response();
        }
    }

    (StatusCode::NOT_FOUND, Json("Not found")).into_response()
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let (tx, _) = broadcast::channel(10);

    let state = AppState {
        pending: Arc::new(Mutex::new(HashMap::new())),
        tx,
    };

    let routes = Router::new()
        .route("/events/{destination}", get(handle_sse))
        .route("/proxy/{destination}", any(handle_proxy_request_root))
        .route("/proxy/{destination}/{*path}", any(handle_proxy_request))
        .route("/pending/{destination}/{uuid}", get(handle_pending))
        .route("/pending/{destination}/{uuid}", post(handle_response))
        .with_state(state);

    match TcpListener::bind(&CONFIG.listen()).await {
        Ok(listener) => {
            log::info!("Starting application listening on '{}'", &CONFIG.listen());
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
                &CONFIG.listen(),
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
