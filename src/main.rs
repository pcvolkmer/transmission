use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::sse::Event;
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast::Sender;
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRequest {
    pub destination: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PendingRequest {
    pub request: StoredRequest,
    pub response_tx: Arc<oneshot::Sender<String>>,
}

#[derive(Clone)]
pub struct AppState {
    pub pending: Arc<Mutex<HashMap<String, PendingRequest>>>,
    pub tx: Sender<EventSignal>,
}

#[derive(Clone)]
pub struct EventSignal {
    pub destination: String,
    pub uuid: String,
}

pub async fn handle_proxy_request(
    State(state): State<AppState>,
    path: Path<(String, String)>,
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

    let uuid = Uuid::new_v4().to_string();

    let (response_tx, response_rx) = oneshot::channel();

    state.pending.lock().await.insert(
        uuid.clone(),
        PendingRequest {
            request: StoredRequest {
                destination: path.0.0.clone(),
                method: parts.method.to_string(),
                uri: path.1.to_string(),
                headers: parts
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        Some((name.to_string(), value.to_str().ok()?.to_owned()))
                    })
                    .collect(),
                body: to_bytes(body, 10 * 1024 * 1024).await.unwrap().to_vec(),
            },
            response_tx: Arc::new(response_tx),
        },
    );

    let _ = state.tx.send(EventSignal {
        destination: path.0.0,
        uuid: uuid.clone(),
    });

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Body::empty())
        .unwrap()
}

pub async fn handle_sse(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let mut rx = state.tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            println!("{}", state.pending.lock().await.len());
            match rx.recv().await {
                Ok(message) => yield Ok(Event::default().id(message.uuid).event(message.destination)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
}

pub async fn handle_pending(
    State(state): State<AppState>,
    path: Path<(String, String)>,
) -> Response {
    let x = state.pending.lock().await.clone();
    if let Some((pending_uuid, pending_request)) =
        x.into_iter().find(|(uuid, request)| {
            println!("{} - {} <> {} - {}", uuid, request.request.destination, path.0.0, path.0.1);
            uuid.eq(path.0.1.as_str()) && request.request.destination == path.0.0
        })
    {
        return (StatusCode::OK, Json(pending_request.request)).into_response();
    };

    (StatusCode::NOT_FOUND, Json("Not found")).into_response()
}

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("Hello, world!");

    let (tx, mut rx) = broadcast::channel(10);

    let state = AppState {
        pending: Arc::new(Mutex::new(HashMap::new())),
        tx,
    };

    let routes = Router::new()
        .route("/events", get(handle_sse))
        .route("/proxy/{destination}/{*path}", any(handle_proxy_request))
        .route("/pending/{destination}/{uuid}", get(handle_pending))
        .with_state(state);

    match TcpListener::bind("[::]:3000").await {
        Ok(listener) => {
            log::info!("Starting application listening on '{}'", "[::]:3000");
            if let Err(err) = axum::serve(listener, routes)
                .with_graceful_shutdown(shutdown_signal())
                .await
            {
                return Err(err.to_string());
            }
        }
        Err(err) => return Err(format!("Cannot listening on '{}': {}", "[::]:3000", err)),
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
