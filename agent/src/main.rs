mod config;

use crate::config::Config;
use reqwest::Method;
use reqwest::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use reqwest_sse::{Event, EventSource};
use std::str::FromStr;
use std::sync::LazyLock;
use tokio_stream::StreamExt;
use transmission::{AgentResponse, StoredRequest, create_shared_secret};

#[allow(clippy::expect_used)]
const CONFIG: LazyLock<Config> = LazyLock::new(|| Config::parse().expect("Failed to parse config"));

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

    let sse_response = reqwest::Client::new()
        .get(CONFIG.sse_url())
        .header("Accept", "text/event-stream")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;

    let mut events = sse_response
        .events()
        .await
        .map_err(|_| "failed to get events")?;

    while let Some(event) = events.next().await {
        match event {
            Ok(event) => {
                if let Err(err) = handle_event(event.clone()).await {
                    log::error!(
                        "Cannot handle request with ID '{}': {}",
                        event.last_event_id.unwrap_or_default(),
                        err
                    );
                }
            }
            Err(err) => eprintln!("SSE error: {err}"),
        }
    }

    Ok(())
}

async fn handle_event(event: Event) -> Result<(), String> {
    let uuid = event.last_event_id.unwrap_or_default();
    let stored_request = reqwest::Client::new()
        .get(CONFIG.pending_url_for(&uuid))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    let shared_secret = create_shared_secret(&CONFIG.secret(), &CONFIG.other_public(), &event.data)
        .map_err(|_| "Failed to create shared secret")?;

    let stored_request = StoredRequest::decrypt_with(&stored_request, shared_secret)
        .map_err(|()| "Decrypt error".to_string())?;

    let method = Method::from_str(stored_request.method.as_str())
        .map_err(|_| stored_request.method)
        .unwrap_or_default();

    if !CONFIG.is_method_allowed(&method) {
        reqwest::Client::new()
            .post(CONFIG.pending_url_for(&uuid))
            .body(
                AgentResponse {
                    status: 405,
                    headers: vec![("X-Proxy".to_string(), "Rejected by agent".to_string())],
                    body: vec![],
                }
                .encrypt_with(shared_secret),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?;
    }

    log::info!(
        "ID {} - {} request for '{}{}'",
        uuid,
        method,
        CONFIG.destination().base_url,
        stored_request.uri
    );

    let mut headers = HeaderMap::new();
    for (name, value) in stored_request.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).map_err(|err| err.to_string())?,
            HeaderValue::from_bytes(value.as_bytes()).map_err(|err| err.to_string())?,
        );
    }
    headers.insert(
        HOST,
        HeaderValue::from_str(&CONFIG.destination().name).map_err(|err| err.to_string())?,
    );

    let response = reqwest::Client::new()
        .request(
            method,
            format!("{}{}", CONFIG.destination().base_url, stored_request.uri),
        )
        //.headers(headers)
        .body(stored_request.body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let _ = reqwest::Client::new()
        .post(CONFIG.pending_url_for(&uuid))
        .body(
            AgentResponse {
                status: response.status().as_u16(),
                headers: response
                    .headers()
                    .iter()
                    .map(|(header_name, header_value)| {
                        (
                            header_name.to_string(),
                            header_value.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect(),
                body: response
                    .bytes()
                    .await
                    .map_err(|err| err.to_string())?
                    .to_vec(),
            }
            .encrypt_with(shared_secret),
        )
        .send()
        .await
        .map_err(|e| e.to_string())?;

    log::info!("ID {} - Response returned", uuid);

    Ok(())
}
