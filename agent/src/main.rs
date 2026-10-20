mod config;

use crate::config::Config;
use reqwest::Method;
use reqwest::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use reqwest_sse::EventSource;
use std::str::FromStr;
use tokio_stream::StreamExt;
use transmission::{AgentResponse, StoredRequest, create_shared_secret};

#[tokio::main]
async fn main() -> Result<(), String> {
    let config = Config::parse().map_err(|_| "Failed to parse config")?;

    let sse_response = reqwest::Client::new()
        .get(config.sse_url())
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
                let uuid = event.last_event_id.unwrap_or_default();
                let stored_request = reqwest::Client::new()
                    .get(config.pending_url_for(&uuid))
                    .send()
                    .await
                    .map_err(|e| e.to_string())?
                    .error_for_status()
                    .map_err(|e| e.to_string())?
                    .text()
                    .await
                    .map_err(|e| e.to_string())?;

                let shared_secret =
                    create_shared_secret(&config.secret(), &config.other_public(), &event.data)
                        .unwrap();

                let stored_request = StoredRequest::decrypt_with(&stored_request, shared_secret)
                    .map_err(|_| "Decrypt error".to_string())?;

                let method = Method::from_str(stored_request.method.as_str())
                    .map_err(|_| stored_request.method)
                    .unwrap_or_default();

                if !config.is_method_allowed(&method) {
                    reqwest::Client::new()
                        .post(config.pending_url_for(&uuid))
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

                log::info!("Request for {} with UUID {}", stored_request.uri, uuid);

                let mut headers = HeaderMap::new();
                for (name, value) in stored_request.headers {
                    headers.insert(
                        HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        HeaderValue::from_bytes(value.as_bytes()).unwrap(),
                    );
                }
                headers.insert(
                    HOST,
                    HeaderValue::from_str(&config.destination().name).unwrap(),
                );

                let response = reqwest::Client::new()
                    .request(
                        method,
                        format!("{}{}", &config.destination().base_url, stored_request.uri),
                    )
                    //.headers(headers)
                    .body(stored_request.body)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;

                let _ = reqwest::Client::new()
                    .post(config.pending_url_for(&uuid))
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
                            body: response.bytes().await.unwrap().to_vec(),
                        }
                        .encrypt_with(shared_secret),
                    )
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Err(err) => eprintln!("SSE error: {err}"),
        }
    }

    Ok(())
}
