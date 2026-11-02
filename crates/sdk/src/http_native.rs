//! Native adapter retains the original bounded JSON request/response contract.
use super::*;

pub(super) async fn request<R: DeserializeOwned>(
    client: &Client,
    origin: &Url,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> Result<Option<R>, SdkError> {
    // Waiting, connect, headers and the complete bounded body share the same
    // original budget. Enclosing signed-handshake deadlines can cancel sooner.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let operation = async {
        let _admission = http_admission::acquire(origin, &method).await?;
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero()).ok_or(SdkError::Timeout)?;
        let url = origin.join(&format!("{API_BASE}{path}")).map_err(|_| SdkError::Invalid)?;
        let mut request = client.request(method, url)
            .header("Origin", origin.origin().ascii_serialization()).timeout(remaining);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        if response.content_length().is_some_and(|v| v > CONTROL_BYTES) {
            return Err(SdkError::Invalid);
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > CONTROL_BYTES as usize {
                return Err(SdkError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        decode_response(status, &bytes)
    };
    tokio::time::timeout_at(deadline, operation).await.map_err(|_| SdkError::Timeout)?
}
