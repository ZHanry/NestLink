//! Browser system API adapter; business state and signatures stay in the shared SDK.
use super::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, RequestCache, RequestCredentials, RequestInit, RequestMode, RequestRedirect,
};

struct AbortOnDrop(AbortController);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn request<R: DeserializeOwned>(
    _client: &Client,
    origin: &Url,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> Result<Option<R>, SdkError> {
    let url = origin
        .join(&format!("{API_BASE}{path}"))
        .map_err(|_| SdkError::Invalid)?;
    let init = RequestInit::new();
    init.set_method(method.as_str());
    init.set_redirect(RequestRedirect::Error);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_mode(RequestMode::SameOrigin);
    init.set_cache(RequestCache::NoStore);
    let abort = AbortController::new().map_err(|_| SdkError::BrowserTransport)?;
    let _abort_on_drop = AbortOnDrop(abort.clone());
    init.set_signal(Some(&abort.signal()));
    if let Some(body) = body {
        init.set_body(&JsValue::from_str(&serde_json::to_string(&body)?));
    }
    let request = web_sys::Request::new_with_str_and_init(url.as_str(), &init)
        .map_err(|_| SdkError::BrowserTransport)?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|_| SdkError::BrowserTransport)?;
    if let Some(token) = token {
        request
            .headers()
            .set("Authorization", &format!("Bearer {token}"))
            .map_err(|_| SdkError::BrowserTransport)?;
    }
    let window = web_sys::window().ok_or(SdkError::BrowserTransport)?;
    let operation = async {
        let response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| SdkError::BrowserTransport)?;
        let response = response
            .dyn_into::<web_sys::Response>()
            .map_err(|_| SdkError::BrowserTransport)?;
        let status = StatusCode::from_u16(response.status()).map_err(|_| SdkError::Invalid)?;
        let mut bytes = Vec::new();
        if let Some(body) = response.body() {
            let mut stream = wasm_streams::ReadableStream::from_raw(body).into_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(|_| SdkError::BrowserTransport)?
                    .dyn_into::<js_sys::Uint8Array>()
                    .map_err(|_| SdkError::Invalid)?;
                if bytes.len().saturating_add(chunk.length() as usize) > CONTROL_BYTES as usize {
                    return Err(SdkError::Invalid);
                }
                bytes.extend_from_slice(&chunk.to_vec());
            }
        }
        decode_response(status, &bytes)
    };
    match futures_util::future::select(
        Box::pin(operation),
        Box::pin(gloo_timers::future::TimeoutFuture::new(15000)),
    )
    .await
    {
        futures_util::future::Either::Left((result, _)) => {
            if result.is_err() {
                abort.abort();
            }
            result
        }
        futures_util::future::Either::Right((_, _)) => {
            abort.abort();
            Err(SdkError::Timeout)
        }
    }
}
