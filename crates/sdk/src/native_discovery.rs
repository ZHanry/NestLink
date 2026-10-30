//! Deployment discovery is authenticated by the same pinned management entry.
use super::*;

impl Sdk {
    /// Both deployment policy and explicit local gateway consent are required.
    /// Missing endpoints, authentication errors and invalid policy fail closed.
    pub async fn native_pcp_policy(&self) -> Result<NativePcpPolicy, SdkError> {
        #[cfg(target_arch = "wasm32")]
        let policy: NativePcpPolicy = self
            .required(Method::GET, "/discovery/native/pcp", None::<&()>)
            .await?;
        #[cfg(not(target_arch = "wasm32"))]
        let policy: NativePcpPolicy = self
            .native_discovery_response("/discovery/native/pcp")
            .await?;
        policy.validate()?;
        if policy.deployment_id != self.trust.deployment_id {
            return Err(SdkError::Trust);
        }
        Ok(policy)
    }

    pub async fn native_discovery_config(&self) -> Result<NativeDiscoveryConfig, SdkError> {
        #[cfg(target_arch = "wasm32")]
        let config: NativeDiscoveryConfig = self
            .required(Method::GET, "/network/discovery", None::<&()>)
            .await?;
        #[cfg(not(target_arch = "wasm32"))]
        let config: NativeDiscoveryConfig =
            self.native_discovery_response("/network/discovery").await?;
        if config.deployment_id != self.trust.deployment_id {
            return Err(SdkError::Trust);
        }
        config.validate()?;
        Ok(config)
    }

    /// Discovery has one total network budget, including a streaming success
    /// body. A known HTTP rejection is returned before reading its body, so a
    /// delayed error document cannot turn a hard rejection into a timeout.
    #[cfg(not(target_arch = "wasm32"))]
    async fn native_discovery_response<R: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<R, SdkError> {
        const BUDGET: Duration = Duration::from_secs(3);
        let token = self.login.as_ref().ok_or(SdkError::SignIn)?.access.expose();
        let url = self
            .origin
            .join(&format!("{API_BASE}{path}"))
            .map_err(|_| SdkError::Invalid)?;
        let operation = async {
            let response = self
                .client
                .get(url)
                .header("Origin", self.origin.origin().ascii_serialization())
                .bearer_auth(token)
                .timeout(BUDGET)
                .send()
                .await?;
            let status = response.status();
            if !status.is_success() {
                // These codes describe the already-known status. Parsing an
                // optional error body could lose that fact to a transport or
                // deadline failure, or reject an ordinary proxy's HTML 503.
                let code = match status {
                    StatusCode::UNAUTHORIZED => ErrorCode::AuthRequired,
                    StatusCode::FORBIDDEN => ErrorCode::PermissionRequired,
                    StatusCode::TOO_MANY_REQUESTS => ErrorCode::CapacityExceeded,
                    status if status.is_server_error() => ErrorCode::InternalError,
                    _ => ErrorCode::InvalidMessage,
                };
                return Err(SdkError::Api(status, code));
            }
            if response
                .content_length()
                .is_some_and(|size| size > CONTROL_BYTES)
            {
                return Err(SdkError::Invalid);
            }
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if bytes.len().saturating_add(chunk.len()) > CONTROL_BYTES as usize {
                    return Err(SdkError::Invalid);
                }
                bytes.extend_from_slice(&chunk);
            }
            decode_response(status, &bytes)?.ok_or(SdkError::Invalid)
        };
        tokio::time::timeout(BUDGET, operation)
            .await
            .map_err(|_| SdkError::Timeout)?
    }
}

impl SdkError {
    /// Only unavailable transport/service failures may leave discovery empty.
    /// TLS validation, authentication, missing routes and invalid JSON fail closed.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn discovery_temporarily_unavailable(&self) -> bool {
        match self {
            Self::Timeout => true,
            Self::Api(status, _) => matches!(
                *status,
                StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            ),
            Self::Transport(error) if error.is_timeout() => true,
            Self::Transport(error) => {
                use std::error::Error;
                let mut source = error.source();
                while let Some(error) = source {
                    if let Some(io) = error.downcast_ref::<std::io::Error>() {
                        return matches!(
                            io.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::NetworkUnreachable
                                | std::io::ErrorKind::HostUnreachable
                                | std::io::ErrorKind::NotConnected
                                | std::io::ErrorKind::AddrNotAvailable
                                | std::io::ErrorKind::TimedOut
                        );
                    }
                    source = error.source();
                }
                false
            }
            _ => false,
        }
    }
}
