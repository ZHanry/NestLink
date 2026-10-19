//! Refresh each installation's own login before the five-minute access deadline.
//! The actor retains exclusive SDK ownership; logout and server-switch fences
//! still retire any refresh that completes in an older generation.
use super::*;

const REFRESH_AHEAD: Duration = Duration::from_secs(60);

impl Actor {
    pub(super) fn start_session_refresh(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        if self.view.authentication != Authentication::SignedIn
            || self.retire
            || self.boundary.is_some()
            || now < self.session_refresh_retry
            || self
                .access_deadline
                .is_none_or(|deadline| deadline > now + REFRESH_AHEAD)
        {
            return false;
        }
        let Some(mut client) = self.sdk.take() else {
            return false;
        };
        let generation = self.view.generation;
        self.active = Some(Active {
            envelope: None,
            server: Some(client.server.clone()),
            section: None,
            cancelled: None,
            cancellation: Arc::new(AtomicBool::new(false)),
            secret: None,
            remote_revoke: None,
            native_request_id: None,
            native_connection_generation: None,
            service_host_runtime_id: None,
            future: Box::pin(async move {
                let result = client.sdk.refresh().await.map_err(Failure::from);
                Job::SessionRefreshed {
                    client,
                    generation,
                    result,
                }
            }),
        });
        true
    }

    pub(super) fn complete_session_refresh(
        &mut self,
        client: Client,
        generation: u64,
        result: Result<(), Failure>,
    ) {
        self.sdk = Some(client);
        self.session_refresh_retry = tokio::time::Instant::now() + Duration::from_secs(5);
        if generation != self.view.generation
            || self.retire
            || self.boundary.is_some()
            || self.view.lifecycle != Lifecycle::Running
        {
            return;
        }
        if result.is_ok() {
            self.view.principal = self
                .sdk
                .as_ref()
                .and_then(|client| client.sdk.principal().cloned());
            if let Some(principal) = &self.view.principal {
                self.view.security.data = Some(Arc::new(nestlink_protocol::api::MeResponse {
                    principal: principal.clone(),
                }));
            }
            self.install_deadline();
            self.view.authentication_error = None;
            self.publish();
        } else if self
            .sdk
            .as_ref()
            .is_none_or(|client| client.sdk.principal().is_none())
        {
            self.expire();
        }
    }
}
