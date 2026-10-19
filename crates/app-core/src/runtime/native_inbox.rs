//! A host wakes only for approved offers addressed to its local key.
use super::*;
use nestlink_protocol::api::RemoteView;

impl Actor {
    pub(super) fn start_native_inbox(&mut self) -> bool {
        if self.native.as_ref().is_none_or(|config| {
            !config.listen_for_native_requests && config.browser_host.is_none()
        }) || self.view.authentication != Authentication::SignedIn
            || self.view.principal.is_none()
            || self.boundary.is_some()
            || self.retire
            || !self.native_network_idle()
            || tokio::time::Instant::now() < self.native_inbox_deadline
        {
            return false;
        }
        let Some(identity) = self.identity.clone() else {
            return false;
        };
        let Some(client) = self.sdk.take() else {
            return false;
        };
        let generation = self.view.generation;
        let browser_enabled = self
            .native
            .as_ref()
            .is_some_and(|config| config.browser_host.is_some());
        let native_enabled = self
            .native
            .as_ref()
            .is_some_and(|config| config.listen_for_native_requests);
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
                let result = tokio::time::timeout(Duration::from_secs(2), async {
                    let native = async {
                        if native_enabled {
                            client.sdk.ready_native_remote(&identity).await
                        } else {
                            Ok(Vec::new())
                        }
                    };
                    let browser = async {
                        if browser_enabled {
                            client.sdk.ready_browser_remote(&identity).await
                        } else {
                            Ok(Vec::new())
                        }
                    };
                    tokio::try_join!(native, browser)
                })
                .await
                .map_err(|_| Failure::local(FailureKind::Timeout))
                .and_then(|result| result.map_err(Failure::from));
                Job::NativeInboxPolled {
                    client,
                    generation,
                    result,
                }
            }),
        });
        true
    }

    pub(super) fn complete_native_inbox(
        &mut self,
        active: Active,
        client: Client,
        generation: u64,
        result: Result<(Vec<RemoteView>, Vec<RemoteView>), Failure>,
    ) {
        // Return ownership even across logout/server-switch so normal retirement
        // can invalidate the old login. Never continue an old generation.
        self.sdk = Some(client);
        self.native_inbox_deadline =
            tokio::time::Instant::now() + Duration::from_secs(if result.is_ok() { 1 } else { 5 });
        if generation != self.view.generation
            || self.view.lifecycle != Lifecycle::Running
            || self.view.authentication != Authentication::SignedIn
            || self.retire
            || self.boundary.is_some()
            // A user command may arrive while this read is in flight. Let it
            // run first; a manual Start must not race an automatic duplicate.
            || !self.pending.is_empty()
            || active.cancelled.is_some()
            || active.cancellation.load(Ordering::Acquire)
        {
            return;
        }
        let Ok((offers, browser_offers)) = result else {
            return;
        };
        let Some(identity) = &self.identity else {
            return;
        };
        self.native_inbox_attempts
            .retain(|(epoch, _, _)| *epoch == generation);
        // Bound retained wake-up hints. Offers expire at the server; retaining
        // only the current batch cannot create new consent or widen permissions.
        if self.native_inbox_attempts.len() > 256 {
            self.native_inbox_attempts.retain(|(_, id, connection)| {
                offers
                    .iter()
                    .chain(browser_offers.iter())
                    .any(|offer| &offer.id == id && offer.connection_generation == *connection)
            });
        }
        let all_offers = offers
            .into_iter()
            .map(|offer| (false, offer))
            .chain(browser_offers.into_iter().map(|offer| (true, offer)));
        for (browser, offer) in all_offers {
            let key = (generation, offer.id.clone(), offer.connection_generation);
            if offer.host_device_id != identity.device_id
                || offer.controller_device_id == identity.device_id
                || offer.status != "approved"
                || (!browser && offer.lease_sequence == 0)
                || offer.connection_generation == 0
                || offer.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX)
                || self.native_inbox_attempts.contains(&key)
                // A manual or recovered session need not have come through
                // this inbox. Its retained stopped/failed view also consumes
                // the generation, so explicit stop cannot wake it again.
                || self.view.native_session.data.as_ref().is_some_and(|session| {
                    session.request_id == offer.id
                        && session.connection_generation == offer.connection_generation
                })
            {
                continue;
            }
            if self.view.browser_host.data.as_ref().is_some_and(|host| {
                host.request_id == offer.id
                    && host.connection_generation == offer.connection_generation
            }) {
                continue;
            }
            let action = if browser {
                let request_id = offer.id.clone();
                self.view.selected_request.data = Some(Arc::new(offer));
                Action::StartBrowserHost { request_id }
            } else {
                Action::StartNativeSession {
                    request_id: offer.id,
                }
            };
            if self
                .automation
                .submit_for_generation(generation, action)
                .is_ok()
            {
                self.native_inbox_attempts.insert(key);
            }
            break;
        }
    }
}
