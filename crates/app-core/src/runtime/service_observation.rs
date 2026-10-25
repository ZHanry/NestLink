//! On-demand verified service lease evidence. No snapshot history or authority.
use super::*;
impl CoreHandle {
    pub async fn local_service_lease_observation(
        &self,
        runtime_id: String,
        expected_generation: u64,
        request: crate::ServiceLeaseObservationRequest,
    ) -> Result<crate::ServiceLeaseObservation, SubmitError> {
        if !nestlink_protocol::valid_id(&runtime_id) || !request.valid() {
            return Err(SubmitError::Invalid);
        }
        if expected_generation != self.shared.generation.load(Ordering::Acquire) {
            return Err(SubmitError::StaleGeneration);
        }
        let permit = self.capacity(true)?;
        let (reply, receive) = oneshot::channel();
        self.controls
            .try_send(Control::LocalServiceLeaseObservation {
                runtime_id,
                expected_generation,
                request,
                reply,
                _permit: permit,
            })
            .map_err(send_error)?;
        tokio::time::timeout(Duration::from_millis(500), receive)
            .await
            .map_err(|_| SubmitError::Capacity)?
            .unwrap_or(Err(SubmitError::Stopped))
    }
}
impl Actor {
    pub(super) fn local_service_lease_observation(
        &self,
        runtime_id: &str,
        expected_generation: u64,
        request: &crate::ServiceLeaseObservationRequest,
    ) -> Result<crate::ServiceLeaseObservation, SubmitError> {
        if expected_generation != self.view.generation {
            return Err(SubmitError::StaleGeneration);
        }
        let owner = self
            .service_host_owner
            .as_ref()
            .ok_or(SubmitError::Stopped)?;
        let view = self
            .view
            .local_service_host
            .as_ref()
            .ok_or(SubmitError::Stopped)?;
        let approved = owner.approved_view.as_ref().ok_or(SubmitError::Stopped)?;
        if owner.cleanup_requested
            || view.status != crate::LocalServiceHostStatus::Running
            || view.cleanup_failed
            || owner.binding.service_id != request.service_id
            || approved.revision != request.approved_revision
            || !snapshot_context_matches_binding(&self.view, &owner.binding, runtime_id)
            || !approved_service_matches(&owner.binding, approved)
            || self
                .view
                .selected_service
                .data
                .as_ref()
                .filter(|s| s.id == owner.binding.service_id)
                .is_some_and(|s| !approved_service_matches(&owner.binding, s))
            || self
                .view
                .services
                .data
                .as_ref()
                .and_then(|page| {
                    page.services
                        .iter()
                        .find(|s| s.id == owner.binding.service_id)
                })
                .is_some_and(|s| !approved_service_matches(&owner.binding, s))
        {
            return Err(SubmitError::Invalid);
        }
        let mut observation = owner
            .runtime
            .lease_observation(request)
            .map_err(|_| SubmitError::Stopped)?;
        if observation.sample_finished_unix_ms / 1000 >= owner.binding.auth_expires
            || observation.service_id != owner.binding.service_id
            || observation.service_revision != approved.revision
            || observation.choice_revision != owner.binding.service_revision
            || URL_SAFE_NO_PAD.encode(observation.definition_sha256)
                != owner.binding.definition_sha256
            || URL_SAFE_NO_PAD.encode(observation.target_sha256) != owner.binding.target_sha256
        {
            return Err(SubmitError::Invalid);
        }
        observation.runtime_generation = Some(expected_generation);
        Ok(observation)
    }
}
