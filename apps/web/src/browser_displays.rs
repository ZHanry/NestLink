//! A proved peer may publish one exact, locally approved display catalog.
//! Neither partial catalogs nor unacknowledged selections become input state.

use crate::browser_peer::PeerError;
use nestlink_protocol::native_displays::{
    CatalogAssembler, DISPLAY_COUNT_MAX, DisplayCatalogKey, DisplayDescriptor, DisplayEnvelope,
    DisplaySelection,
};
use nestlink_protocol::webrtc::WebRtcDisplayControl;
use std::collections::VecDeque;

const MAX_PENDING_CATALOG_BYTES: usize = 32 * 1024;

/// Only Layout/Selected for the outstanding Select may use its exact permit.
/// The caller also checks the live peer/session authority before constructing
/// this window; absence of current authority represents cancellation/revocation.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) struct DisplayPermitWindow<'a> {
    current: Option<&'a nestlink_protocol::PermitClaims>,
    pinned: Option<&'a nestlink_protocol::PermitClaims>,
    same_issuer: bool,
    deadline_ms: Option<f64>,
    now_unix_ms: u64,
    now_monotonic_ms: f64,
}

#[cfg(any(target_arch = "wasm32", test))]
impl<'a> DisplayPermitWindow<'a> {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new(
        current: Option<&'a nestlink_identity::VerifiedPermit>,
        pinned: Option<&'a nestlink_identity::VerifiedPermit>,
        deadline_ms: Option<f64>,
        now_unix_ms: u64,
        now_monotonic_ms: f64,
    ) -> Self {
        Self {
            current: current.map(nestlink_identity::VerifiedPermit::claims),
            pinned: pinned.map(nestlink_identity::VerifiedPermit::claims),
            same_issuer: current
                .zip(pinned)
                .is_some_and(|(current, pinned)| current.issuer() == pinned.issuer()),
            deadline_ms,
            now_unix_ms,
            now_monotonic_ms,
        }
    }

    fn current(&self) -> Result<&'a nestlink_protocol::PermitClaims, PeerError> {
        let claims = self.current.ok_or(PeerError::Cancelled)?;
        if !self.now_monotonic_ms.is_finite()
            || self.now_monotonic_ms < 0.0
            || self.now_unix_ms < claims.issued_at_unix_ms
            || self.now_unix_ms >= claims.expires_at_unix_ms
        {
            return Err(PeerError::Expired);
        }
        Ok(claims)
    }

    pub(crate) fn transaction(&self) -> Result<&'a nestlink_protocol::PermitClaims, PeerError> {
        let current = self.current()?;
        let pinned = self.pinned.ok_or(PeerError::SignalRejected)?;
        if !self.same_issuer
            || self
                .deadline_ms
                .is_none_or(|deadline| !deadline.is_finite() || self.now_monotonic_ms >= deadline)
            || self.now_unix_ms < pinned.issued_at_unix_ms
            || self.now_unix_ms >= pinned.expires_at_unix_ms
        {
            return Err(PeerError::Expired);
        }
        let mut expected = pinned.clone();
        expected.lease_sequence = current.lease_sequence;
        expected.issued_at_unix_ms = current.issued_at_unix_ms;
        expected.expires_at_unix_ms = current.expires_at_unix_ms;
        if &expected != current || current.lease_sequence < pinned.lease_sequence {
            return Err(PeerError::SignalRejected);
        }
        Ok(pinned)
    }

    pub(crate) fn validate_json(
        &self,
        message: &nestlink_protocol::webrtc::WebRtcControl,
    ) -> Result<(), PeerError> {
        let claims = if matches!(
            message,
            nestlink_protocol::webrtc::WebRtcControl::HostInputLayout { .. }
        ) {
            self.transaction()?
        } else {
            self.current()?
        };
        message
            .validate(claims)
            .map_err(|_| PeerError::SignalRejected)
    }

    pub(crate) fn decode_display(&self, bytes: &[u8]) -> Result<WebRtcDisplayControl, PeerError> {
        let current = self.current()?;
        let message = match WebRtcDisplayControl::decode_validated(bytes, current) {
            Ok(message) => message,
            Err(_) => {
                let message = WebRtcDisplayControl::decode_validated(bytes, self.transaction()?)
                    .map_err(|_| PeerError::SignalRejected)?;
                if !matches!(message.message, DisplayEnvelope::Selected(_)) {
                    return Err(PeerError::SignalRejected);
                }
                message
            }
        };
        if matches!(message.message, DisplayEnvelope::Selected(_)) {
            message
                .validate(self.transaction()?)
                .map_err(|_| PeerError::SignalRejected)?;
        }
        Ok(message)
    }
}

/// Accepted and its following catalog can be delivered before the async proof
/// waiter resumes. Keep only one complete bounded catalog, with no ACK or UI
/// publication, until that waiter has verified the acceptance and session.
#[derive(Default)]
pub(crate) struct PendingDisplayCatalog {
    messages: VecDeque<WebRtcDisplayControl>,
    encoded_bytes: usize,
    assembler: CatalogAssembler,
    started: bool,
    committed: bool,
}

impl PendingDisplayCatalog {
    pub(crate) fn push(
        &mut self,
        message: WebRtcDisplayControl,
        encoded_bytes: usize,
    ) -> Result<(), PeerError> {
        if self.committed
            || self.messages.len() >= DISPLAY_COUNT_MAX + 2
            || encoded_bytes > MAX_PENDING_CATALOG_BYTES.saturating_sub(self.encoded_bytes)
        {
            return Err(PeerError::SignalRejected);
        }
        match &message.message {
            DisplayEnvelope::CatalogBegin { catalog, count } if !self.started => {
                self.assembler
                    .begin(catalog.clone(), *count)
                    .map_err(|_| PeerError::SignalRejected)?;
                self.started = true;
            }
            DisplayEnvelope::CatalogEntry {
                catalog,
                index,
                display,
            } => {
                self.assembler
                    .entry(catalog.clone(), *index, display.clone())
                    .map_err(|_| PeerError::SignalRejected)?;
            }
            DisplayEnvelope::CatalogCommit(catalog) => {
                self.assembler
                    .commit(catalog)
                    .map_err(|_| PeerError::SignalRejected)?;
                self.committed = true;
            }
            _ => return Err(PeerError::SignalRejected),
        }
        self.encoded_bytes += encoded_bytes;
        self.messages.push_back(message);
        Ok(())
    }

    pub(crate) fn take(&mut self) -> VecDeque<WebRtcDisplayControl> {
        std::mem::take(self).messages
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerDisplaySnapshot {
    pub displays: Vec<DisplayDescriptor>,
    pub selected: Option<DisplaySelection>,
    pub pending_source: Option<u32>,
}

pub(crate) struct DisplayClientState {
    request_id: String,
    connection_generation: u64,
    input: bool,
    assembler: CatalogAssembler,
    started: bool,
    catalog: Option<DisplayCatalogKey>,
    displays: Vec<DisplayDescriptor>,
    selected: Option<DisplaySelection>,
    pending: Option<(u64, u32)>,
}

impl DisplayClientState {
    pub(crate) fn new(request_id: String, connection_generation: u64, input: bool) -> Self {
        Self {
            request_id,
            connection_generation,
            input,
            assembler: CatalogAssembler::default(),
            started: false,
            catalog: None,
            displays: Vec::new(),
            selected: None,
            pending: None,
        }
    }

    pub(crate) fn receive_catalog(
        &mut self,
        envelope: DisplayEnvelope,
    ) -> Result<Option<DisplayEnvelope>, PeerError> {
        let rejected = |_| PeerError::SignalRejected;
        match envelope {
            DisplayEnvelope::CatalogBegin { catalog, count } => {
                if self.started
                    || catalog.request_id != self.request_id
                    || catalog.connection_generation != self.connection_generation
                {
                    return Err(PeerError::SignalRejected);
                }
                self.assembler.begin(catalog, count).map_err(rejected)?;
                self.started = true;
                Ok(None)
            }
            DisplayEnvelope::CatalogEntry {
                catalog,
                index,
                display,
            } => {
                self.assembler
                    .entry(catalog, index, display)
                    .map_err(rejected)?;
                Ok(None)
            }
            DisplayEnvelope::CatalogCommit(catalog) => {
                if self.catalog.is_some() {
                    return Err(PeerError::SignalRejected);
                }
                let displays = self.assembler.commit(&catalog).map_err(rejected)?;
                self.catalog = Some(catalog.clone());
                self.displays = displays;
                Ok(Some(DisplayEnvelope::CatalogAck(catalog)))
            }
            _ => Err(PeerError::SignalRejected),
        }
    }

    pub(crate) fn snapshot(&self) -> Option<PeerDisplaySnapshot> {
        self.catalog.as_ref().map(|_| PeerDisplaySnapshot {
            displays: self.displays.clone(),
            selected: self.selected.clone(),
            pending_source: self.pending.map(|(_, source)| source),
        })
    }

    pub(crate) fn select(&mut self, source: u32) -> Result<DisplayEnvelope, PeerError> {
        let catalog = self.catalog.clone().ok_or(PeerError::SignalRejected)?;
        if self.pending.is_some() || !self.displays.iter().any(|item| item.source == source) {
            return Err(PeerError::SignalRejected);
        }
        let sequence = self
            .selected
            .as_ref()
            .map_or(0, |selection| selection.sequence)
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(PeerError::SignalRejected)?;
        self.pending = Some((sequence, source));
        Ok(DisplayEnvelope::Select {
            catalog,
            sequence,
            source,
        })
    }

    /// The reliable ordered channel carries the new input layout before Selected.
    /// It remains staged until the complete selection has been checked and ACKed.
    pub(crate) fn validate_layout(
        &self,
        geometry: (i32, i32, u32, u32),
        input_epoch: u64,
        layout_epoch: u64,
    ) -> Result<(), PeerError> {
        let (_, source) = self.pending.ok_or(PeerError::SignalRejected)?;
        let display = self
            .displays
            .iter()
            .find(|item| item.source == source)
            .ok_or(PeerError::SignalRejected)?;
        if !self.input
            || geometry != (display.left, display.top, display.width, display.height)
            || input_epoch == 0
            || input_epoch > i64::MAX as u64
            || layout_epoch == 0
            || layout_epoch > i64::MAX as u64
            || self.selected.as_ref().is_some_and(|previous| {
                input_epoch <= previous.input_epoch || layout_epoch <= previous.layout_epoch
            })
        {
            return Err(PeerError::SignalRejected);
        }
        Ok(())
    }

    pub(crate) fn validate_selection(&self, selected: &DisplaySelection) -> Result<(), PeerError> {
        selected.validate().map_err(|_| PeerError::SignalRejected)?;
        if self.catalog.as_ref() != Some(&selected.catalog)
            || self.pending != Some((selected.sequence, selected.source))
            || (selected.input_epoch != 0) != self.input
            || self.selected.as_ref().is_some_and(|previous| {
                selected.layout_epoch <= previous.layout_epoch
                    || (self.input && selected.input_epoch <= previous.input_epoch)
            })
        {
            return Err(PeerError::SignalRejected);
        }
        Ok(())
    }

    pub(crate) fn commit_selection(&mut self, selected: DisplaySelection) -> Result<(), PeerError> {
        self.validate_selection(&selected)?;
        self.selected = Some(selected);
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::native_displays::catalog_key;

    const REQUEST: &str = "12345678-1234-4234-8234-123456789abc";

    fn public_permit_claims() -> Result<nestlink_protocol::PermitClaims, Box<dyn std::error::Error>>
    {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/session-permit-v1.json"
        ))?;
        let text = vector["envelope_hex"]
            .as_str()
            .ok_or("missing public permit vector")?;
        let bytes = (0..text.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        let signer = nestlink_identity::PermitSigner::from_seed([1; 32]);
        Ok(
            nestlink_identity::verify_permit(&bytes, &signer.public_key())?
                .claims()
                .clone(),
        )
    }

    fn permit_window<'a>(
        old: &'a nestlink_protocol::PermitClaims,
        current: &'a nestlink_protocol::PermitClaims,
    ) -> DisplayPermitWindow<'a> {
        DisplayPermitWindow {
            current: Some(current),
            pinned: Some(old),
            same_issuer: true,
            deadline_ms: Some(5_000.0),
            now_unix_ms: current.issued_at_unix_ms + 1,
            now_monotonic_ms: 1_000.0,
        }
    }

    #[test]
    fn selection_pin_survives_renewal_only_for_exact_layout_and_selected()
    -> Result<(), Box<dyn std::error::Error>> {
        use nestlink_protocol::webrtc::WebRtcControl;
        let old = public_permit_claims()?;
        let mut current = old.clone();
        current.lease_sequence += 1;
        current.issued_at_unix_ms += 1_000;
        current.expires_at_unix_ms += 1_000;
        let window = permit_window(&old, &current);
        assert_eq!(window.transaction()?, &old);
        let layout = WebRtcControl::HostInputLayout {
            schema_version: old.schema_version,
            session_id: old.session_id.clone(),
            connection_generation: old.connection_generation,
            lease_sequence: old.lease_sequence,
            input_epoch: 2,
            layout_epoch: 2,
            left: -256,
            top: -32,
            width: 256,
            height: 144,
        };
        assert!(window.validate_json(&layout).is_ok());
        assert!(layout.validate(&current).is_err());
        let key = catalog_key(&old.session_id, old.connection_generation, 1, &displays())?;
        let selection = DisplaySelection {
            catalog: key.clone(),
            sequence: 1,
            source: 3,
            layout_epoch: 2,
            input_epoch: 2,
        };
        let control = WebRtcDisplayControl {
            schema_version: old.schema_version,
            session_id: old.session_id.clone(),
            connection_generation: old.connection_generation,
            lease_sequence: old.lease_sequence,
            message: DisplayEnvelope::Selected(selection.clone()),
        };
        let encoded = control.encode_validated(&old)?;
        assert_eq!(window.decode_display(&encoded)?, control);
        assert!(WebRtcDisplayControl::decode_validated(&encoded, &current).is_err());
        let ack = WebRtcDisplayControl {
            message: DisplayEnvelope::SelectionAck(selection),
            ..control.clone()
        };
        assert!(ack.encode_validated(window.transaction()?).is_ok());
        assert!(ack.encode_validated(&current).is_err());

        // Neither ordinary JSON nor catalog/ACK messages get the old-permit
        // exception, even while that exact transaction remains live.
        let ordinary = WebRtcControl::EndpointProofAccepted {
            schema_version: old.schema_version,
            session_id: old.session_id.clone(),
            connection_generation: old.connection_generation,
            lease_sequence: old.lease_sequence,
        };
        assert!(ordinary.validate(&old).is_ok());
        assert!(window.validate_json(&ordinary).is_err());
        let old_catalog = WebRtcDisplayControl {
            message: DisplayEnvelope::CatalogCommit(key),
            ..control.clone()
        };
        assert!(
            window
                .decode_display(&old_catalog.encode_validated(&old)?)
                .is_err()
        );
        assert!(window.decode_display(&ack.encode_validated(&old)?).is_err());
        let after_ack = DisplayPermitWindow {
            pinned: None,
            ..window
        };
        assert!(after_ack.decode_display(&encoded).is_err());
        assert!(after_ack.validate_json(&layout).is_err());
        Ok(())
    }

    #[test]
    fn selection_pin_rejects_expiry_revocation_and_changed_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let old = public_permit_claims()?;
        let mut current = old.clone();
        current.lease_sequence += 1;
        current.issued_at_unix_ms += 1_000;
        current.expires_at_unix_ms += 1_000;
        let at_pin_expiry = DisplayPermitWindow {
            now_unix_ms: old.expires_at_unix_ms,
            ..permit_window(&old, &current)
        };
        assert!(at_pin_expiry.transaction().is_err());
        let at_deadline = DisplayPermitWindow {
            now_monotonic_ms: 5_000.0,
            ..permit_window(&old, &current)
        };
        assert!(at_deadline.transaction().is_err());
        let revoked = DisplayPermitWindow {
            current: None,
            ..permit_window(&old, &current)
        };
        assert!(revoked.transaction().is_err());
        let wrong_issuer = DisplayPermitWindow {
            same_issuer: false,
            ..permit_window(&old, &current)
        };
        assert!(wrong_issuer.transaction().is_err());
        let mut expired_current = current.clone();
        expired_current.expires_at_unix_ms = current.issued_at_unix_ms;
        assert!(permit_window(&old, &expired_current).transaction().is_err());
        let mut changed = current.clone();
        changed.session_id = REQUEST.into();
        assert!(permit_window(&old, &changed).transaction().is_err());
        changed = current.clone();
        changed
            .permissions
            .retain(|permission| *permission != nestlink_protocol::Permission::Input as i32);
        assert!(permit_window(&old, &changed).transaction().is_err());
        changed = current.clone();
        changed.connection_generation += 1;
        assert!(permit_window(&old, &changed).transaction().is_err());
        Ok(())
    }

    fn displays() -> Vec<DisplayDescriptor> {
        vec![
            DisplayDescriptor {
                source: 3,
                left: -1920,
                top: 0,
                width: 1920,
                height: 1080,
                label: "左侧显示器".into(),
            },
            DisplayDescriptor {
                source: 8,
                left: 0,
                top: 0,
                width: 2560,
                height: 1440,
                label: "Main display".into(),
            },
        ]
    }

    fn catalog(
        input: bool,
    ) -> Result<(DisplayClientState, DisplayCatalogKey), Box<dyn std::error::Error>> {
        let displays = displays();
        let key = catalog_key(REQUEST, 2, 1, &displays)?;
        let mut client = DisplayClientState::new(REQUEST.into(), 2, input);
        assert!(client.snapshot().is_none());
        client.receive_catalog(DisplayEnvelope::CatalogBegin {
            catalog: key.clone(),
            count: displays.len() as u8,
        })?;
        for (index, display) in displays.into_iter().enumerate() {
            client.receive_catalog(DisplayEnvelope::CatalogEntry {
                catalog: key.clone(),
                index: index as u8,
                display,
            })?;
            assert!(client.snapshot().is_none());
        }
        assert_eq!(
            client.receive_catalog(DisplayEnvelope::CatalogCommit(key.clone()))?,
            Some(DisplayEnvelope::CatalogAck(key.clone()))
        );
        Ok((client, key))
    }

    #[test]
    fn catalog_is_atomic_bound_and_cannot_be_replaced() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, key) = catalog(false)?;
        let snapshot = client.snapshot().ok_or("catalog missing")?;
        assert_eq!(snapshot.displays, displays());
        assert_eq!(snapshot.displays[0].label, "左侧显示器");
        assert!(snapshot.selected.is_none());
        assert!(client.select(99).is_err());
        assert!(
            client
                .receive_catalog(DisplayEnvelope::CatalogBegin {
                    catalog: key.clone(),
                    count: 2,
                })
                .is_err()
        );
        for (request, generation) in [(REQUEST, 3), ("22345678-1234-4234-8234-123456789abc", 2)] {
            let mut wrong = DisplayClientState::new(request.into(), generation, false);
            assert!(
                wrong
                    .receive_catalog(DisplayEnvelope::CatalogBegin {
                        catalog: key.clone(),
                        count: 2,
                    })
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn only_latest_requested_source_and_new_epochs_can_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, key) = catalog(true)?;
        let mut selected = DisplaySelection {
            catalog: key.clone(),
            sequence: 1,
            source: 3,
            layout_epoch: 2,
            input_epoch: 2,
        };
        assert!(client.validate_selection(&selected).is_err());
        assert!(matches!(
            client.select(3)?,
            DisplayEnvelope::Select { sequence: 1, .. }
        ));
        assert!(client.select(8).is_err());
        client.validate_layout((-1920, 0, 1920, 1080), 2, 2)?;
        assert!(client.validate_layout((0, 0, 2560, 1440), 2, 2).is_err());
        for wrong in [
            DisplaySelection {
                source: 8,
                ..selected.clone()
            },
            DisplaySelection {
                sequence: 2,
                ..selected.clone()
            },
            DisplaySelection {
                input_epoch: 0,
                ..selected.clone()
            },
            DisplaySelection {
                catalog: DisplayCatalogKey {
                    revision: 2,
                    ..key.clone()
                },
                ..selected.clone()
            },
        ] {
            assert!(client.validate_selection(&wrong).is_err());
        }
        client.commit_selection(selected.clone())?;
        assert!(client.validate_selection(&selected).is_err());
        assert!(matches!(
            client.select(8)?,
            DisplayEnvelope::Select { sequence: 2, .. }
        ));
        selected.sequence = 2;
        selected.source = 8;
        assert!(client.validate_selection(&selected).is_err());
        assert!(client.validate_layout((0, 0, 2560, 1440), 2, 3).is_err());
        selected.layout_epoch = 3;
        selected.input_epoch = 3;
        client.validate_layout((0, 0, 2560, 1440), 3, 3)?;
        client.commit_selection(selected.clone())?;
        let snapshot = client.snapshot().ok_or("catalog missing")?;
        assert_eq!(snapshot.selected, Some(selected));
        assert_eq!(snapshot.pending_source, None);
        Ok(())
    }

    #[test]
    fn view_only_selection_never_grants_input() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, key) = catalog(false)?;
        client.select(3)?;
        assert!(
            client
                .validate_layout((-1920, 0, 1920, 1080), 1, 1)
                .is_err()
        );
        let mut selected = DisplaySelection {
            catalog: key,
            sequence: 1,
            source: 3,
            layout_epoch: 2,
            input_epoch: 1,
        };
        assert!(client.validate_selection(&selected).is_err());
        selected.input_epoch = 0;
        client.commit_selection(selected)?;
        Ok(())
    }

    #[test]
    fn post_accept_catalog_is_bounded_ordered_and_does_not_publish_early()
    -> Result<(), Box<dyn std::error::Error>> {
        let displays = displays();
        let key = catalog_key(REQUEST, 2, 1, &displays)?;
        let wrap = |message| WebRtcDisplayControl {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            session_id: REQUEST.into(),
            connection_generation: 2,
            lease_sequence: 1,
            message,
        };
        let begin = wrap(DisplayEnvelope::CatalogBegin {
            catalog: key.clone(),
            count: 2,
        });
        let mut pending = PendingDisplayCatalog::default();
        assert!(
            pending
                .push(begin.clone(), MAX_PENDING_CATALOG_BYTES + 1)
                .is_err()
        );
        let mut pending = PendingDisplayCatalog::default();
        assert!(
            pending
                .push(
                    wrap(DisplayEnvelope::Select {
                        catalog: key.clone(),
                        sequence: 1,
                        source: 3,
                    }),
                    120
                )
                .is_err()
        );
        pending.push(begin.clone(), 120)?;
        assert!(pending.push(begin, 120).is_err());
        for (index, display) in displays.into_iter().enumerate() {
            pending.push(
                wrap(DisplayEnvelope::CatalogEntry {
                    catalog: key.clone(),
                    index: index as u8,
                    display,
                }),
                256,
            )?;
        }
        pending.push(wrap(DisplayEnvelope::CatalogCommit(key.clone())), 120)?;
        assert!(
            pending
                .push(wrap(DisplayEnvelope::CatalogCommit(key)), 120)
                .is_err()
        );
        let mut client = DisplayClientState::new(REQUEST.into(), 2, false);
        assert!(client.snapshot().is_none());
        let mut replies = Vec::new();
        for message in pending.take() {
            if let Some(reply) = client.receive_catalog(message.message)? {
                replies.push(reply);
            }
        }
        assert_eq!(replies.len(), 1);
        assert!(client.snapshot().is_some());
        Ok(())
    }
}
