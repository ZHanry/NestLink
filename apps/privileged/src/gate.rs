use crate::wire::{
    BrokerAction, BrokerError, BrokerState, Grant, GrantBinding, Layout, Result, Stamp, Status,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::verify_permit;
use nestlink_platform_input::NativeInput;
use nestlink_protocol::{PERMIT_BYTES, Permission, PermitClaims, valid_id};
use nestlink_remote::input::{Button, InputAction, PlatformInput};
use rand_core::{OsRng, RngCore};
use std::{collections::BTreeSet, io};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct TrustPins {
    pub issuer: [u8; 32],
    pub deployment_id: String,
    pub host_device_id: String,
    pub host_key_sha256: [u8; 32],
}
impl TrustPins {
    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.deployment_id)
            || !valid_id(&self.host_device_id)
            || self.issuer == [0; 32]
            || self.host_key_sha256 == [0; 32]
        {
            return Err(BrokerError::Authorization);
        }
        Ok(())
    }
}

/// Public facts displayed by the elevated local consent window, never remote text.
pub struct ConsentFacts {
    pub deployment_id: String,
    pub host_device_id: String,
    pub controller_device_id: String,
    pub session_id: String,
    pub connection_generation: u64,
    pub issuer: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub layout: Layout,
}
struct Pending {
    claims: PermitClaims,
    binding: GrantBinding,
    layout: Layout,
    deadline_ms: u64,
}
struct Active<D: NativeInput> {
    device: D,
    claims: PermitClaims,
    grant: Grant,
    deadline_ms: u64,
    sequence: u64,
    held: BTreeSet<Button>,
}

pub struct BrokerGate<D: NativeInput> {
    pins: TrustPins,
    pending: Option<Pending>,
    active: Option<Active<D>>,
    last_clock: Option<Stamp>,
    stopped: bool,
    cleanup_failed: bool,
}
impl<D: NativeInput> BrokerGate<D> {
    pub fn new(pins: TrustPins) -> Result<Self> {
        pins.validate()?;
        Ok(Self {
            pins,
            pending: None,
            active: None,
            last_clock: None,
            stopped: false,
            cleanup_failed: false,
        })
    }
    pub fn status(&self) -> Status {
        Status {
            state: if self.stopped {
                BrokerState::Stopped
            } else if self.active.is_some() {
                BrokerState::Active
            } else {
                BrokerState::Idle
            },
            cleanup_failed: self.cleanup_failed,
        }
    }
    fn clear(&mut self) -> Result<()> {
        self.pending = None;
        let Some(mut active) = self.active.take() else {
            return if self.cleanup_failed {
                Err(BrokerError::Cleanup)
            } else {
                Ok(())
            };
        };
        let first =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| active.device.begin_reset()));
        // A failed initialization must not suppress the actual release attempt.
        let second =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| active.device.reset()));
        if !matches!(first, Ok(Ok(()))) || !matches!(second, Ok(Ok(()))) {
            self.cleanup_failed = true;
            self.stopped = true;
            return Err(BrokerError::Cleanup);
        }
        Ok(())
    }
    fn clock(&mut self, now: Stamp) -> Result<()> {
        if self.last_clock.is_some_and(|previous| {
            now.monotonic_ms < previous.monotonic_ms || now.unix_ms < previous.unix_ms
        }) {
            self.stopped = true;
            self.clear()?;
            return Err(BrokerError::Clock);
        }
        self.last_clock = Some(now);
        if self.stopped {
            return Err(BrokerError::Stopped);
        }
        Ok(())
    }
    pub fn tick(&mut self, now: Stamp) -> Result<()> {
        self.clock(now)?;
        if self.active.as_ref().is_some_and(|active| {
            now.monotonic_ms >= active.deadline_ms
                || now.unix_ms >= active.claims.expires_at_unix_ms
        }) {
            self.clear()?;
            return Err(BrokerError::Expired);
        }
        if let Some(active) = &mut self.active {
            let checked =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| active.device.check()));
            if !matches!(checked, Ok(Ok(()))) {
                self.clear()?;
                return Err(BrokerError::Platform);
            }
        }
        Ok(())
    }
    fn claims(&self, encoded: &str, now: Stamp) -> Result<(PermitClaims, u64)> {
        if encoded.is_empty() || encoded.len() > (PERMIT_BYTES as usize).div_ceil(3) * 4 {
            return Err(BrokerError::Protocol);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| BrokerError::Protocol)?,
        );
        let verified =
            verify_permit(&bytes, &self.pins.issuer).map_err(|_| BrokerError::Authorization)?;
        let claims = verified.claims();
        if claims.deployment_id != self.pins.deployment_id
            || claims.host_device_id != self.pins.host_device_id
            || claims.host_key_sha256.as_slice() != self.pins.host_key_sha256
        {
            return Err(BrokerError::Authorization);
        }
        if !claims.permissions.contains(&(Permission::Input as i32)) {
            return Err(BrokerError::Permission);
        }
        let remaining = claims
            .expires_at_unix_ms
            .checked_sub(now.unix_ms)
            .filter(|value| *value > 0)
            .ok_or(BrokerError::Expired)?;
        if claims.issued_at_unix_ms > now.unix_ms {
            return Err(BrokerError::Expired);
        }
        let lifetime = claims.expires_at_unix_ms - claims.issued_at_unix_ms;
        let deadline = now
            .monotonic_ms
            .checked_add(remaining.min(lifetime))
            .ok_or(BrokerError::Clock)?;
        Ok((claims.clone(), deadline))
    }
    /// Starts only an authorization proposal. No input device exists until the
    /// caller displays these facts in the elevated local consent UI and approves.
    pub fn begin_authorize(
        &mut self,
        signed_permit: &str,
        input_epoch: u64,
        layout_epoch: u64,
        layout: Layout,
        now: Stamp,
    ) -> Result<ConsentFacts> {
        self.tick(now)?;
        if self.active.is_some() || self.pending.is_some() {
            return Err(BrokerError::Busy);
        }
        if [input_epoch, layout_epoch]
            .iter()
            .any(|value| *value == 0 || *value > i64::MAX as u64)
        {
            return Err(BrokerError::Epoch);
        }
        if !layout.valid() {
            return Err(BrokerError::Layout);
        }
        let (claims, deadline_ms) = self.claims(signed_permit, now)?;
        let facts = ConsentFacts {
            deployment_id: claims.deployment_id.clone(),
            host_device_id: claims.host_device_id.clone(),
            controller_device_id: claims.controller_device_id.clone(),
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            issuer: self.pins.issuer,
            host_key_sha256: self.pins.host_key_sha256,
            layout,
        };
        let binding = GrantBinding {
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            input_epoch,
            layout_epoch,
        };
        self.pending = Some(Pending {
            claims,
            binding,
            layout,
            deadline_ms,
        });
        Ok(facts)
    }
    pub fn cancel_authorization(&mut self) {
        self.pending = None;
    }
    /// Called only after the elevated, bounded, default-cancel local consent UI.
    /// The platform device is opened after that UI returns to Default desktop.
    pub fn approve_authorization(&mut self, mut device: D, now: Stamp) -> Result<Grant> {
        self.clock(now)?;
        let pending = self.pending.take().ok_or(BrokerError::Authorization)?;
        if now.monotonic_ms >= pending.deadline_ms
            || now.unix_ms >= pending.claims.expires_at_unix_ms
        {
            return Err(BrokerError::Expired);
        }
        if !Layout::from(device.layout()).contains_layout(pending.layout) {
            return Err(BrokerError::Layout);
        }
        device.check().map_err(|_| BrokerError::Platform)?;
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| BrokerError::Platform)?;
        let grant = Grant {
            nonce,
            binding: pending.binding,
            layout: pending.layout,
        };
        self.active = Some(Active {
            device,
            claims: pending.claims,
            grant: grant.clone(),
            deadline_ms: pending.deadline_ms,
            sequence: 0,
            held: BTreeSet::new(),
        });
        Ok(grant)
    }
    fn active_for(
        &mut self,
        nonce: &[u8; 32],
        binding: Option<&GrantBinding>,
        now: Stamp,
    ) -> Result<&mut Active<D>> {
        self.tick(now)?;
        let active = self.active.as_mut().ok_or(BrokerError::Authorization)?;
        if &active.grant.nonce != nonce {
            return Err(BrokerError::Authorization);
        }
        if binding.is_some_and(|binding| binding != &active.grant.binding) {
            return Err(BrokerError::Epoch);
        }
        Ok(active)
    }
    pub fn renew(
        &mut self,
        nonce: &[u8; 32],
        signed_permit: &str,
        now: Stamp,
    ) -> Result<GrantBinding> {
        self.active_for(nonce, None, now)?;
        let (claims, deadline_ms) = self.claims(signed_permit, now)?;
        let active = self.active.as_mut().ok_or(BrokerError::Authorization)?;
        if claims.lease_sequence <= active.claims.lease_sequence
            || claims.issued_at_unix_ms < active.claims.issued_at_unix_ms
        {
            return Err(BrokerError::Replay);
        }
        let mut expected = active.claims.clone();
        expected.lease_sequence = claims.lease_sequence;
        expected.issued_at_unix_ms = claims.issued_at_unix_ms;
        expected.expires_at_unix_ms = claims.expires_at_unix_ms;
        if expected != claims {
            return Err(BrokerError::Authorization);
        }
        active.grant.binding.lease_sequence = claims.lease_sequence;
        active.claims = claims;
        active.deadline_ms = deadline_ms;
        Ok(active.grant.binding.clone())
    }
    pub fn input(
        &mut self,
        nonce: &[u8; 32],
        binding: &GrantBinding,
        sequence: u64,
        action: BrokerAction,
        now: Stamp,
    ) -> Result<()> {
        let active = self.active_for(nonce, Some(binding), now)?;
        if sequence == 0 || sequence <= active.sequence || sequence > i64::MAX as u64 {
            return Err(BrokerError::Replay);
        }
        let action = action.into_native(active.grant.layout)?;
        if matches!(&action, InputAction::Text(_)) && !active.held.is_empty() {
            return Err(BrokerError::Protocol);
        }
        let button = match &action {
            InputAction::Key { code, down } => Some((Button::Key(*code), *down)),
            InputAction::Pointer {
                button: Some(button),
                down,
                ..
            } => Some((Button::Pointer(*button), *down)),
            _ => None,
        };
        // Retain a possible partial down effect before the OS call so failures
        // still enter full platform cleanup rather than losing a held key.
        if let Some((button, true)) = button {
            active.held.insert(button);
        }
        active.sequence = sequence;
        let injected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            active.device.inject(PlatformInput::Action(&action))
        }));
        if !matches!(injected, Ok(Ok(()))) {
            self.clear()?;
            return Err(BrokerError::Platform);
        }
        if let Some((button, false)) = button {
            active.held.remove(&button);
        }
        Ok(())
    }
    pub fn release_all(
        &mut self,
        nonce: &[u8; 32],
        binding: &GrantBinding,
        sequence: u64,
        now: Stamp,
    ) -> Result<()> {
        let active = self.active_for(nonce, Some(binding), now)?;
        if sequence == 0 || sequence <= active.sequence || sequence > i64::MAX as u64 {
            return Err(BrokerError::Replay);
        }
        active.sequence = sequence;
        let mut failed = false;
        for button in active.held.iter().copied().collect::<Vec<_>>() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                active.device.inject(PlatformInput::Release(button))
            }));
            if matches!(result, Ok(Ok(()))) {
                active.held.remove(&button);
            } else {
                failed = true;
            }
        }
        if failed {
            self.clear()?;
            return Err(BrokerError::Platform);
        }
        Ok(())
    }
    pub fn revoke(&mut self, nonce: &[u8; 32]) -> Result<()> {
        if self
            .active
            .as_ref()
            .is_none_or(|active| &active.grant.nonce != nonce)
        {
            return Err(BrokerError::Authorization);
        }
        self.clear()
    }
    pub fn disconnect(&mut self) -> Result<()> {
        self.clear()
    }
    pub fn stop_user(&mut self) -> Result<()> {
        self.stopped = true;
        self.clear()
    }
}
impl<D: NativeInput> Drop for BrokerGate<D> {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

impl From<BrokerError> for io::Error {
    fn from(value: BrokerError) -> Self {
        let kind = match value {
            BrokerError::Timeout => io::ErrorKind::TimedOut,
            BrokerError::Io | BrokerError::Cleanup | BrokerError::Platform => io::ErrorKind::Other,
            BrokerError::Protocol
            | BrokerError::Layout
            | BrokerError::Epoch
            | BrokerError::Replay => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::PermissionDenied,
        };
        Self::new(kind, value)
    }
}
