//! A single cumulative offline authority for every reconnect and both I/O halves.
use super::*;
use std::{
    pin::Pin,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct State {
    pub authority: nestlink_identity::offline::OfflineAdmission,
    definition: [u8; 32],
    target: [u8; 32],
    paused: bool,
    wakers: Vec<Waker>,
}
pub(super) struct Shared {
    pub state: Mutex<State>,
    pub authority_key: [u8; 32],
    signal: watch::Sender<bool>,
    pub active: AtomicU32,
    recovery: tokio::sync::Mutex<()>,
}
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
impl State {
    fn check(&mut self, now: u64) -> io::Result<()> {
        self.authority
            .check_current(now)
            .map_err(|e| denied(&e.to_string()))?;
        if self.authority.spent_bytes() >= self.authority.claims().resources.byte_limit {
            self.authority.stop();
            return Err(denied("offline cumulative byte reservation exhausted"));
        }
        Ok(())
    }
    fn remaining(&self) -> usize {
        self.authority
            .claims()
            .resources
            .byte_limit
            .saturating_sub(self.authority.spent_bytes())
            .min(16 * 1024) as usize
    }
    fn charge(&mut self, now: u64, n: usize) -> io::Result<()> {
        self.authority
            .admit_private_service(now, &self.definition, &self.target, n as u64)
            .map_err(|e| denied(&e.to_string()))
    }
    fn wake(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }
}
impl Shared {
    pub fn new(
        consumed: crate::network_management::ConsumedOfflineBundle,
        identity: &DeviceIdentity,
        endpoint: usize,
    ) -> Result<Arc<Self>, SdkError> {
        let (mut authority, authority_key) = consumed.into_admission();
        authority.check_current(wall()?)?;
        let member = &authority.claims().members[endpoint];
        if member.installation_id != identity.device_id
            || member.public_key != identity.identity.public_key()
        {
            return Err(SdkError::Trust);
        }
        let OfflineBusiness::PrivateService {
            definition_digest,
            target_digest,
            ..
        } = &authority.claims().business
        else {
            return Err(SdkError::Trust);
        };
        let (definition, target) = (*definition_digest, *target_digest);
        let (signal, _) = watch::channel(false);
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                authority,
                definition,
                target,
                paused: false,
                wakers: Vec::new(),
            }),
            authority_key,
            signal,
            active: AtomicU32::new(0),
            recovery: tokio::sync::Mutex::new(()),
        }))
    }
    pub fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| denied("offline authority lock failed"))
    }
    pub fn check(&self) -> io::Result<()> {
        self.lock()?.check(wall()?)
    }
    pub fn stop(&self) {
        self.signal.send_replace(true);
        if let Ok(mut state) = self.lock() {
            state.authority.stop();
            state.wake();
        }
    }
    pub async fn stopped(&self) {
        let mut signal = self.signal.subscribe();
        loop {
            if *signal.borrow() || self.check().is_err() {
                return;
            }
            tokio::select! {biased;
                result=signal.changed()=>if result.is_err() {return;},
                _=tokio::time::sleep(Duration::from_millis(250))=>{},
            }
        }
    }
    pub fn status(&self, cleanup_pending: bool) -> Result<OfflinePrivateStatus, SdkError> {
        let state = self.lock()?;
        let c = state.authority.claims();
        Ok(OfflinePrivateStatus {
            bundle_id: c.bundle_id.clone(),
            direct_only: true,
            expires_at_ms: c.expires_at_ms,
            remaining_ms: state
                .authority
                .remaining_lifetime()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            remaining_bytes: c
                .resources
                .byte_limit
                .saturating_sub(state.authority.spent_bytes()),
            cumulative_connections: state.authority.connections(),
            connected: self.active.load(Ordering::Acquire),
            stopped: state.authority.is_stopped(),
            recovering: state.paused,
            cleanup_pending: cleanup_pending && state.authority.is_stopped(),
            central_revocation_may_be_delayed_until_ms: c.expires_at_ms,
        })
    }
    pub async fn synchronize(&self, sdk: &Sdk) -> Result<(), SdkError> {
        let _recovery = self.recovery.lock().await;
        let claims = {
            let mut state = self.lock()?;
            state.check(wall()?)?;
            state.paused = true;
            state.authority.claims().clone()
        };
        let result = async {
            let view = sdk
                .offline_bundle(&claims.space_id, &claims.bundle_id)
                .await?;
            if !view.live
                || view.claims != claims
                || view.authority_public_key != self.authority_key
            {
                return Err(SdkError::Trust);
            }
            let revoked = std::collections::BTreeSet::new();
            let context = nestlink_identity::offline::OfflineVerification {
                authority: &self.authority_key,
                deployment_id: &claims.deployment_id,
                space_id: &claims.space_id,
                policy_epoch: view.policy_epoch,
                security_epoch: view.security_epoch,
                highest_revocation_epoch: view.highest_revocation_epoch,
                revoked_bundle_ids: &revoked,
                now_ms: wall()?,
            };
            self.lock()?.authority.observe_online(&context)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.stop();
        }
        let mut state = self.lock()?;
        state.paused = false;
        state.wake();
        result
    }
    fn gate<'a>(&'a self, cx: &Context<'_>) -> Poll<io::Result<(MutexGuard<'a, State>, u64)>> {
        let mut state = match self.lock() {
            Ok(s) => s,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let now = match wall() {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Err(e) = state.check(now) {
            return Poll::Ready(Err(e));
        }
        if state.paused {
            if !state.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                state.wakers.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        Poll::Ready(Ok((state, now)))
    }
}
pub(super) struct Metered<S> {
    pub inner: S,
    pub shared: Arc<Shared>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = this.shared.clone();
        let (mut state, now) = match shared.gate(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(v)) => v,
        };
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut bytes = [0u8; 16 * 1024];
        let n = state.remaining().min(buffer.remaining());
        let mut read = ReadBuf::new(&mut bytes[..n]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                if let Err(e) = state.charge(now, read.filled().len()) {
                    return Poll::Ready(Err(e));
                }
                buffer.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = this.shared.clone();
        let (mut state, now) = match shared.gate(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(v)) => v,
        };
        let n = bytes.len().min(state.remaining());
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..n]) {
            Poll::Ready(Ok(n)) => Poll::Ready(state.charge(now, n).map(|()| n)),
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
