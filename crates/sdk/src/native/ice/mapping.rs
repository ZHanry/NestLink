//! A bounded mapping lease attached to the existing ICE owner, without another
//! data socket or receiver. Failed creation retains cleanup authority by nonce.
use super::*;
use nestlink_traversal::pcp_mapping::PcpMapping;
use nestlink_transport_stream::owner::TaskOwner;
use std::{net::Ipv4Addr, sync::atomic::AtomicBool};

pub(crate) struct MappingOwner {
    state: Arc<tokio::sync::Mutex<PcpMapping>>,
    task: Option<TaskOwner>,
    close_deadline: Mutex<Option<TokioInstant>>,
    closed: AtomicBool,
}

impl MappingOwner {
    /// Call only after local consent and deployment allow_pcp both succeed.
    /// The caller retains the actual business socket used by local.
    pub(crate) fn new(
        gateway: Ipv4Addr,
        local: SocketAddr,
        authorization_deadline: Instant,
    ) -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(tokio::sync::Mutex::new(PcpMapping::new(
                gateway, local, authorization_deadline,
            )?)),
            task: None,
            close_deadline: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    /// Retain this MappingOwner outside a cancelable/timeout establish future.
    /// A failed mapping cannot silently publish a host or guessed candidate.
    pub(crate) async fn establish(&self, policy: &AddressPolicy) -> io::Result<SocketAddr> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let address = self.state.lock().await.establish_or_renew().await?;
        if !safe_peer_address(address.ip()) || !policy.allows(address.ip()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(address)
    }

    /// Keep the original signed tuple. A gateway changing its external tuple,
    /// refusing renewal, or passing the original deadline terminates the agent.
    /// Re-establishment requires the normal fresh signaling/business workflow.
    pub(crate) fn start(&mut self, agent: Arc<Agent>) -> io::Result<()> {
        if self.task.is_some() || self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let state = self.state.clone();
        self.task = Some(TaskOwner::new(tokio::spawn(async move {
            loop {
                let next = state.lock().await.renewal_deadline();
                let Ok(next) = next else {
                    let _ = agent.close().await;
                    return;
                };
                tokio::time::sleep_until(TokioInstant::from_std(next)).await;
                let renewed = state.lock().await.establish_or_renew().await;
                if renewed.is_err() {
                    let _ = agent.close().await;
                    return;
                }
            }
        })));
        Ok(())
    }

    pub(crate) fn request_close(&self) {
        if let Some(task) = &self.task {
            task.request_close();
        }
    }

    /// Wait for the original renewal task, then the exact nonce deletion ACK.
    /// Timeout/cancellation preserves state so a caller can retry the receipt.
    pub(crate) async fn close_and_wait(&self, deadline: TokioInstant) -> io::Result<()> {
        let deadline = *self.close_deadline.lock()
            .map_err(|_| io::Error::other("PCP cleanup owner poisoned"))?
            .get_or_insert(deadline);
        self.request_close();
        if let Some(task) = &self.task {
            task.close_and_wait(deadline).await?;
        }
        let mut state = tokio::time::timeout_at(deadline, self.state.lock()).await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        tokio::time::timeout_at(deadline, state.release()).await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for MappingOwner {
    fn drop(&mut self) {
        self.request_close();
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        // Best effort only. Successful release is reported exclusively through
        // close_and_wait. A crash cannot keep renewing a lease after exit.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let state = self.state.clone();
            let task = self.task.clone();
            let deadline = self.close_deadline.lock().ok().and_then(|value| *value)
                .unwrap_or_else(|| TokioInstant::now() + Duration::from_secs(2));
            runtime.spawn(async move {
                if let Some(task) = task {
                    let _ = task.close_and_wait(deadline).await;
                }
                if let Ok(mut state) = tokio::time::timeout_at(deadline, state.lock()).await {
                    let _ = tokio::time::timeout_at(deadline, state.release()).await;
                }
            });
        }
    }
}
