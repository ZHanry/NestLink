//! Scope Quinn's background tasks to one terminal raw-packet owner. QUIC's
//! draining timer depends on RTT; it is not a physical socket cleanup bound.
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::task::JoinSet;

#[derive(Debug)]
pub(super) struct PacketRuntime {
    tasks: Mutex<Option<JoinSet<()>>>,
}
impl PacketRuntime {
    pub(super) fn new() -> Self {
        Self {
            tasks: Mutex::new(Some(JoinSet::new())),
        }
    }
    pub(super) fn stop(&self) -> Option<JoinSet<()>> {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        let mut owned = tasks.take()?;
        // Taking the set fences any concurrent spawn. Dropping the returned set
        // also aborts its tasks if the caller's cleanup future is cancelled.
        owned.abort_all();
        Some(owned)
    }
}
impl Runtime for PacketRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        quinn::TokioRuntime.new_timer(at)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(tasks) = tasks.as_mut() {
            // Reap completed attempts instead of retaining them until stop.
            while tasks.try_join_next().is_some() {}
            tasks.spawn(future);
        }
        // A terminal owner drops late driver futures; it cannot restart I/O.
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
    fn now(&self) -> Instant {
        quinn::TokioRuntime.now()
    }
}
