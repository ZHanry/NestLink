//! Cancellation-safe receipts for existing Tokio carrier tasks.
use std::{io, sync::Arc};
use tokio::{
    sync::Mutex,
    task::{AbortHandle, JoinHandle},
    time::Instant,
};

/// A close capability for one task, not another task or socket reader.
/// The join handle remains owned when a caller cancels a wait.
#[derive(Clone)]
pub struct TaskOwner {
    abort: AbortHandle,
    state: Arc<Mutex<State>>,
}
struct State {
    task: Option<JoinHandle<()>>,
    failure: Option<io::ErrorKind>,
}
impl TaskOwner {
    pub fn new(task: JoinHandle<()>) -> Self {
        Self {
            abort: task.abort_handle(),
            state: Arc::new(Mutex::new(State {
                task: Some(task),
                failure: None,
            })),
        }
    }
    pub fn request_close(&self) {
        self.abort.abort();
    }
    pub async fn close_and_wait(&self, deadline: Instant) -> io::Result<()> {
        self.request_close();
        let mut state = tokio::time::timeout_at(deadline, self.state.lock())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        if let Some(task) = state.task.as_mut() {
            let result = tokio::time::timeout_at(deadline, task)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            if result.is_err_and(|error| !error.is_cancelled()) {
                state.failure = Some(io::ErrorKind::Other);
            }
            state.task = None;
        }
        match state.failure {
            Some(kind) => Err(io::Error::new(kind, "carrier task failed during cleanup")),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn timeout_and_cancelled_wait_keep_the_unfinished_task_and_socket_owned() -> io::Result<()>
    {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        // A running blocking task cannot be aborted. The receipt must wait for
        // its real completion rather than interpreting abort() as a join.
        let task = tokio::task::spawn_blocking(move || {
            let _socket = socket;
            let _ = started.send(());
            let _ = blocked.recv();
        });
        ready.await.map_err(io::Error::other)?;
        let owner = TaskOwner::new(task);
        let deadline = Instant::now() + Duration::from_millis(50);
        assert_eq!(
            owner
                .close_and_wait(deadline)
                .await
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(
            std::net::UdpSocket::bind(address)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
        let cancelled = tokio::time::timeout(
            Duration::from_millis(10),
            owner.close_and_wait(Instant::now() + Duration::from_secs(2)),
        )
        .await;
        assert!(cancelled.is_err());
        release.send(()).map_err(io::Error::other)?;
        owner
            .close_and_wait(Instant::now() + Duration::from_secs(2))
            .await?;
        let rebound = std::net::UdpSocket::bind(address)?;
        drop(rebound);
        Ok(())
    }
    #[tokio::test]
    async fn receipt_waits_until_aborted_task_drops_its_real_socket() -> io::Result<()> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _socket = socket;
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.map_err(io::Error::other)?;
        let owner = TaskOwner::new(task);
        assert_eq!(
            std::net::UdpSocket::bind(address)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
        owner
            .close_and_wait(Instant::now() + Duration::from_secs(1))
            .await?;
        let rebound = std::net::UdpSocket::bind(address)?;
        drop(rebound);
        Ok(())
    }
}
