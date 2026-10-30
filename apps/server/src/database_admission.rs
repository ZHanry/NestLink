//! Keep blocking workers bounded while absorbing a short authenticated burst.
//! Waiting happens before spawn_blocking, without holding the Store mutex.
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

const WORKERS: usize = 8;
const WAITERS: usize = 8;
const WAIT_BUDGET: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub(super) struct DatabaseAdmission {
    workers: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl DatabaseAdmission {
    pub(super) fn new() -> Self {
        Self {
            workers: Arc::new(Semaphore::new(WORKERS)),
            waiters: Arc::new(Semaphore::new(WAITERS)),
        }
    }

    pub(super) async fn acquire(&self) -> Result<OwnedSemaphorePermit, ()> {
        match self.workers.clone().try_acquire_owned() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => return Err(()),
            Err(TryAcquireError::NoPermits) => {}
        }
        // The queue itself is bounded. A canceled or expired request drops its
        // queue slot and cannot later enter spawn_blocking or mutate the Store.
        let _waiting = self.waiters.clone().try_acquire_owned().map_err(|_| ())?;
        tokio::time::timeout(WAIT_BUDGET, self.workers.clone().acquire_owned())
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        sync::atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn short_burst_waits_without_starting_a_ninth_database_worker() -> io::Result<()> {
        let admission = DatabaseAdmission::new();
        let mut active = Vec::new();
        for _ in 0..WORKERS {
            active.push(admission.acquire().await.map_err(|_| io::ErrorKind::Other)?);
        }
        let mut next = Box::pin(admission.acquire());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut next)
                .await
                .is_err()
        );
        assert_eq!(admission.workers.available_permits(), 0);
        active.pop();
        let admitted = next.await.map_err(|_| io::ErrorKind::Other)?;
        assert_eq!(admission.workers.available_permits(), 0);
        drop((admitted, active));
        assert_eq!(admission.workers.available_permits(), WORKERS);
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        Ok(())
    }

    #[tokio::test]
    async fn full_wait_queue_rejects_and_cancelled_or_expired_requests_never_execute() -> io::Result<()>
    {
        let admission = DatabaseAdmission::new();
        let mut active = Vec::new();
        for _ in 0..WORKERS {
            active.push(admission.acquire().await.map_err(|_| io::ErrorKind::Other)?);
        }
        let mut queued = Vec::new();
        for _ in 0..WAITERS {
            let mut request = Box::pin(admission.acquire());
            assert!(
                tokio::time::timeout(Duration::from_millis(1), &mut request)
                    .await
                    .is_err()
            );
            queued.push(request);
        }
        assert_eq!(admission.waiters.available_permits(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), admission.acquire())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .is_err()
        );
        // Canceling queued futures must immediately release every admission
        // slot. Their work cannot survive as detached blocking tasks.
        drop(queued);
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        let executed = AtomicBool::new(false);
        let request = async {
            let _permit = admission.acquire().await?;
            executed.store(true, Ordering::Release);
            Ok::<_, ()>(())
        };
        assert!(request.await.is_err());
        drop(active);
        tokio::task::yield_now().await;
        assert!(!executed.load(Ordering::Acquire));
        assert_eq!(admission.workers.available_permits(), WORKERS);
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        Ok(())
    }
}
