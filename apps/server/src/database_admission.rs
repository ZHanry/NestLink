//! Keep blocking workers bounded while absorbing a short authenticated burst.
//! Waiting happens before spawn_blocking, without holding the Store mutex.
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

const WORKERS: usize = 8;
const REVOCATION_WORKERS: usize = 1;
const ORDINARY_WORKERS: usize = WORKERS - REVOCATION_WORKERS;
const WAITERS: usize = 8;
const WAIT_BUDGET: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub(super) struct DatabaseAdmission {
    workers: Arc<Semaphore>,
    revocations: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl DatabaseAdmission {
    pub(super) fn new() -> Self {
        Self {
            workers: Arc::new(Semaphore::new(ORDINARY_WORKERS)),
            revocations: Arc::new(Semaphore::new(REVOCATION_WORKERS)),
            waiters: Arc::new(Semaphore::new(WAITERS)),
        }
    }

    pub(super) async fn acquire(&self) -> Result<OwnedSemaphorePermit, ()> {
        self.acquire_from(&self.workers).await
    }

    /// Ordinary polling cannot consume the final worker needed to revoke its
    /// authority. This lane still authenticates in the database operation and
    /// shares the same bounded waiting slots and deadline as ordinary work.
    pub(super) async fn acquire_revocation(&self) -> Result<OwnedSemaphorePermit, ()> {
        self.acquire_from(&self.revocations).await
    }

    async fn acquire_from(&self, workers: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, ()> {
        match workers.clone().try_acquire_owned() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => return Err(()),
            Err(TryAcquireError::NoPermits) => {}
        }
        // The queue itself is bounded. A canceled or expired request drops its
        // queue slot and cannot later enter spawn_blocking or mutate the Store.
        let _waiting = self.waiters.clone().try_acquire_owned().map_err(|_| ())?;
        tokio::time::timeout(WAIT_BUDGET, workers.clone().acquire_owned())
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    /// Background maintenance skips a busy tick instead of consuming an
    /// authenticated request's bounded waiting slot.
    pub(super) fn try_acquire(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.workers.clone().try_acquire_owned()
    }

    #[cfg(test)]
    pub(super) fn close(&self) {
        self.workers.close();
        self.revocations.close();
        self.waiters.close();
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
    async fn ordinary_burst_waits_without_consuming_the_reserved_revocation_worker()
    -> io::Result<()> {
        let admission = DatabaseAdmission::new();
        let mut active = Vec::new();
        for _ in 0..ORDINARY_WORKERS {
            active.push(
                admission
                    .acquire()
                    .await
                    .map_err(|_| io::ErrorKind::Other)?,
            );
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
        assert_eq!(admission.workers.available_permits(), ORDINARY_WORKERS);
        assert_eq!(
            admission.revocations.available_permits(),
            REVOCATION_WORKERS
        );
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        Ok(())
    }

    #[tokio::test]
    async fn full_wait_queue_rejects_and_cancelled_or_expired_requests_never_execute()
    -> io::Result<()> {
        let admission = DatabaseAdmission::new();
        let mut active = Vec::new();
        for _ in 0..ORDINARY_WORKERS {
            active.push(
                admission
                    .acquire()
                    .await
                    .map_err(|_| io::ErrorKind::Other)?,
            );
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
        assert_eq!(admission.workers.available_permits(), ORDINARY_WORKERS);
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        Ok(())
    }

    #[tokio::test]
    async fn revocation_survives_full_ordinary_capacity_without_a_ninth_worker_or_extra_waiters()
    -> io::Result<()> {
        let admission = DatabaseAdmission::new();
        let mut ordinary = Vec::new();
        for _ in 0..ORDINARY_WORKERS {
            ordinary.push(
                admission
                    .acquire()
                    .await
                    .map_err(|_| io::ErrorKind::Other)?,
            );
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
        let revocation = admission
            .acquire_revocation()
            .await
            .map_err(|_| io::ErrorKind::Other)?;
        assert_eq!(ordinary.len() + 1, WORKERS);
        assert_eq!(admission.workers.available_permits(), 0);
        assert_eq!(admission.revocations.available_permits(), 0);
        assert_eq!(admission.waiters.available_permits(), 0);
        assert!(admission.acquire().await.is_err());
        assert!(admission.acquire_revocation().await.is_err());
        assert!(admission.try_acquire().is_err());
        drop(queued);
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        let executed = AtomicBool::new(false);
        let request = async {
            let _permit = admission.acquire_revocation().await?;
            executed.store(true, Ordering::Release);
            Ok::<_, ()>(())
        };
        assert!(request.await.is_err());
        let mut cancelled = Box::pin(admission.acquire_revocation());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut cancelled)
                .await
                .is_err()
        );
        assert_eq!(admission.waiters.available_permits(), WAITERS - 1);
        drop(cancelled);
        assert_eq!(admission.waiters.available_permits(), WAITERS);
        drop((revocation, ordinary));
        tokio::task::yield_now().await;
        assert!(!executed.load(Ordering::Acquire));
        assert_eq!(admission.workers.available_permits(), ORDINARY_WORKERS);
        assert_eq!(
            admission.revocations.available_permits(),
            REVOCATION_WORKERS
        );
        Ok(())
    }
}
