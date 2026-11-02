//! Process-local backpressure for independently constructed native SDK clients.
//! This never changes the management server's own queue or authorization gates.
use crate::SdkError;
use reqwest::{Method, StatusCode};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use url::Url;

const ORDINARY_ACTIVE: usize = 4;
const DELETE_ACTIVE: usize = 1;
const ORDINARY_WAITERS: usize = 256;
const DELETE_WAITERS: usize = 32;
const MAX_ORIGINS: usize = 256;
const MAX_ORIGIN_BYTES: usize = 512;

struct Admission {
    ordinary: Arc<Semaphore>,
    deletions: Arc<Semaphore>,
    ordinary_waiters: Arc<Semaphore>,
    delete_waiters: Arc<Semaphore>,
}

/// The active semaphore permit alone cannot keep the weak registry entry alive.
/// Retain this exact gate until the complete HTTP response has been consumed.
pub(super) struct Permit {
    _active: OwnedSemaphorePermit,
    _owner: Arc<Admission>,
}

impl Admission {
    fn new() -> Self {
        Self {
            ordinary: Arc::new(Semaphore::new(ORDINARY_ACTIVE)),
            deletions: Arc::new(Semaphore::new(DELETE_ACTIVE)),
            ordinary_waiters: Arc::new(Semaphore::new(ORDINARY_WAITERS)),
            delete_waiters: Arc::new(Semaphore::new(DELETE_WAITERS)),
        }
    }

    async fn acquire(self: Arc<Self>, deletion: bool) -> Result<Permit, SdkError> {
        let (active, waiting) = if deletion {
            (&self.deletions, &self.delete_waiters)
        } else {
            (&self.ordinary, &self.ordinary_waiters)
        };
        let permit = match active.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::Closed) => return Err(capacity()),
            Err(TryAcquireError::NoPermits) => {
                // No request body, credential or task is handed to the HTTP
                // client until one of these finite waiting slots is admitted.
                let _waiting = waiting
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| capacity())?;
                active
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| capacity())?
            }
        };
        Ok(Permit {
            _active: permit,
            _owner: self,
        })
    }
}

#[derive(Default)]
struct Registry {
    origins: HashMap<String, Weak<Admission>>,
}

impl Registry {
    fn get(&mut self, origin: &Url) -> Result<Arc<Admission>, SdkError> {
        if !matches!(origin.scheme(), "http" | "https") || origin.host_str().is_none() {
            return Err(SdkError::Invalid);
        }
        let key = origin.origin().ascii_serialization();
        if key.len() > MAX_ORIGIN_BYTES {
            return Err(SdkError::Invalid);
        }
        self.origins.retain(|_, owner| owner.strong_count() != 0);
        if let Some(owner) = self.origins.get(&key).and_then(Weak::upgrade) {
            return Ok(owner);
        }
        // A final owner may have dropped after the sweep. Never retain or
        // evict an active gate merely to admit a different origin.
        self.origins.remove(&key);
        if self.origins.len() >= MAX_ORIGINS {
            return Err(capacity());
        }
        let owner = Arc::new(Admission::new());
        self.origins.insert(key, Arc::downgrade(&owner));
        Ok(owner)
    }
}

fn capacity() -> SdkError {
    SdkError::Api(
        StatusCode::TOO_MANY_REQUESTS,
        nestlink_protocol::ErrorCode::CapacityExceeded,
    )
}

pub(super) async fn acquire(origin: &Url, method: &Method) -> Result<Permit, SdkError> {
    static ORIGINS: OnceLock<Mutex<Registry>> = OnceLock::new();
    let owner = ORIGINS
        .get_or_init(|| Mutex::new(Registry::default()))
        .lock()
        .map_err(|_| capacity())?
        .get(origin)?;
    owner.acquire(*method == Method::DELETE).await
}

#[cfg(test)]
mod tests;
