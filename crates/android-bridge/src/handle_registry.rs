use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub(crate) struct HandleRegistry<T> {
    sessions: Mutex<HashMap<i64, Arc<T>>>,
}

impl<T> Default for HandleRegistry<T> {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> HandleRegistry<T> {
    pub(crate) fn is_empty(&self) -> Result<bool, String> {
        self.sessions
            .lock()
            .map(|sessions| sessions.is_empty())
            .map_err(|_| "Android SDK registry is unavailable".to_owned())
    }

    pub(crate) fn insert(&self, handle: i64, session: Arc<T>) -> Result<(), String> {
        if handle <= 0 {
            return Err("Android SDK handle is invalid".to_owned());
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "Android SDK registry is unavailable".to_owned())?;
        if sessions.contains_key(&handle) {
            return Err("Android SDK handle is already in use".to_owned());
        }
        if !sessions.is_empty() {
            return Err(
                "another Android native handle is active or still awaiting cleanup".to_owned(),
            );
        }
        sessions.insert(handle, session);
        Ok(())
    }

    pub(crate) fn get(&self, handle: i64) -> Result<Arc<T>, String> {
        if handle <= 0 {
            return Err("Android SDK handle is invalid".to_owned());
        }
        self.sessions
            .lock()
            .map_err(|_| "Android SDK registry is unavailable".to_owned())?
            .get(&handle)
            .cloned()
            .ok_or_else(|| "Android SDK session has ended".to_owned())
    }

    pub(crate) fn remove(&self, handle: i64) -> Result<Arc<T>, String> {
        if handle <= 0 {
            return Err("Android SDK handle is invalid".to_owned());
        }
        self.sessions
            .lock()
            .map_err(|_| "Android SDK registry is unavailable".to_owned())?
            .remove(&handle)
            .ok_or_else(|| "Android SDK session has ended".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::HandleRegistry;
    use std::sync::Arc;

    #[test]
    fn removing_a_handle_releases_the_session_and_rejects_stale_lookups() {
        let registry = HandleRegistry::default();
        let session = Arc::new("session".to_owned());

        assert!(registry.insert(7, Arc::clone(&session)).is_ok());
        assert!(
            registry
                .get(7)
                .is_ok_and(|found| Arc::ptr_eq(&found, &session))
        );
        assert!(
            registry
                .remove(7)
                .is_ok_and(|removed| Arc::ptr_eq(&removed, &session))
        );
        assert_eq!(
            registry.get(7).err().as_deref(),
            Some("Android SDK session has ended"),
        );
        assert_eq!(
            registry.remove(7).err().as_deref(),
            Some("Android SDK session has ended"),
        );
    }

    #[test]
    fn registry_rejects_invalid_and_duplicate_handles() {
        let registry = HandleRegistry::default();
        assert_eq!(
            registry.get(0).err().as_deref(),
            Some("Android SDK handle is invalid"),
        );
        assert_eq!(
            registry.remove(-1).err().as_deref(),
            Some("Android SDK handle is invalid"),
        );
        assert_eq!(
            registry.insert(0, Arc::new(())).err().as_deref(),
            Some("Android SDK handle is invalid"),
        );

        assert!(registry.insert(1, Arc::new(())).is_ok());
        assert_eq!(
            registry.insert(1, Arc::new(())).err().as_deref(),
            Some("Android SDK handle is already in use"),
        );
    }

    #[test]
    fn registry_does_not_replace_a_handle_whose_cleanup_is_still_pending() {
        let registry = HandleRegistry::default();
        assert!(registry.insert(1, Arc::new("pending".to_owned())).is_ok());
        assert_eq!(
            registry
                .insert(2, Arc::new("replacement".to_owned()))
                .err()
                .as_deref(),
            Some("another Android native handle is active or still awaiting cleanup"),
        );
        assert!(registry.get(1).is_ok());
    }
}
