//! Shared integration-fixture ownership for a real private SQLite usage ledger.
//! Never unlink a live store: cleanup tokens observe the post-Connection drop
//! sentinel, including detached reporters and outstanding publication permits.
use nestlink_node::{control::NodeControl, service_usage::ServiceUsageCleanup};
use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct ServiceUsageDirectory {
    root: PathBuf,
    ledger: PathBuf,
    cleanups: Vec<ServiceUsageCleanup>,
    observation_failed: bool,
}

impl ServiceUsageDirectory {
    pub fn new() -> io::Result<Self> {
        let parent = std::env::var_os("NESTLINK_NODE_TEST_USAGE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let parent = std::fs::canonicalize(parent)?;
        let root = parent.join(format!("nestlink-node-test-usage-{}", uuid::Uuid::new_v4()));
        nestlink_platform_security::new_private_directory(&root)?;
        // The production store creates this child and verifies its parent.
        let ledger = root.join("ledger");
        Ok(Self {
            root,
            ledger,
            cleanups: Vec::new(),
            observation_failed: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.ledger
    }

    pub fn track(&mut self, control: &NodeControl) -> io::Result<()> {
        match control.service_usage_cleanup() {
            Ok(cleanup) => self.cleanups.push(cleanup),
            Err(error) => {
                // A live owner was supplied but its close could not be
                // observed. Preserve the directory even during test unwind.
                self.observation_failed = true;
                return Err(io::Error::other(error));
            }
        }
        Ok(())
    }
}

impl Drop for ServiceUsageDirectory {
    fn drop(&mut self) {
        if self.observation_failed {
            return;
        }
        if self.cleanups.iter().all(ServiceUsageCleanup::is_finished) {
            let _ = std::fs::remove_dir_all(&self.root);
            return;
        }
        let root = self.root.clone();
        let cleanups = std::mem::take(&mut self.cleanups);
        // A Tokio test may use a single worker. Keep Drop nonblocking so the
        // real control/report tasks can release their SQLite owners, and also
        // allow runtime destruction to finish canceled workers on test failure.
        let _ = std::thread::Builder::new()
            .name("node-usage-fixture-cleanup".into())
            .spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if cleanups.iter().all(ServiceUsageCleanup::is_finished) {
                        let _ = std::fs::remove_dir_all(&root);
                        return;
                    }
                    if Instant::now() >= deadline {
                        // The outer Cargo wrapper owns the scratch parent and
                        // can reclaim it after the entire test process exits.
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
        // Failure to spawn retains the private directory for the same wrapper.
    }
}
