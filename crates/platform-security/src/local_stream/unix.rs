use super::*;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use tokio::net::{UnixListener, UnixStream};

pub struct Listener {
    listener: Option<UnixListener>,
    endpoint: PathBuf,
    uid: u32,
    device: u64,
    inode: u64,
    removed: bool,
}
impl Listener {
    pub fn bind(directory: &Path, owner_id: &str) -> io::Result<Self> {
        if !valid_owner_id(owner_id) {
            return Err(denied());
        }
        crate::check_private_directory(directory)?;
        let endpoint = directory.join(format!("stream-{owner_id}.sock"));
        // UnixListener::bind refuses an existing socket/path. Never unlink an
        // endpoint to make startup succeed, even inside a private directory.
        let listener = UnixListener::bind(&endpoint)?;
        let metadata = std::fs::symlink_metadata(&endpoint)?;
        let uid = rustix::process::geteuid().as_raw();
        if !metadata.file_type().is_socket() || metadata.uid() != uid {
            return Err(denied());
        }
        Ok(Self {
            listener: Some(listener),
            endpoint,
            uid,
            device: metadata.dev(),
            inode: metadata.ino(),
            removed: false,
        })
    }
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }
    pub async fn accept(&mut self) -> io::Result<LocalStream> {
        let listener = self.listener.as_ref().ok_or_else(denied)?;
        let (stream, _) = listener.accept().await?;
        // The kernel supplies connected Unix peer credentials. No PID table,
        // client-provided UID or possession of a pathname authenticates a peer.
        if stream.peer_cred()?.uid() != self.uid {
            return Err(denied());
        }
        Ok(LocalStream::new(stream))
    }
    pub fn stop_accepting(&mut self) {
        self.listener.take();
    }
    pub fn cleanup(mut self) -> io::Result<()> {
        self.stop_accepting();
        self.remove_original()
    }
    fn remove_original(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        let parent = self.endpoint.parent().ok_or_else(denied)?;
        crate::check_private_directory(parent)?;
        let metadata = std::fs::symlink_metadata(&self.endpoint)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != self.uid
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(denied());
        }
        std::fs::remove_file(&self.endpoint)?;
        self.removed = true;
        Ok(())
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.stop_accepting();
        let _ = self.remove_original();
    }
}

pub async fn connect(endpoint: &Path) -> io::Result<LocalStream> {
    let parent = endpoint.parent().ok_or_else(denied)?;
    crate::check_private_directory(parent)?;
    let metadata = std::fs::symlink_metadata(endpoint)?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(denied());
    }
    let stream = UnixStream::connect(endpoint).await?;
    if stream.peer_cred()?.uid() != uid {
        return Err(denied());
    }
    Ok(LocalStream::new(stream))
}
