//! Bounded whole-packet Unix transport. A partial frame remains decoder state
//! across select cancellation; a failed write permanently closes this owner.
use super::*;
use crate::network_packet_runtime::{WholePacketDevice,PacketIoFuture};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::{UnixStream,unix::{OwnedReadHalf,OwnedWriteHalf}},sync::Mutex};
use std::os::unix::{fs::{MetadataExt,OpenOptionsExt,FileTypeExt},io::AsRawFd};
use std::sync::atomic::{AtomicU64,Ordering};
pub(super) const CONTROL_MAGIC:&[u8]=b"NestLink subnet namespace control v1\n";
pub(super) async fn control_start(reader:&mut (impl tokio::io::AsyncRead+Unpin))->io::Result<()> {
    #[cfg(not(test))]
    {let mut bytes=vec![0_u8;CONTROL_MAGIC.len()];reader.read_exact(&mut bytes).await?;if bytes!=CONTROL_MAGIC {return Err(io::Error::other("subnet worker control preface differs"));}}
    // The source-exact hosted native role uses Rust's test harness. Only test
    // builds permit its bounded stdout preamble before the fixed control magic.
    #[cfg(test)]
    {let mut bytes=Vec::new();loop {bytes.push(reader.read_u8().await?);if bytes.ends_with(CONTROL_MAGIC){break;}if bytes.len()>512 {return Err(io::Error::other("native role preamble exceeded its fixed bound"));}}}
    Ok(())
}

/// Retaining the selected private directory prevents a pathname replacement
/// from redirecting a privileged socket rename or removal.
pub(super) struct SocketDirectory { _directory:std::fs::File,pub path:PathBuf,pub device:u64,pub inode:u64 }
impl SocketDirectory {
    pub fn open(plan:&Plan)->Result<Self> {
        let selected=plan.socket()?;
        let parent=selected.parent().ok_or_else(||io::Error::other("subnet packet socket parent missing"))?;
        let directory=std::fs::OpenOptions::new().read(true).custom_flags((rustix::fs::OFlags::DIRECTORY|rustix::fs::OFlags::NOFOLLOW).bits() as i32).open(parent)?;
        let metadata=directory.metadata()?;
        if !metadata.is_dir()||metadata.uid()!=plan.uid||metadata.mode()&0o077!=0 {return Err(io::Error::other("original owner-private socket directory required").into());}
        let path=PathBuf::from(format!("/proc/self/fd/{}",directory.as_raw_fd())).join(selected.file_name().ok_or_else(||io::Error::other("subnet socket filename missing"))?);
        if path.as_os_str().as_encoded_bytes().len()>100 {return Err(io::Error::other("retained-directory Unix socket path exceeds native bound").into());}
        Ok(Self{_directory:directory,path,device:metadata.dev(),inode:metadata.ino()})
    }
    pub fn matches(&self,receipt:&Receipt)->bool {self.device==receipt.socket_parent_device&&self.inode==receipt.socket_parent_inode}
    pub fn sync(&self)->io::Result<()> {self._directory.sync_all()}
}
pub(super) fn socket_metadata(path:&Path)->Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket()&&metadata.uid()==0=>Ok(Some(metadata)),
        Ok(_)=>Err(io::Error::other("selected root subnet socket was replaced; preserving path").into()),
        Err(error) if error.kind()==io::ErrorKind::NotFound=>Ok(None),
        Err(error)=>Err(error.into()),
    }
}
pub(super) fn remove_socket(path:&Path,receipt:Option<&Receipt>)->Result {
    if let Some(metadata)=socket_metadata(path)? {
        if receipt.is_some_and(|receipt|metadata.dev()!=receipt.socket_device||metadata.ino()!=receipt.socket_inode) {return Err(io::Error::other("root subnet socket identity changed; preserving foreign path").into());}
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub(super) struct Reader {reader:OwnedReadHalf,buffer:Vec<u8>}
impl Reader {
    pub fn new(reader:OwnedReadHalf)->Self {Self{reader,buffer:Vec::new()}}
    pub async fn frame(&mut self)->io::Result<Vec<u8>> {
        loop {
            if self.buffer.len()>=4 {
                let length=u32::from_be_bytes(self.buffer[..4].try_into().map_err(io::Error::other)?) as usize;
                if length==0||length>65_536 {return Err(io::Error::other("subnet frame exceeds the complete-packet bound"));}
                if self.buffer.len()>=length+4 {let packet=self.buffer[4..length+4].to_vec();self.buffer.drain(..length+4);return Ok(packet);}
            }
            let remaining=65_540_usize.checked_sub(self.buffer.len()).filter(|value|*value>0).ok_or_else(||io::Error::other("subnet frame accumulator exhausted"))?;
            let mut incoming=[0_u8;4096];
            let limit=remaining.min(incoming.len());
            let count=self.reader.read(&mut incoming[..limit]).await?;
            if count==0 {return Err(io::Error::new(io::ErrorKind::UnexpectedEof,"original subnet packet pipe ended"));}
            self.buffer.extend_from_slice(&incoming[..count]);
        }
    }
}
pub(super) async fn frame(writer:&mut (impl tokio::io::AsyncWrite+Unpin),packet:&[u8])->io::Result<()> {
    if packet.is_empty()||packet.len()>65_536 {return Err(io::Error::other("bounded complete subnet frame required"));}
    writer.write_all(&(packet.len() as u32).to_be_bytes()).await?;
    writer.write_all(packet).await?;
    writer.flush().await
}
pub(super) async fn message(reader:&mut (impl tokio::io::AsyncRead+Unpin))->io::Result<Vec<u8>> {
    let length=reader.read_u32().await? as usize;
    if length==0||length>65_536 {return Err(io::Error::other("bounded subnet control message required"));}
    let mut bytes=vec![0_u8;length];reader.read_exact(&mut bytes).await?;Ok(bytes)
}
pub(super) fn challenge_frame(value:u64)->[u8;9] {let mut bytes=[0_u8;9];bytes[1..].copy_from_slice(&value.to_be_bytes());bytes}
pub(super) fn challenge(bytes:&[u8])->io::Result<Option<u64>> {
    if bytes.first()!=Some(&0) {return Ok(None);}
    if bytes.len()!=9 {return Err(io::Error::other("invalid bounded subnet observation challenge"));}
    let value=u64::from_be_bytes(bytes[1..].try_into().map_err(io::Error::other)?);
    if value==0 {return Err(io::Error::other("subnet observation challenge cannot be zero"));}Ok(Some(value))
}
pub(super) struct PacketPipe {reader:Mutex<Reader>,writer:Mutex<OwnedWriteHalf>,challenge:AtomicU64,pub receipt:Receipt}
impl PacketPipe {
    pub async fn connect(plan:&Plan)->Result<Self> {
        let stream=UnixStream::connect(plan.socket()?).await?;
        let peer=stream.peer_cred()?;
        if peer.uid()!=0 {return Err(io::Error::other("subnet packet provider must be the separately approved root helper").into());}
        let (reader,writer)=stream.into_split();let mut reader=Reader::new(reader);
        let bytes=tokio::time::timeout(Duration::from_secs(2),reader.frame()).await??;
        let receipt:Receipt=serde_json::from_slice(&bytes)?;
        if receipt.schema_version!=1||receipt.plan_digest!=plan.digest()?||peer.pid()!=i32::try_from(receipt.worker.pid()).ok()||receipt.tun_index==0||receipt.macvlan_index==0||receipt.namespace_inode==0||receipt.namespace_device==0||receipt.socket_device==0||receipt.socket_inode==0||receipt.socket_parent_device==0||receipt.socket_parent_inode==0||plan.wireguard.is_some()!=receipt.wireguard_index.is_some()||receipt.wireguard_index==Some(0) {
            return Err(io::Error::other("root packet receipt differs from the exact original subnet plan").into());
        }
        let first=tokio::time::timeout(Duration::from_secs(2),reader.frame()).await??;
        let challenge=challenge(&first)?.ok_or_else(||io::Error::other("root subnet observation challenge is missing"))?;
        Ok(Self{reader:Mutex::new(reader),writer:Mutex::new(writer),challenge:AtomicU64::new(challenge),receipt})
    }
    /// Called only after the shared original packet owner refresh succeeds.
    /// Echoing an old challenge never moves its root-issued five-second limit.
    pub async fn heartbeat(&self)->io::Result<()> {frame(&mut *self.writer.lock().await,&challenge_frame(self.challenge.load(Ordering::Acquire))).await}
    pub async fn shutdown(&self)->io::Result<()> {self.writer.lock().await.shutdown().await}
}
impl WholePacketDevice for PacketPipe {
    fn recv<'a>(&'a self,packet:&'a mut[u8])->PacketIoFuture<'a> {Box::pin(async move {loop {let bytes=self.reader.lock().await.frame().await?;if let Some(value)=challenge(&bytes)? {self.challenge.store(value,Ordering::Release);continue;}if bytes.len()>packet.len(){return Err(io::Error::other("subnet provider cannot truncate a whole packet"));}packet[..bytes.len()].copy_from_slice(&bytes);return Ok(bytes.len());}})}
    fn send<'a>(&'a self,packet:&'a[u8])->PacketIoFuture<'a> {Box::pin(async move {frame(&mut *self.writer.lock().await,packet).await?;Ok(packet.len())})}
}
