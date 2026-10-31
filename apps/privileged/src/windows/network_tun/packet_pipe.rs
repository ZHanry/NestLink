#![allow(unsafe_code)]
use super::super::{
    local_port_gate::{ProcessIdentity, store, wall_ms},
    security,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    mem::size_of,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
    sync::Mutex,
};
use windows_sys::Win32::{
    Security::SECURITY_ATTRIBUTES, System::Pipes::GetNamedPipeServerProcessId,
};

const MAX_PACKET: usize = 1280;
const HELLO: &[u8; 8] = b"NLTUN/01";
const IO_BUDGET: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketBinding {
    pub schema_version: u16,
    pub owner_id: String,
    pub plan_sha256: [u8; 32],
    pub process: ProcessIdentity,
    pub expires_at_ms: u64,
}
impl PacketBinding {
    pub fn check_current_owner(&self) -> io::Result<()> {
        if self.schema_version != 1
            || !nestlink_protocol::valid_id(&self.owner_id)
            || self.plan_sha256 == [0; 32]
            || !self.process.normal()
            || wall_ms()? >= self.expires_at_ms
            || ProcessIdentity::read(self.process.pid)? != self.process
        {
            return Err(security::denied());
        }
        Ok(())
    }
    fn endpoint(&self) -> io::Result<PathBuf> {
        if !nestlink_protocol::valid_id(&self.owner_id) {
            return Err(security::denied());
        }
        Ok(PathBuf::from(format!(
            r"\\.\pipe\NestLink.NetworkTun.{}",
            self.owner_id
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub adapter_guid: String,
    pub name: String,
    pub luid: u64,
    pub index: u32,
    pub mtu: u16,
    pub provider_sha256: [u8; 32],
    pub configuration_sha256: [u8; 32],
}
impl ProviderIdentity {
    fn validate(&self) -> io::Result<()> {
        if !nestlink_protocol::valid_id(&self.adapter_guid)
            || self.name != format!("NestLink-{}", self.adapter_guid)
            || self.luid == 0
            || self.index == 0
            || self.mtu != MAX_PACKET as u16
            || self.provider_sha256 == [0; 32]
            || self.configuration_sha256 == [0; 32]
        {
            return Err(security::denied());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketReceipt {
    pub schema_version: u16,
    pub binding: PacketBinding,
    pub helper: ProcessIdentity,
    pub provider: ProviderIdentity,
}
impl PacketReceipt {
    pub fn read_for_current_process(path: &Path, expected: &PacketBinding) -> io::Result<Self> {
        let parents = store::Parents::open(path.parent().ok_or_else(security::denied)?)?;
        let bytes = parents.read(path.file_name().ok_or_else(security::denied)?, false)?;
        let receipt: Self = serde_json::from_slice(&bytes)?;
        receipt.check_current(expected)?;
        Ok(receipt)
    }
    pub fn check_current(&self, expected: &PacketBinding) -> io::Result<()> {
        expected.check_current_owner()?;
        self.provider.validate()?;
        if self.schema_version != 1
            || self.binding != *expected
            || self.binding.process.pid != std::process::id()
            || !self.helper.administrator()
            || !self.helper.same_image(&expected.process)
            || self.helper.pid == expected.process.pid
        {
            return Err(security::denied());
        }
        self.helper.helper_alive()
    }
    pub async fn connect(&self) -> io::Result<PacketPipe> {
        self.check_current(&self.binding)?;
        let pipe = ClientOptions::new()
            .security_qos_flags(0x0001_0000)
            .open(self.binding.endpoint()?)?;
        let mut server = 0_u32;
        // The protected receipt supplies the high-token attestation. The OS
        // supplies the actual server PID; a medium process need not open an
        // administrator token just to authenticate this already attested PID.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut server) } == 0
            || server != self.helper.pid
        {
            return Err(security::denied());
        }
        self.helper.helper_alive()?;
        let mut pipe = pipe;
        handshake(&mut pipe, &self.binding, true).await?;
        self.check_current(&self.binding)?;
        Ok(PacketPipe::new(pipe))
    }
}

/// The server retains the original normal process handle and protected image
/// lock. The provider helper must keep it until all packet I/O has stopped.
pub struct PacketServer {
    pipe: Option<NamedPipeServer>,
    original: security::Peer,
    receipt: PacketReceipt,
    _image: store::ImageLock,
}
impl PacketServer {
    pub fn bind(binding: PacketBinding, provider: ProviderIdentity) -> io::Result<Self> {
        super::super::require_administrator_process()?;
        binding.check_current_owner()?;
        provider.validate()?;
        let original = security::Peer::open(binding.process.pid)?;
        let helper = ProcessIdentity::read(std::process::id())?;
        let image = store::lock_image(&binding.process.image)?;
        if !helper.administrator()
            || !helper.same_image(&binding.process)
            || image.identity != (binding.process.image_volume, binding.process.image_index)
            || !original.is_normal()
        {
            return Err(security::denied());
        }
        let descriptor = security::pipe_security(&binding.process.sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // Tokio owns the one overlapped handle and copies the fixed descriptor.
        let pipe = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .max_instances(1)
                .in_buffer_size((MAX_PACKET + 2) as u32)
                .out_buffer_size((MAX_PACKET + 2) as u32)
                .create_with_security_attributes_raw(
                    binding.endpoint()?,
                    (&attributes as *const SECURITY_ATTRIBUTES)
                        .cast_mut()
                        .cast(),
                )
        }?;
        let receipt = PacketReceipt {
            schema_version: 1,
            binding,
            helper,
            provider,
        };
        Ok(Self {
            pipe: Some(pipe),
            original,
            receipt,
            _image: image,
        })
    }
    /// The caller must durably journal this exact receipt before publication.
    /// A crash before publish is therefore recoverable as actual file absence.
    pub fn publish_receipt(&self, receipt_path: &Path) -> io::Result<()> {
        self.check_current()?;
        let parents = store::Parents::open(receipt_path.parent().ok_or_else(security::denied)?)?;
        parents.write(
            receipt_path.file_name().ok_or_else(security::denied)?,
            &serde_json::to_vec(&self.receipt)?,
            Some(&self.receipt.binding.process.sid),
            false,
        )
    }
    pub fn check_current(&self) -> io::Result<()> {
        self.original.alive()?;
        self.receipt.binding.check_current_owner()
    }
    pub fn receipt(&self) -> &PacketReceipt {
        &self.receipt
    }
    pub async fn accept(&mut self) -> io::Result<PacketPipe> {
        self.check_current()?;
        let original = &self.original;
        let binding = &self.receipt.binding;
        let pipe = self.pipe.as_mut().ok_or_else(security::denied)?;
        {
            let connect = tokio::time::timeout(Duration::from_secs(10), pipe.connect());
            tokio::pin!(connect);
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {biased;
                    _=tick.tick()=>{original.alive()?;binding.check_current_owner()?;},
                    result=&mut connect=>{result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut))??;break;},
                }
            }
        }
        let peer = security::pipe_peer(pipe.as_raw_handle().cast(), true)?;
        if peer.pid != self.original.pid
            || peer.creation != self.original.creation
            || !peer.is_normal()
            || !peer.same_login(&self.original)
            || !security::same_image(&peer.image, &self.original.image)
            || ProcessIdentity::read(peer.pid)? != self.receipt.binding.process
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TUN packet pipe client is not the original admitted ordinary process",
            ));
        }
        handshake(pipe, &self.receipt.binding, false).await?;
        self.check_current()?;
        Ok(PacketPipe::new(
            self.pipe.take().ok_or_else(security::denied)?,
        ))
    }
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    binding: &PacketBinding,
    client: bool,
) -> io::Result<()> {
    let mut hello = [0_u8; 40];
    hello[..8].copy_from_slice(HELLO);
    hello[8..].copy_from_slice(&binding.plan_sha256);
    let mut received = [0_u8; 40];
    tokio::time::timeout(Duration::from_secs(2), async {
        if client {
            stream.write_all(&hello).await?;
            stream.read_exact(&mut received).await?;
        } else {
            stream.read_exact(&mut received).await?;
            if received != hello {
                return Err(security::denied());
            }
            stream.write_all(&hello).await?;
        }
        if received != hello {
            return Err(security::denied());
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

trait StreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> StreamIo for T {}
type Stream = Box<dyn StreamIo>;
struct Reader {
    stream: ReadHalf<Stream>,
    header: [u8; 2],
    header_read: usize,
    packet: Vec<u8>,
    packet_read: usize,
}
impl Reader {
    async fn recv(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.header_read < 2 {
            let read = self
                .stream
                .read(&mut self.header[self.header_read..])
                .await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.header_read += read;
        }
        let length = usize::from(u16::from_be_bytes(self.header));
        if !(20..=MAX_PACKET).contains(&length) || output.len() < length {
            return Err(security::denied());
        }
        if self.packet.is_empty() {
            self.packet.resize(length, 0);
        }
        while self.packet_read < length {
            let read = self
                .stream
                .read(&mut self.packet[self.packet_read..])
                .await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.packet_read += read;
        }
        output[..length].copy_from_slice(&self.packet);
        self.header_read = 0;
        self.packet.clear();
        self.packet_read = 0;
        Ok(length)
    }
}
pub struct PacketPipe {
    read: Mutex<Reader>,
    write: Mutex<WriteHalf<Stream>>,
    stopped: AtomicBool,
}
impl PacketPipe {
    fn new(stream: impl StreamIo + 'static) -> Self {
        let stream: Stream = Box::new(stream);
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(Reader {
                stream: read,
                header: [0; 2],
                header_read: 0,
                packet: Vec::new(),
                packet_read: 0,
            }),
            write: Mutex::new(write),
            stopped: AtomicBool::new(false),
        }
    }
    pub async fn recv(&self, output: &mut [u8]) -> io::Result<usize> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(security::denied());
        }
        let result = self.read.lock().await.recv(output).await;
        if result.is_err() {
            self.stopped.store(true, Ordering::Release);
        }
        result
    }
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        if self.stopped.load(Ordering::Acquire) || !(20..=MAX_PACKET).contains(&packet.len()) {
            return Err(security::denied());
        }
        struct InFlight<'a> {
            stopped: &'a AtomicBool,
            complete: bool,
        }
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                if !self.complete {
                    self.stopped.store(true, Ordering::Release);
                }
            }
        }
        let mut flight = InFlight {
            stopped: &self.stopped,
            complete: false,
        };
        let mut frame = Vec::with_capacity(packet.len() + 2);
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        tokio::time::timeout(IO_BUDGET, async {
            let mut writer = self.write.lock().await;
            if self.stopped.load(Ordering::Acquire) {
                return Err(security::denied());
            }
            writer.write_all(&frame).await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        flight.complete = true;
        Ok(packet.len())
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        self.stopped.store(true, Ordering::Release);
        tokio::time::timeout(IO_BUDGET, async {
            self.write.lock().await.shutdown().await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounded_packet_reader_retains_partial_header_and_body_across_cancellation()
    -> io::Result<()> {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let pipe = PacketPipe::new(reader);
        let packet = vec![17_u8; 1280];
        let mut output = vec![0_u8; 65_536];
        writer.write_all(&[5]).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pipe.recv(&mut output))
                .await
                .is_err()
        );
        writer.write_all(&[0]).await?;
        writer.write_all(&packet[..700]).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pipe.recv(&mut output))
                .await
                .is_err()
        );
        writer.write_all(&packet[700..]).await?;
        assert_eq!(pipe.recv(&mut output).await?, 1280);
        assert_eq!(&output[..1280], packet);
        writer.write_all(&[0, 20]).await?;
        writer.write_all(&[9; 20]).await?;
        assert_eq!(pipe.recv(&mut output).await?, 20);
        assert_eq!(&output[..20], [9; 20]);
        Ok(())
    }
    #[tokio::test]
    async fn invalid_frame_and_cancelled_write_are_terminal() -> io::Result<()> {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let pipe = PacketPipe::new(reader);
        writer.write_all(&[255, 255]).await?;
        assert!(pipe.recv(&mut [0; 1280]).await.is_err());
        assert!(pipe.send(&[1; 20]).await.is_err());
        let (_not_reading, writer) = tokio::io::duplex(16);
        let pipe = PacketPipe::new(writer);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pipe.send(&[1; 1280]))
                .await
                .is_err()
        );
        assert!(pipe.send(&[1; 20]).await.is_err());
        Ok(())
    }
}
