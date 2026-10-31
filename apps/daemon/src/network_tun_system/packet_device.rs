//! The common ordinary-owner boundary is complete IP packets and terminal
//! shutdown. No provider implementation owns login, transport or packet policy.
use super::*;
#[cfg(target_os = "linux")]
type Inner = tun_rs::AsyncDevice;
#[cfg(windows)]
type Inner = nestlink_privileged::windows::network_tun::PacketPipe;

pub(super) struct PacketDevice {
    inner: Option<Inner>,
}
impl PacketDevice {
    #[cfg(target_os = "linux")]
    pub fn linux(device: tun_rs::AsyncDevice) -> Self {
        Self {
            inner: Some(device),
        }
    }
    #[cfg(windows)]
    pub fn windows(pipe: nestlink_privileged::windows::network_tun::PacketPipe) -> Self {
        Self { inner: Some(pipe) }
    }
    pub async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        self.inner
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?
            .recv(packet)
            .await
    }
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.inner
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?
            .send(packet)
            .await
    }
    pub async fn shutdown(&mut self) -> io::Result<()> {
        let Some(inner) = self.inner.take() else {
            return Ok(());
        };
        #[cfg(windows)]
        let result = inner.shutdown().await;
        drop(inner);
        #[cfg(windows)]
        {
            result
        }
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }
    }
}
