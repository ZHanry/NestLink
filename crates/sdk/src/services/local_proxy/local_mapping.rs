//! One authenticated SOCKS control connection owns one exact local UDP mapping.
//! SOCKS wire parsing and framing remain entirely in fast-socks5. Neither the
//! association request nor a datagram can choose an outbound socket destination.
use super::*;
use fast_socks5::{new_udp_header, parse_udp_request};
use nestlink_node::service_plane::DatagramPacket;
use tokio::{io::AsyncReadExt, net::UdpSocket};

/// Zero-length packets consume an event even though their payload costs zero
/// bytes. This is a local CPU/work cap, not a second service byte allowance.
const MAX_DATAGRAM_EVENTS: u64 = 8192;
const LOCAL_SEND_BUDGET: Duration = Duration::from_millis(250);
const UDP_RECEIVE_BYTES: usize = 65_536;

fn association_peer(target: &TargetAddr, tcp_peer: SocketAddr) -> Option<SocketAddr> {
    match target {
        TargetAddr::Ip(peer)
            if peer.ip().is_loopback() && peer.ip() == tcp_peer.ip() && peer.port() != 0 =>
        {
            Some(*peer)
        }
        _ => None,
    }
}

async fn admitted_packet<'a>(
    choice: &LocalProxyServiceChoice,
    expected: SocketAddr,
    source: SocketAddr,
    packet: &'a [u8],
) -> Option<&'a [u8]> {
    if source != expected || !source.ip().is_loopback() {
        return None;
    }
    let (fragment, target, payload) = parse_udp_request(packet).await.ok()?;
    (fragment == 0 && choice.accepts(&target) && payload.len() <= DatagramPacket::MAX_PAYLOAD)
        .then_some(payload)
}

struct LocalDatagramBudget {
    bytes: u64,
    events: u64,
    maximum_bytes: u64,
}
impl LocalDatagramBudget {
    fn observe_event(&mut self) -> bool {
        self.events = self.events.saturating_add(1);
        self.events <= MAX_DATAGRAM_EVENTS
    }
    fn admit_bytes(&mut self, length: usize) -> bool {
        let Some(next) = self
            .bytes
            .checked_add(length as u64)
            .filter(|next| *next <= self.maximum_bytes)
        else {
            return false;
        };
        self.bytes = next;
        true
    }
}

async fn authenticate_association(
    socket: TcpStream,
    credentials: &Credentials,
) -> Result<(Command, SocketAddr), ()> {
    let tcp_peer = socket.peer_addr().map_err(|_| ())?;
    let (authenticated, _) =
        Socks5ServerProtocol::accept_password_auth(socket, |username, password| {
            credentials.accepts(username, password)
        })
        .await
        .map_err(|_| ())?;
    let (protocol, command, target) = authenticated.read_command().await.map_err(|_| ())?;
    if command != Socks5Command::UDPAssociate {
        let _ = protocol.reply_error(&ReplyError::CommandNotSupported).await;
        return Err(());
    }
    let Some(peer) = association_peer(&target, tcp_peer) else {
        let _ = protocol
            .reply_error(&ReplyError::ConnectionNotAllowed)
            .await;
        return Err(());
    };
    Ok((protocol, peer))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_flow(
    sdk: Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    choice: Arc<LocalProxyServiceChoice>,
    credentials: Arc<Credentials>,
    socket: TcpStream,
    mut stop: watch::Receiver<bool>,
    owner_deadline: Instant,
) -> FlowOutcome {
    let setup_deadline = (Instant::now() + SETUP_BUDGET).min(owner_deadline);
    let local_address = match socket.local_addr() {
        Ok(address) => SocketAddr::new(address.ip(), 0),
        Err(_) => {
            return FlowOutcome {
                failed: true,
                ..FlowOutcome::default()
            };
        }
    };
    let setup = async {
        let (protocol, peer) = authenticate_association(socket, &credentials).await?;
        let udp = match UdpSocket::bind(local_address).await {
            Ok(udp) => udp,
            Err(_) => {
                let _ = protocol.reply_error(&ReplyError::GeneralFailure).await;
                return Err(());
            }
        };
        let request = choice.access_request(&consumer).map_err(|_| ())?;
        let lease = match sdk
            .request_private_service(&choice.entry.service.id, request)
            .await
        {
            Ok(lease) if choice.checks_lease(&lease) => lease,
            _ => {
                let _ = protocol
                    .reply_error(&ReplyError::ConnectionNotAllowed)
                    .await;
                return Err(());
            }
        };
        Ok((protocol, peer, udp, lease))
    };
    let (protocol, peer, udp, lease) = tokio::select! { biased;
        _ = stopping(&mut stop) => return FlowOutcome::default(),
        result = tokio::time::timeout_at(setup_deadline, setup) => match result {
            Ok(Ok(value)) => value,
            _ => return FlowOutcome { rejected: true, ..FlowOutcome::default() },
        }
    };
    let connecting =
        sdk.connect_private_service_with_relay_policy(&consumer, lease, &choice.relay_policy);
    tokio::pin!(connecting);
    let connected = tokio::select! { biased;
        _ = stopping(&mut stop) => None,
        _ = tokio::time::sleep_until(setup_deadline) => None,
        result = &mut connecting => Some(result),
    };
    let mut connection = match connected {
        Some(Ok(connection)) => connection,
        Some(Err(_)) => {
            let _ = tokio::time::timeout_at(
                setup_deadline,
                protocol.reply_error(&ReplyError::GeneralFailure),
            )
            .await;
            return FlowOutcome {
                failed: true,
                cleanup_failed: true,
                ..FlowOutcome::default()
            };
        }
        None => {
            drop(protocol);
            drop(udp);
            let cleanup_failed = match connecting.await {
                Ok(mut connection) => connection.close().await.is_err(),
                Err(_) => true,
            };
            return FlowOutcome {
                cleanup_failed,
                ..FlowOutcome::default()
            };
        }
    };
    let relay_address = match udp.local_addr() {
        Ok(address) => address,
        Err(_) => {
            let _ = tokio::time::timeout_at(
                setup_deadline,
                protocol.reply_error(&ReplyError::GeneralFailure),
            )
            .await;
            drop(udp);
            return FlowOutcome {
                failed: true,
                cleanup_failed: connection.close().await.is_err(),
                ..FlowOutcome::default()
            };
        }
    };
    let ready = tokio::select! { biased;
        _ = stopping(&mut stop) => None,
        result = tokio::time::timeout_at(setup_deadline, protocol.reply_success(relay_address)) => result.ok().and_then(Result::ok),
    };
    let mut outcome = FlowOutcome::default();
    if let Some(control) = ready {
        outcome = forward_association(
            control,
            udp,
            peer,
            &choice,
            &mut connection,
            &mut stop,
            owner_deadline,
        )
        .await;
    } else {
        drop(udp);
    }
    outcome.cleanup_failed |= connection.close().await.is_err();
    outcome
}

enum DatagramEvent {
    Local(io::Result<(usize, SocketAddr)>),
    Private(Result<Vec<u8>, SdkError>),
}

#[allow(clippy::too_many_arguments)]
async fn forward_association(
    mut control: TcpStream,
    udp: UdpSocket,
    peer: SocketAddr,
    choice: &LocalProxyServiceChoice,
    connection: &mut PrivateServiceConnection,
    stop: &mut watch::Receiver<bool>,
    owner_deadline: Instant,
) -> FlowOutcome {
    let mut outcome = FlowOutcome::default();
    let mut buffer = vec![0_u8; UDP_RECEIVE_BYTES];
    let mut control_byte = [0_u8; 1];
    let lease = connection.lease().clone();
    let expired = authority_expired(&lease);
    tokio::pin!(expired);
    let idle = Duration::from_secs(u64::from(
        choice.entry.service.definition.limits.idle_timeout_seconds,
    ));
    let mut idle_deadline = Instant::now() + idle;
    let mut budget = LocalDatagramBudget {
        bytes: 0,
        events: 0,
        maximum_bytes: choice.maximum_bytes,
    };
    let response_header = match new_udp_header((choice.alias.as_str(), choice.port)) {
        Ok(header) => header,
        Err(_) => {
            return FlowOutcome {
                failed: true,
                ..FlowOutcome::default()
            };
        }
    };
    loop {
        // receive_datagram borrows the connection only inside this select. Its
        // cancellation-safe Quinn receive releases the borrow before send below.
        let data = async {
            tokio::select! {
                result = udp.recv_from(&mut buffer) => DatagramEvent::Local(result),
                result = connection.receive_datagram() => DatagramEvent::Private(result),
            }
        };
        let event = tokio::select! { biased;
            _ = stopping(stop) => break,
            _ = tokio::time::sleep_until(owner_deadline.min(idle_deadline)) => break,
            _ = &mut expired => break,
            _ = control.read(&mut control_byte) => break,
            event = data => event,
        };
        if !budget.observe_event() {
            outcome.discarded_datagrams += 1;
            break;
        }
        match event {
            DatagramEvent::Local(Ok((size, source))) => {
                let Some(payload) = admitted_packet(choice, peer, source, &buffer[..size]).await
                else {
                    outcome.discarded_datagrams += 1;
                    continue;
                };
                if !budget.admit_bytes(payload.len()) {
                    outcome.discarded_datagrams += 1;
                    break;
                }
                if lease.check_time(wall_ms().unwrap_or(0)).is_err() {
                    break;
                }
                if connection.send_datagram(payload).is_err() {
                    outcome.failed = true;
                    break;
                }
                outcome.forwarded_datagrams += 1;
                idle_deadline = Instant::now() + idle;
            }
            DatagramEvent::Private(Ok(payload)) => {
                if payload.len() > DatagramPacket::MAX_PAYLOAD {
                    outcome.discarded_datagrams += 1;
                    continue;
                }
                if !budget.admit_bytes(payload.len()) {
                    outcome.discarded_datagrams += 1;
                    break;
                }
                if lease.check_time(wall_ms().unwrap_or(0)).is_err() {
                    break;
                }
                let mut packet = response_header.clone();
                packet.extend_from_slice(&payload);
                let send_deadline = (Instant::now() + LOCAL_SEND_BUDGET)
                    .min(owner_deadline)
                    .min(idle_deadline);
                let sent = tokio::select! { biased;
                    _ = stopping(stop) => break,
                    _ = &mut expired => break,
                    result = tokio::time::timeout_at(send_deadline, udp.send_to(&packet, peer)) => result,
                };
                if !matches!(sent, Ok(Ok(size)) if size == packet.len()) {
                    outcome.failed = true;
                    break;
                }
                outcome.forwarded_datagrams += 1;
                idle_deadline = Instant::now() + idle;
            }
            DatagramEvent::Local(Err(_)) | DatagramEvent::Private(Err(_)) => {
                outcome.failed = true;
                break;
            }
        }
    }
    // Socket/stream drops happen before the caller joins private carrier close.
    drop(control);
    drop(udp);
    outcome
}

#[cfg(test)]
mod tests;
