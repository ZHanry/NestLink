#![allow(unsafe_code)]
use super::{
    consent,
    installation::{self, Installation},
    security::{self, Peer},
};
use crate::{
    BrokerGate, TrustPins,
    wire::{self, BrokerError, Command, Reply, ReplyValue, Request, Stamp},
};
use clap::Parser;
use nestlink_platform_input::WindowsInput;
use nestlink_platform_session::WindowsSessionSnapshot;
use std::{
    io,
    mem::size_of,
    os::windows::io::AsRawHandle,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

#[derive(Parser)]
#[command(
    name = "nestlink-privileged",
    version,
    about = "Optional same-user Windows input broker"
)]
pub struct BrokerArgs {
    #[arg(long)]
    pub daemon_pid: u32,
    #[arg(long)]
    pub startup_nonce: String,
    #[arg(long)]
    pub deployment: String,
    #[arg(long)]
    pub issuer: String,
    #[arg(long)]
    pub host: String,
    #[arg(long)]
    pub host_key: String,
}
pub(super) fn pipe_name(pid: u32, nonce: &str) -> io::Result<String> {
    if pid == 0 {
        return Err(security::denied());
    }
    installation::hex32(nonce)?;
    Ok(format!(r"\\.\pipe\NestLink.v15.privileged.{pid}.{nonce}"))
}
pub(super) struct Clock {
    origin: Instant,
}
impl Clock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
    pub fn now(&self) -> wire::Result<Stamp> {
        Ok(Stamp {
            monotonic_ms: self
                .origin
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| BrokerError::Clock)?,
            unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BrokerError::Clock)?
                .as_millis()
                .try_into()
                .map_err(|_| BrokerError::Clock)?,
        })
    }
}

pub async fn run(args: BrokerArgs) -> io::Result<()> {
    let installation = Installation::current("nestlink-privileged.exe")?;
    let current = Peer::open(std::process::id())?;
    let parent = Peer::open(args.daemon_pid)?;
    if !current.is_broker()
        || !parent.is_normal()
        || !current.same_login(&parent)
        || !security::same_image(&current.image, &installation.broker())
        || !security::same_image(&parent.image, &installation.daemon())
    {
        return Err(security::denied());
    }
    WindowsSessionSnapshot::current()?;
    let pins = TrustPins {
        issuer: installation::hex32(&args.issuer)?,
        deployment_id: args.deployment,
        host_device_id: args.host,
        host_key_sha256: installation::hex32(&args.host_key)?,
    };
    let mut gate = BrokerGate::<WindowsInput>::new(pins)?;
    let descriptor = security::pipe_security(&current.sid)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: the descriptor/attributes live through creation; Tokio creates one
    // overlapped local pipe and copies its security descriptor into the kernel.
    let mut pipe = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .max_instances(1)
            .in_buffer_size(wire::FRAME_BYTES as u32)
            .out_buffer_size(wire::FRAME_BYTES as u32)
            .create_with_security_attributes_raw(
                pipe_name(parent.pid, &args.startup_nonce)?,
                (&attributes as *const SECURITY_ATTRIBUTES)
                    .cast_mut()
                    .cast(),
            )
    }?;
    drop(descriptor);
    let clock = Clock::new();
    let outcome = serve(&mut pipe, &parent, &mut gate, &clock).await;
    let cleanup = gate.stop_user();
    // Keep the installation/file locks until no input or pipe owner remains.
    drop(pipe);
    drop(installation);
    cleanup.map_err(io::Error::from)?;
    outcome.map_err(io::Error::from)
}

async fn serve(
    pipe: &mut NamedPipeServer,
    parent: &Peer,
    gate: &mut BrokerGate<WindowsInput>,
    clock: &Clock,
) -> wire::Result<()> {
    let mut watchdog = tokio::time::interval(wire::WATCHDOG_INTERVAL);
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    {
        let connect = tokio::time::timeout(std::time::Duration::from_secs(10), pipe.connect());
        tokio::pin!(connect);
        loop {
            tokio::select! {
                biased;
                _ = watchdog.tick() => { parent.alive().map_err(|_| BrokerError::Stopped)?; WindowsSessionSnapshot::current().map_err(|_| BrokerError::Platform)?; },
                result = &mut connect => { result.map_err(|_| BrokerError::Timeout)?.map_err(|_| BrokerError::Io)?; break; }
            }
        }
    }
    let peer = security::pipe_peer(pipe.as_raw_handle().cast(), true)
        .map_err(|_| BrokerError::Authorization)?;
    if peer.pid != parent.pid
        || peer.creation != parent.creation
        || !peer.is_normal()
        || !peer.same_login(parent)
        || !security::same_image(&peer.image, &parent.image)
    {
        return Err(BrokerError::Authorization);
    }
    let mut previous_id = 0;
    loop {
        let request = {
            let read = tokio::time::timeout(wire::IO_BUDGET, wire::read::<_, Request>(pipe));
            tokio::pin!(read);
            loop {
                tokio::select! {
                    biased;
                    _ = watchdog.tick() => {
                        parent.alive().map_err(|_| BrokerError::Stopped)?;
                        let now = clock.now()?;
                        if let Err(error) = gate.tick(now) {
                            // Expiry/platform loss already release the device. A new
                            // grant still needs fresh signed authorization + consent.
                            if !matches!(error, BrokerError::Expired | BrokerError::Platform | BrokerError::Stopped) { return Err(error); }
                        }
                    },
                    result = &mut read => { break result.map_err(|_| BrokerError::Timeout)??; }
                }
            }
        };
        request.validate(previous_id)?;
        previous_id = request.id;
        parent.alive().map_err(|_| BrokerError::Stopped)?;
        let stop = matches!(&request.command, Command::StopUser {});
        let operation = dispatch(
            request.command,
            gate,
            clock,
            parent,
            pipe.as_raw_handle().cast(),
        );
        let result = match operation {
            Ok(result) => result,
            Err(code) => {
                // A rejected request cannot leave an earlier grant injecting.
                gate.disconnect()?;
                ReplyValue::Denied { code }
            }
        };
        let reply = Reply {
            version: wire::VERSION,
            id: request.id,
            result,
        };
        tokio::time::timeout(wire::IO_BUDGET, wire::write(pipe, &reply))
            .await
            .map_err(|_| BrokerError::Timeout)??;
        if stop {
            return Ok(());
        }
    }
}
fn dispatch(
    command: Command,
    gate: &mut BrokerGate<WindowsInput>,
    clock: &Clock,
    parent: &Peer,
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> wire::Result<ReplyValue> {
    match command {
        Command::Authorize {
            signed_permit,
            connection_generation,
            input_epoch,
            layout_epoch,
            layout,
        } => {
            let signed_permit = zeroize::Zeroizing::new(signed_permit);
            let facts = gate.begin_authorize(
                &signed_permit,
                input_epoch,
                layout_epoch,
                layout,
                clock.now()?,
            )?;
            if facts.connection_generation != connection_generation {
                gate.cancel_authorization();
                return Err(BrokerError::Epoch);
            }
            let consent = consent::confirm(&facts, parent, pipe).map_err(|_| BrokerError::Platform);
            if !matches!(consent, Ok(true)) {
                gate.cancel_authorization();
                return Err(consent.err().unwrap_or(BrokerError::ConsentDenied));
            }
            parent.alive().map_err(|_| BrokerError::Stopped)?;
            let device = WindowsInput::open().map_err(|_| BrokerError::Platform)?;
            let grant = gate.approve_authorization(device, clock.now()?)?;
            Ok(ReplyValue::Granted { grant })
        }
        Command::Renew {
            nonce,
            signed_permit,
        } => {
            let signed_permit = zeroize::Zeroizing::new(signed_permit);
            Ok(ReplyValue::Renewed {
                binding: gate.renew(&nonce, &signed_permit, clock.now()?)?,
            })
        }
        Command::Input {
            nonce,
            binding,
            sequence,
            action,
        } => {
            gate.input(&nonce, &binding, sequence, action, clock.now()?)?;
            Ok(ReplyValue::Applied {})
        }
        Command::ReleaseAll {
            nonce,
            binding,
            sequence,
        } => {
            gate.release_all(&nonce, &binding, sequence, clock.now()?)?;
            Ok(ReplyValue::Released {})
        }
        Command::Revoke { nonce } => {
            gate.revoke(&nonce)?;
            Ok(ReplyValue::Revoked {})
        }
        Command::StopUser {} => {
            gate.stop_user()?;
            Ok(ReplyValue::Stopped {})
        }
        Command::Status {} => Ok(ReplyValue::State {
            value: gate.status(),
        }),
    }
}
