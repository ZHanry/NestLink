//! Explicit remote OS fixture boundary. The original target online owner and
//! production QUIC packet loop remain in the coordinator. A private local Unix
//! datagram pair transports whole IP packets to a second actual Linux TUN;
//! Linux, curl and the unmodified Python HTTP server own TCP and HTTP.
use super::*;
use crate::network_packet_runtime::{PacketIoFuture, WholePacketDevice};
use tokio::net::UnixDatagram;

const SELECTOR: &str =
    "network_tun_system::native_tests::combined::kernel_peer::actual_kernel_peer_role";
pub(super) struct KernelPeer {
    socket: UnixDatagram,
    child: Child,
    helper: Option<Child>,
    pub plan: TunPlan,
    plan_path: PathBuf,
    journal: PathBuf,
    namespace: String,
    _private: tempfile::TempDir,
}
impl WholePacketDevice for KernelPeer {
    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketIoFuture<'a> {
        Box::pin(self.socket.recv(packet))
    }
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketIoFuture<'a> {
        Box::pin(self.socket.send(packet))
    }
}
fn namespace_command(namespace: &str, ordinary: bool) -> Result<Command> {
    let mut command = Command::new("sudo");
    command.args(["-n", "ip", "netns", "exec", namespace]);
    if ordinary {
        command.args([
            "setpriv",
            &format!("--reuid={}", rustix::process::geteuid().as_raw()),
            &format!("--regid={}", rustix::process::getegid().as_raw()),
            "--init-groups",
            "--no-new-privs",
        ]);
    }
    command.args(["env", "GITHUB_ACTIONS=true", "NESTLINK_TUN_NATIVE_LAB=1"]);
    command.kill_on_drop(true);
    Ok(command)
}
fn helper_command(namespace: &str, role: &str, plan: &Path, journal: &Path) -> Result<Command> {
    let mut command = namespace_command(namespace, false)?;
    command
        .arg(format!("NESTLINK_TUN_NATIVE_ROLE={role}"))
        .arg(format!("NESTLINK_TUN_NATIVE_PLAN={}", plan.display()))
        .arg(format!("NESTLINK_TUN_NATIVE_JOURNAL={}", journal.display()))
        .arg(std::env::current_exe()?)
        .args([
            ROLE_TEST,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
    Ok(command)
}
impl KernelPeer {
    pub async fn start(template: TunPlan, namespace: String) -> Result<Self> {
        let private = tempfile::Builder::new()
            .prefix("nl-kernel-")
            .tempdir_in("/tmp")?;
        let directory = private.path().join("owner");
        nestlink_platform_security::new_private_directory(&directory)?;
        nestlink_platform_security::create_private(
            &directory.join("template.json"),
            &serde_json::to_vec(&template)?,
        )?;
        nestlink_platform_security::create_private(&directory.join("probe"), &vec![83_u8; 32_768])?;
        let socket = UnixDatagram::bind(directory.join("coordinator.sock"))?;
        let plan_path = directory.join("plan.json");
        let journal = PathBuf::from("/tmp").join(format!(
            "nestlink-tun-native-{}",
            nestlink_auth::random_id()
        ));
        assert!(status("init", &plan_path, &journal).await?);
        let mut command = namespace_command(&namespace, true)?;
        let mut child = command
            .arg(format!(
                "NESTLINK_COMBINED_KERNEL_DIRECTORY={}",
                directory.display()
            ))
            .arg(std::env::current_exe()?)
            .args([
                SELECTOR,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .spawn()?;
        let setup = async {
            wait_file(&plan_path, &mut child).await?;
            let plan = TunPlan::read(&plan_path)?;
            let helper = helper_command(&namespace, "apply", &plan_path, &journal)?.spawn()?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((plan, helper))
        }
        .await;
        let (plan, helper) = match setup {
            Ok(value) => value,
            Err(error) => {
                let _ = child.start_kill();
                let _ = finished(&mut child).await;
                let _ = status("teardown", &plan_path, &journal).await;
                return Err(error);
            }
        };
        let mut peer = Self {
            socket,
            child,
            helper: Some(helper),
            plan,
            plan_path,
            journal,
            namespace,
            _private: private,
        };
        let ready = wait_file(&peer.plan_path.with_extension("ready"), &mut peer.child).await;
        if let Err(error) = ready {
            let _ = peer.shutdown().await;
            return Err(error);
        }
        if let Err(error) = peer.socket.connect(directory.join("peer.sock")) {
            let _ = peer.shutdown().await;
            return Err(error.into());
        }
        Ok(peer)
    }
    pub async fn check(&self) -> Result {
        self.plan.validate(true)?;
        if process_identity(self.plan.process.pid()).await? != self.plan.process {
            return Err(io::Error::other("original remote kernel fixture process changed").into());
        }
        Ok(())
    }
    pub async fn shutdown(&mut self) -> Result {
        nestlink_platform_security::create_private(
            &self.plan_path.with_extension("stop"),
            b"stop",
        )?;
        let ordinary = finished(&mut self.child).await;
        let root = if let Some(helper) = &mut self.helper {
            finished(helper).await
        } else {
            Ok(true)
        };
        if !matches!(ordinary, Ok(true)) || !matches!(root, Ok(true)) {
            let _ = self.child.start_kill();
            let _ = finished(&mut self.child).await;
            let _ = helper_command(
                &self.namespace,
                "kill-helper",
                &self.plan_path,
                &self.journal,
            )?
            .status()
            .await;
            let _ = helper_command(&self.namespace, "recover", &self.plan_path, &self.journal)?
                .status()
                .await;
        }
        let removed = helper_command(&self.namespace, "teardown", &self.plan_path, &self.journal)?
            .status()
            .await?;
        assert!(
            ordinary?,
            "ordinary remote kernel fixture did not close normally"
        );
        assert!(
            root?,
            "original remote root helper did not confirm physical cleanup"
        );
        assert!(removed.success());
        let observed = Command::new("sudo")
            .args([
                "-n",
                "ip",
                "-n",
                &self.namespace,
                "link",
                "show",
                "dev",
                &self.plan.link(),
            ])
            .output()
            .await?;
        assert!(
            !observed.status.success(),
            "original remote TUN survived cleanup"
        );
        self.helper = None;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "internal actual remote Linux kernel fixture role; only the isolated combined hosted coordinator may invoke it"]
async fn actual_kernel_peer_role() -> Result {
    lab()?;
    assert_ne!(rustix::process::geteuid().as_raw(), 0);
    let directory = PathBuf::from(std::env::var("NESTLINK_COMBINED_KERNEL_DIRECTORY")?);
    nestlink_platform_security::check_private_directory(&directory)?;
    let mut plan: TunPlan = serde_json::from_slice(&nestlink_platform_security::read_private(
        &directory.join("template.json"),
        65_536,
    )?)?;
    plan.process = process_identity(std::process::id()).await?;
    plan.principal = plan::HostPrincipal::current()?;
    let path = directory.join("plan.json");
    plan.save_new(&path)?;
    let state = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            plan.validate(true)?;
            if let Some(state) = linux::inspect(&plan).await?
                && state.up
                && state.persistent
                && state.addresses.len() == 2
            {
                linux::verify(&plan, &state, true)?;
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let native = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match linux::adopt(&plan, &state).await {
                Ok(device) => return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(device),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.raw_os_error() == Some(16)) =>
                {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    let mut device = PacketDevice::linux(native);
    let socket = UnixDatagram::bind(directory.join("peer.sock"))?;
    socket.connect(directory.join("coordinator.sock"))?;
    let mut servers = Vec::new();
    for host in plan.local_hosts {
        servers.push(
            Command::new("python3")
                .args([
                    "-B",
                    "-u",
                    "-m",
                    "http.server",
                    "8080",
                    "--bind",
                    &host.to_string(),
                    "--directory",
                    directory
                        .to_str()
                        .ok_or_else(|| io::Error::other("kernel fixture path encoding"))?,
                ])
                .kill_on_drop(true)
                .spawn()?,
        );
    }
    let left = tokio::net::UdpSocket::bind((plan.local_hosts[0], 4443)).await?;
    let right = tokio::net::UdpSocket::bind((plan.local_hosts[1], 4443)).await?;
    // An actual local TCP handshake proves both unmodified services are ready;
    // cross-TUN HTTP still has its own exact body and kernel path assertions.
    tokio::time::timeout(Duration::from_secs(3), async {
        for host in plan.local_hosts {
            loop {
                if tokio::net::TcpStream::connect((host, 8080)).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    })
    .await?;
    nestlink_platform_security::create_private(
        &path.with_extension("ready"),
        b"actual-dual-stack-kernel-and-http-ready",
    )?;
    let mut from_kernel = vec![0; 65_536];
    let mut from_owner = vec![0; 65_536];
    let mut v4_payload = vec![0; 2048];
    let mut v6_payload = vec![0; 2048];
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let outcome = async { loop { tokio::select! {
        result = device.recv(&mut from_kernel) => { let count = result?; assert_eq!(socket.send(&from_kernel[..count]).await?, count); },
        result = socket.recv(&mut from_owner) => { let count = result?; assert_eq!(device.send(&from_owner[..count]).await?, count); },
        result = left.recv_from(&mut v4_payload) => { let (count, source) = result?; assert_eq!(left.send_to(&v4_payload[..count], source).await?, count); },
        result = right.recv_from(&mut v6_payload) => { let (count, source) = result?; assert_eq!(right.send_to(&v6_payload[..count], source).await?, count); },
        _ = tick.tick() => {
            plan.validate(true)?;
            if path.with_extension("stop").try_exists()? { break; }
            if linux::inspect(&plan).await?.as_ref() != Some(&state) { return Err(io::Error::other("original remote kernel TUN changed").into()); }
            for server in &mut servers { assert!(server.try_wait()?.is_none(), "unmodified HTTP service exited"); }
        },
    }} Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()) }.await;
    for server in &mut servers {
        server.start_kill()?;
        let _ = server.wait().await?;
    }
    device.shutdown().await?;
    let released = owner::release_plan(&plan, &path).await;
    outcome?;
    released
}
