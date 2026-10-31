use super::*;
#[cfg(target_os = "linux")]
use nestlink_platform_security::local_port_gate::{GatePlan, RootGateReceipt, Transport};
#[cfg(windows)]
use nestlink_privileged::windows::local_port_gate::{GatePlan, RootGateReceipt, Transport};

/// The caller remains the original ordinary-user socket owner while a separate
/// administrator installs its exact plan. No child substitutes for this PID.
pub(super) async fn wait_raw_gate(
    listen: SocketAddr,
    datagram: bool,
    lifetime: Duration,
    plan_path: &std::path::Path,
    receipt_path: &std::path::Path,
) -> Result<GatePlan> {
    if !plan_path.is_absolute() || !receipt_path.is_absolute() || listen.port() == 0 {
        return Err(io::Error::other("raw loopback requires an exact nonzero --listen endpoint and absolute --gate-plan/--gate-receipt paths").into());
    }
    #[cfg(target_os = "linux")]
    use nestlink_platform_security::local_port_gate::wall_ms;
    #[cfg(windows)]
    use nestlink_privileged::windows::local_port_gate::wall_ms;
    let expires = wall_ms()?
        .checked_add(lifetime.as_millis().try_into()?)
        .ok_or_else(|| io::Error::other("gate expiry overflow"))?;
    let plan = GatePlan::for_current_process(
        nestlink_auth::random_id(),
        listen,
        if datagram {
            Transport::Udp
        } else {
            Transport::Tcp
        },
        expires,
    )?;
    plan.save_new(plan_path)?;
    println!(
        "Original ordinary-user loopback plan: {}",
        plan_path.display()
    );
    println!(
        "Waiting in this process for administrator receipt: {}",
        receipt_path.display()
    );
    println!(
        "Run the same executable as administrator: local-port-gate install --plan <above-plan> --journal-dir <fresh-root-private-directory> --receipt <above-receipt>"
    );
    let deadline = tokio::time::Instant::now() + lifetime;
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {biased;
            result=&mut signal=>{result?;return Err(io::Error::other("original raw owner stopped before kernel admission").into());},
            _=tokio::time::sleep_until(deadline)=>return Err(io::Error::other("original raw owner lifetime expired before kernel admission").into()),
            _=tick.tick()=>{
                match RootGateReceipt::read_for_current_process(receipt_path,&plan) {
                    Ok(_)=>return Ok(plan),
                    Err(error) if error.kind()==io::ErrorKind::NotFound=>{},
                    Err(error)=>return Err(error.into()),
                }
            },
        }
    }
}
