//! Explicit privileged helper for one ordinary user's exact loopback gate.
//! This command does not load an installation, login or private service grant.
use nestlink_platform_security::local_port_gate::{GateOwner, GatePlan, wall_ms};
use std::{io, path::PathBuf, time::Duration};

#[derive(clap::Args)]
pub(crate) struct GateArgs {
    #[command(subcommand)]
    action: GateAction,
}
#[derive(clap::Subcommand)]
enum GateAction {
    /// Install the exact live ordinary-user plan, then watch its original PID.
    /// Use a root-private existing journal directory and root-controlled public
    /// receipt path. No service target or management credentials are consumed.
    Install {
        #[arg(long)] plan: PathBuf,
        #[arg(long)] journal_dir: PathBuf,
        #[arg(long)] receipt: PathBuf,
    },
    /// Inspect retained recovery state after the original helper releases it.
    Inspect { #[arg(long)] journal_dir: PathBuf },
    /// Remove the exact original gate only after its real socket owner exits.
    Recover { #[arg(long)] journal_dir: PathBuf },
}
pub(crate) async fn run(args: GateArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match args.action {
        GateAction::Inspect {journal_dir} => {
            println!("{}", serde_json::to_string_pretty(&GateOwner::inspect_journal(&journal_dir).await?)?);
            Ok(())
        },
        GateAction::Recover {journal_dir} => Ok(GateOwner::recover(&journal_dir).await?),
        GateAction::Install {plan, journal_dir, receipt} => {
            let plan = GatePlan::read_public(&plan)?;
            let mut previous_wall=wall_ms()?;
            let remaining=plan.expires_at_ms.checked_sub(previous_wall).ok_or_else(||io::Error::other("gate plan already expired"))?;
            let deadline=tokio::time::Instant::now()+Duration::from_millis(remaining);
            GateOwner::initialize_journal(&journal_dir)?;
            let mut owner = GateOwner::install(plan, &journal_dir).await?;
            owner.publish_receipt(&receipt).await?;
            println!("Installed exact ordinary-user loopback gate; receipt {}", receipt.display());
            let signal = crate::space_dns_system::termination();
            tokio::pin!(signal);
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! { biased;
                    result = &mut signal => {
                        result?;
                        owner.deny_all().await?;
                        return Err(io::Error::other("gate helper stopped; deny-all fence and original recovery journal retained until the socket owner actually exits").into());
                    },
                    _ = tick.tick() => {
                        if !owner.owner_alive()? {
                            owner.cleanup_after_owner_exit().await?;
                            println!("Original socket owner exited; exact kernel gate removed.");
                            return Ok(());
                        }
                        let now=wall_ms()?;
                        if (now<previous_wall || now>=owner.plan().expires_at_ms || tokio::time::Instant::now()>=deadline) && !owner.is_denied() {
                            owner.deny_all().await?;
                        }
                        previous_wall=now;
                        owner.verify_unchanged().await?;
                    },
                }
            }
        },
    }
}
