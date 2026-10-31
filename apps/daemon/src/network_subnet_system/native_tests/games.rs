//! Actual upstream Luanti+Minetest Game over the unchanged native subnet path.
//! The explicit fixed signed fixture qualifies mechanism interoperability;
//! production management one-use starts and physical sites are separate gates.
use super::*;

#[tokio::test]
#[ignore = "exact pinned game sources, original GitHub-hosted native subnet lab and explicit game workflow required"]
async fn actual_luanti_client_server_play_and_original_kernel_carrier_stop() -> Result {
    lab_only()?;
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    assert_ne!(rustix::process::geteuid().as_raw(), 0);
    let output = PathBuf::from(std::env::var("NESTLINK_GAME_EVIDENCE")?);
    nestlink_platform_security::new_private_directory(&output)?;
    let lab = lab::Lab::new()?;
    nestlink_platform_security::create_private(&lab.config(), &serde_json::to_vec(&lab)?)?;
    assert!(lab.status("setup").await?, "exact owned subnet setup failed");
    let fixture = fixture::Fixture::for_game()?;
    let plans = [fixture.plan(0, lab.plan(0), lab.bridge(0)).await?,
        fixture.plan(1, lab.plan(1), lab.bridge(1)).await?];
    for plan in &plans { plan.save_new()?; }
    let mut helpers = [lab.command("apply0")?.spawn()?, lab.command("apply1")?.spawn()?];
    let mut game: Option<Child> = None;
    let outcome = async {
        let (first, second) = helpers.split_at_mut(1);
        let (left, right) = tokio::try_join!(connect(&plans[0], &mut first[0]), connect(&plans[1], &mut second[0]))?;
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let carriers = carrier::start(&plans, [left.clone(), right.clone()], stopped).await?;
        drop(left); drop(right);
        let process = Command::new("python3")
            .args(["-B", "scripts/network-games.py", "luanti"])
            .env("NESTLINK_LUANTI_0_NAMESPACE", lab.target(0))
            .env("NESTLINK_LUANTI_1_NAMESPACE", lab.target(1))
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
            .kill_on_drop(true).spawn()?;
        game = Some(process);
        let exercise = async {
            tokio::time::timeout(Duration::from_secs(35), async {
                while !output.join("luanti-ready-for-stop").try_exists()? {
                    if game.as_mut().ok_or_else(||io::Error::other("original game actor missing"))?.try_wait()?.is_some() {
                        return Err(io::Error::other("actual Luanti actor exited before its game receipt").into());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
            }).await??;
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        }.await;
        let _ = stop.send(true);
        let [first, second] = carriers;
        let (left, right) = tokio::try_join!(first, second)?;
        let left = left?; let right = right?;
        assert!(left.sent > 0 && left.received > 0 && right.sent > 0 && right.received > 0);
        assert!(left.spent > 0 && right.spent > 0 && left.spent <= 16 * 1_048_576 && right.spent <= 16 * 1_048_576);
        assert!(finished(&mut helpers[0]).await? && finished(&mut helpers[1]).await?, "original root helpers must confirm physical cleanup");
        exercise?;
        std::fs::write(output.join("luanti-owner-stopped"), b"original encrypted carriers and exact root TUN/route owners joined")?;
        let process = game.as_mut().ok_or_else(||io::Error::other("original game actor missing"))?;
        assert!(tokio::time::timeout(Duration::from_secs(35), process.wait()).await??.success(), "actual Luanti execution failed; same-run evidence retained");
        let actual: serde_json::Value = serde_json::from_slice(&std::fs::read(output.join("luanti-execution.json"))?)?;
        assert_eq!(actual["passed"], true);
        std::fs::write(output.join("original-subnet-game.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":1,"source_revision":std::env::var("GITHUB_SHA")?,"passed":true,
            "scope":"actual hosted official Luanti+Minetest Game through production kernel TUN/prefix NAT/QUIC with explicit fixed signed mechanism credentials; no production login/one-use or physical-site claim",
            "left":{"sent_packets":left.sent,"received_packets":left.received,"spent_bytes":left.spent},
            "right":{"sent_packets":right.sent,"received_packets":right.received,"spent_bytes":right.spent},
            "original_packet_owners_stopped":true,"root_helpers_joined":true
        }))?)?;
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }.await;
    if let Some(game) = &mut game
        && game.try_wait()?.is_none() {
        if let Some(pid) = game.id().and_then(|pid| rustix::process::Pid::from_raw(pid as i32)) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), game.wait()).await;
    }
    if outcome.is_err() {
        for (index, helper) in helpers.iter_mut().enumerate() {
            let _ = lab.status(&format!("kill-helper{index}")).await;
            let _ = finished(helper).await;
            let _ = lab.status(&format!("recover{index}")).await;
        }
    }
    let teardown = lab.status("teardown").await?;
    outcome?;
    assert!(teardown, "exact native game lab teardown failed");
    for entry in std::fs::read_dir(&lab.ordinary)? {
        let path = entry?.path();
        if path.is_file() { std::fs::remove_file(path)?; }
    }
    std::fs::remove_dir(&lab.ordinary)?;
    Ok(())
}
