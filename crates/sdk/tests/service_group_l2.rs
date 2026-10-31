//! Dedicated hosted cooperation roles. Python owns real Linux namespaces,
//! IPVS, keepalived and Caddy; these roles own the original production SDK,
//! node control, QUIC, target, usage and physical cleanup paths.
#[path = "service_group_l2/roles.rs"]
mod roles;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "only the dedicated GitHub-hosted dual-edge IPVS workflow invokes this cooperation role"]
async fn actual_ipvs_dual_edge_role() -> roles::Result {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("NESTLINK_GROUP_L2").as_deref() != Ok("1")
    {
        return Err("R02: use the dedicated GitHub-hosted service-group workflow".into());
    }
    tokio::time::timeout(std::time::Duration::from_secs(210), roles::run()).await??;
    Ok(())
}
