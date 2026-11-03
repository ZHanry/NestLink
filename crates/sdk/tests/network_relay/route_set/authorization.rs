//! Explicit authority withdrawal cannot use the physical-loss hold or migrate.
use super::*;
use nestlink_connectivity::continuation::QualityConstraints;

#[tokio::test]
async fn current_node_or_original_path_revocation_stops_both_prepared_owners_without_migration()
-> Result {
    for revoke_node in [true, false] {
        let mut f = Fixture::file_only().await?;
        let mut second = super::super::chain::ChainNode::new(&f).await?;
        let (set, _, controller_route) = reserve(&f, &second).await?;
        let path_id = controller_route.path_grant_id().to_owned();
        let controller_key = f.controller.identity.public_key();
        let host_key = f.host.identity.public_key();
        let host_route = f.sdk.verified_network_remote_route_set(
            &f.pin, &f.host, &f.permit, &controller_key, &set,
        ).await?;
        let (_keep_stop, stop) = watch::channel(None);
        let (_keep_cancel, cancel) = watch::channel(false);
        let addresses = [unused_udp()?, unused_udp()?];
        let policy = AddressPolicy::new(&[])?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut controller, mut host) = tokio::try_join!(
            f.sdk.connect_continuing_network_remote_route_candidate(
                controller_route, 1, addresses[0], &f.controller, &host_key,
                f.setup(EndpointRole::Controller, stop.clone())?, &policy,
                cancel.clone(), deadline, QualityConstraints::default(),
            ),
            f.sdk.connect_continuing_network_remote_route_candidate(
                host_route, 1, addresses[1], &f.host, &controller_key,
                f.setup(EndpointRole::Host, stop)?, &policy,
                cancel, deadline, QualityConstraints::default(),
            ),
        )?;
        let (sent, received) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                host.channels().send(Channel::FileRead, b"proved original business"),
                controller.channels().receive(),
            )
        }).await?;
        sent?;
        assert_eq!(received?.payload, b"proved original business");
        let (controller_ready, host_ready) = tokio::try_join!(
            controller.poll(&f.sdk, &f.controller, &host_key, true),
            host.poll(&f.sdk, &f.host, &controller_key, true),
        )?;
        assert!(controller_ready.policy.standby.is_some());
        assert!(host_ready.policy.standby.is_some());
        let standby = [controller.standby_local_addr().ok_or("controller standby")?,
            host.standby_local_addr().ok_or("host standby")?];
        if revoke_node {
            // Leave the listener and NodeControl running: this is an explicit
            // authenticated management withdrawal, never a simulated DROP.
            f.sdk.revoke_node(&second.id).await?;
        } else {
            f.sdk.revoke_network_remote_path(f.pin.space_id(), &path_id).await?;
        }
        let (controller_report, host_report) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
        }).await??;
        assert_eq!(controller_report.reason, StopReason::Revoked);
        assert_eq!(host_report.reason, StopReason::Revoked);
        assert_eq!(controller.status()?.policy.epoch, 1);
        assert_eq!(host.status()?.policy.epoch, 1);
        assert!(controller.channels().send(Channel::FileRead, b"revoked request").await.is_err());
        assert!(host.channels().send(Channel::FileRead, b"revoked response").await.is_err());
        drop(rebind(&addresses)?);
        drop(rebind(&standby)?);
        second.finish().await?;
        f.finish().await?;
    }
    Ok(())
}
