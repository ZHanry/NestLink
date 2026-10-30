//! Explicit local UUID intent must reach the original independent relay owner.
use super::*;
use super::signed_discovery::{approve_quic_endpoint,local_options,routed_host_address,wait_for_peer_relay_marker};
use nestlink_sdk::native::{NativeMediaSessionOptions,SessionEstablishError};

fn selected(node: &str) -> NativeMediaSessionOptions {
    NativeMediaSessionOptions { session:local_options(), media:None, relay_node_id:Some(node.into()) }
}

#[tokio::test]
async fn explicit_relay_survives_discovery_refresh_and_carries_business_with_combined_available() -> Result {
    let address=routed_host_address()?;
    // Unlike the old automatic-only fixture, the combined relay stays available.
    let mut f=Fixture::with_quic_bound(None,"0.0.0.0:0").await?;
    approve_quic_endpoint(&mut f,address).await?;
    let _available_combined=f.sdk.relay_route(&f.permit).await?;
    let (_cancel,cancel)=watch::channel(false);
    let mut connecting=Box::pin(f.endpoints[0].establish_with_media(&f.sdk,&f.controller,selected(&f.node_id),&[],vec![],cancel.clone()));
    let marker=tokio::select! {
        result=&mut connecting=>return Err(match result { Ok(_)=>"controller connected before its host".to_owned(),Err(error)=>format!("selected relay failed before host: {error:?}") }.into()),
        marker=wait_for_peer_relay_marker(&f,&f.host)=>marker?,
    };
    assert_eq!(marker.address.ip(),address);
    // The first signed discovery is expired before the peer arrives. Refresh
    // must rediscover this same UUID under the original establishment owner.
    tokio::time::sleep(Duration::from_millis(5100)).await;
    let (mut controller,mut host)=tokio::try_join!(
        &mut connecting,
        f.endpoints[1].establish(&f.sdk,&f.host,local_options(),&[],vec![],cancel),
    )?;
    for session in [&controller,&host] {
        assert_eq!(session.candidate.path(),Path::Relay);
        assert_eq!(session.candidate.transport,nestlink_protocol::api::Transport::Quic);
        assert_eq!(session.candidate.address.ip(),address);
        assert_eq!(session.candidate.address.port().to_string(),f.quic_uri.rsplit(':').next().ok_or("fixture port missing")?);
    }
    let payload=vec![0x51;64*1024];
    let (sent,received)=tokio::join!(controller.channels.send(Channel::Video,&payload),host.channels.receive());
    sent?;
    assert_eq!(received?.payload,payload);
    let (sent,received)=tokio::join!(host.channels.send(Channel::Video,b"explicit selected relay reverse"),controller.channels.receive());
    sent?;
    assert_eq!(received?.payload,b"explicit selected relay reverse");
    let counters=f.control.counters()?;
    assert_eq!(counters.opened_connections,2);
    assert!(counters.admitted_bytes>=payload.len() as u64);
    controller.control.stop(nestlink_sdk::StopReason::ExplicitExit)?;
    host.control.stop(nestlink_sdk::StopReason::ExplicitExit)?;
    drop(controller);
    drop(host);
    f.closed().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_unknown_and_revoked_explicit_nodes_never_use_an_available_other_relay() -> Result {
    let address=routed_host_address()?;
    let mut f=Fixture::with_quic_bound(None,"0.0.0.0:0").await?;
    approve_quic_endpoint(&mut f,address).await?;
    let _available_combined=f.sdk.relay_route(&f.permit).await?;
    assert_eq!(f.sdk.discover_relay_candidates(&f.controller,&f.permit).await?.checked(&f.sdk,&f.permit,&f.controller)?.len(),1);
    let held=f.sdk.relay_reservations().await?.held_allocations;
    let (_cancel,cancel)=watch::channel(false);
    let invalid=f.endpoints[0].establish_with_media(&f.sdk,&f.controller,selected("not-a-node-uuid"),&[],vec![],cancel.clone()).await;
    assert!(matches!(invalid,Err(SessionEstablishError::RelaySelectionInvalid)));
    let mut direct_only=selected(&f.node_id);
    direct_only.session.local_paths=PathSet::DIRECT;
    assert!(matches!(f.endpoints[0].establish_with_media(&f.sdk,&f.controller,direct_only,&[],vec![],cancel.clone()).await,Err(SessionEstablishError::RelaySelectionInvalid)));
    let unknown=f.endpoints[0].establish_with_media(&f.sdk,&f.controller,selected(&random_id()),&[],vec![],cancel.clone()).await;
    assert!(matches!(unknown,Err(SessionEstablishError::SelectedRelayUnavailable(_))));
    f.sdk.revoke_node(&f.node_id).await?;
    let revoked=f.endpoints[0].establish_with_media(&f.sdk,&f.controller,selected(&f.node_id),&[],vec![],cancel).await;
    assert!(matches!(revoked,Err(SessionEstablishError::SelectedRelayUnavailable(_))));
    assert_eq!(f.control.counters()?.opened_connections,0);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations,held);
    Ok(())
}
