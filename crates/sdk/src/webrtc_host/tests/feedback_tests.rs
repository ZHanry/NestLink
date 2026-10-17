use super::*;
use webrtc::rtcp::{packet::Packet, reception_report::ReceptionReport};

async fn wait_for_target(target: &AtomicU32, expected: u32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        while target.load(Ordering::Acquire) != expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn authenticated_rtcp_reduces_rate_for_this_video_and_requests_keyframes() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    let permit = test_permit(&controller, &host_identity)?;
    let (host, _video, _, sender) =
        make_peer_with_mdns(&permit, false, MulticastDnsMode::Disabled).await?;
    let browser = make_browser_peer().await?;
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let keyframe = Arc::new(AtomicBool::new(false));
    let target = Arc::new(AtomicU32::new(4_000));
    let feedback =
        spawn_video_feedback(sender.clone(), cancel_rx, keyframe.clone(), target.clone());

    let result: TestResult = async {
        let offer = browser.create_offer(None).await?;
        let mut gathered = browser.gathering_complete_promise().await;
        browser.set_local_description(offer).await?;
        tokio::time::timeout(Duration::from_secs(10), gathered.recv()).await?;
        host.set_remote_description(
            browser
                .local_description()
                .await
                .ok_or_else(|| io::Error::other("missing offer"))?,
        )
        .await?;
        let answer = host.create_answer(None).await?;
        let mut gathered = host.gathering_complete_promise().await;
        host.set_local_description(answer).await?;
        tokio::time::timeout(Duration::from_secs(10), gathered.recv()).await?;
        browser
            .set_remote_description(
                host.local_description()
                    .await
                    .ok_or_else(|| io::Error::other("missing answer"))?,
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            while host.connection_state() != RTCPeerConnectionState::Connected
                || browser.connection_state() != RTCPeerConnectionState::Connected
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let ssrc = sender
            .get_parameters()
            .await
            .encodings
            .first()
            .ok_or_else(|| io::Error::other("video has no encoding"))?
            .ssrc;
        assert_ne!(ssrc, 0);
        let wrong_ssrc = ssrc ^ 1;
        let estimate = |ssrc| -> Box<dyn Packet + Send + Sync> {
            Box::new(ReceiverEstimatedMaximumBitrate {
                sender_ssrc: 77,
                bitrate: 1_000_000.0,
                ssrcs: vec![ssrc],
            })
        };
        // These are real encrypted RTCP datagrams on a negotiated loopback
        // transport, not direct calls to the rate controller. No capture or
        // product permission is opened by this transport-only regression.
        browser.write_rtcp(&[estimate(wrong_ssrc)]).await?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(target.load(Ordering::Acquire), 4_000);
        browser.write_rtcp(&[estimate(ssrc)]).await?;
        wait_for_target(&target, 850).await?;
        tokio::time::sleep(Duration::from_millis(260)).await;
        browser
            .write_rtcp(&[Box::new(ReceiverReport {
                ssrc: 77,
                reports: vec![ReceptionReport {
                    ssrc,
                    last_sequence_number: 100,
                    fraction_lost: 64,
                    ..Default::default()
                }],
                ..Default::default()
            })])
            .await?;
        wait_for_target(&target, 680).await?;
        browser
            .write_rtcp(&[Box::new(PictureLossIndication {
                sender_ssrc: 77,
                media_ssrc: ssrc,
            })])
            .await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !keyframe.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }
    .await;
    cancel_tx.send_replace(true);
    let joined = tokio::time::timeout(Duration::from_secs(3), feedback).await;
    let browser_closed = browser.close().await;
    let host_closed = host.close().await;
    result?;
    joined??;
    browser_closed?;
    host_closed?;
    Ok(())
}
