use super::*;

fn keyframe(width: u32, height: u32, layout: u64, sequence: u64, pts: u64) -> Result<NativeVideo> {
    let mut encoder = Vp8Encoder::new(VideoConfig {
        width,
        height,
        fps: 30,
        bitrate_kbps: 1000,
    })?;
    let encoded = encoder.encode(
        &[0, 255, 0, 255].repeat((width * height) as usize),
        pts,
        true,
    )?;
    Ok(NativeVideo {
        format_epoch: 0,
        format_sha256: Vec::new(),
        codec: 0,
        schema_version: 1,
        connection_generation: EPOCH.connection,
        layout_epoch: layout,
        source: 42,
        sequence,
        pts_90khz: pts,
        width,
        height,
        keyframe: encoded.keyframe,
        repeated_source: false,
        payload: encoded.data,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_layout_decodes_new_geometry_and_retires_on_revocation() -> Result {
    for quic in [false, true] {
        let mut pair = pair_with_transport(quic).await?;
        let mut receiver = VideoReceiver::attach_dynamic_channel(
            &mut pair.controller,
            EPOCH.connection,
            vec![42],
        )?;
        let presentation = receiver.presentation();
        for (width, height, layout, sequence) in [(64, 48, 3, 1), (80, 40, 4, 2), (80, 40, 5, 3)] {
            let packet = keyframe(width, height, layout, sequence, sequence)?;
            pair.host
                .send(Channel::Video, &packet.encode_validated()?)
                .await?;
            wait_until(|| {
                if let Some(decoded) = presentation.poll_video()? {
                    assert_eq!(
                        decoded.epoch,
                        VideoEpoch {
                            connection: EPOCH.connection,
                            layout
                        }
                    );
                    assert_eq!(decoded.sequence, sequence);
                    assert_eq!(decoded.pts_90khz, sequence);
                    assert_eq!((decoded.width, decoded.height), (width, height));
                    assert_eq!(decoded.pixels.len(), (width * height * 4) as usize);
                    assert!(
                        decoded
                            .pixels
                            .chunks_exact(4)
                            .all(|pixel| pixel[1] > 240 && pixel[0] < 15 && pixel[2] < 15)
                    );
                    let current = presentation.layout(42)?.ok_or("missing dynamic layout")?;
                    assert_eq!(current.epoch, decoded.epoch);
                    assert_eq!((current.width, current.height), (width, height));
                    return Ok(true);
                }
                Ok(false)
            })
            .await?;
        }
        pair.controller_revoke
            .send_replace(Some(StopReason::Revoked));
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(presentation.poll_video().is_err());
        assert!(presentation.layout(42).is_err());
        assert_eq!(
            receiver.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_layout_does_not_reset_replay_or_timestamp_checks() -> Result {
    for case in 0..5 {
        let mut pair = pair().await?;
        let mut receiver = VideoReceiver::attach_dynamic_channel(
            &mut pair.controller,
            EPOCH.connection,
            vec![42],
        )?;
        pair.host
            .send(
                Channel::Video,
                &keyframe(64, 48, 3, 1, 1)?.encode_validated()?,
            )
            .await?;
        wait_until(|| Ok(receiver.poll_video()?.is_some())).await?;
        let mut packet = keyframe(80, 40, 4, 2, 2)?;
        match case {
            0 => packet.sequence = 1,
            1 => packet.pts_90khz = 1,
            2 => packet.layout_epoch = 2,
            3 => packet.source = 43,
            _ => packet.layout_epoch = 3, // geometry changed without advancing layout
        }
        pair.host
            .send(Channel::Video, &packet.encode_validated()?)
            .await?;
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(receiver.monitor().status().error.is_some(), "case {case}");
        assert!(receiver.poll_video().is_err());
        assert_eq!(
            receiver.shutdown(StopReason::Revoked)?,
            ShutdownReport::Joined
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layout_change_without_keyframe_clears_pixels_until_recovery() -> Result {
    let mut pair = pair().await?;
    let mut receiver =
        VideoReceiver::attach_dynamic_channel(&mut pair.controller, EPOCH.connection, vec![42])?;
    pair.host
        .send(
            Channel::Video,
            &keyframe(64, 48, 3, 1, 1)?.encode_validated()?,
        )
        .await?;
    wait_until(|| Ok(receiver.presentation().layout(42)?.is_some())).await?;
    // Keep the old image in the presentation mailbox, then enter a new layout
    // with an interframe whose reference was never transmitted.
    let mut encoder = Vp8Encoder::new(selected(42).codec)?;
    let _ = envelope(&mut encoder, 1, 1)?;
    let mut packet = envelope(&mut encoder, 2, 2)?;
    assert!(!packet.keyframe);
    packet.layout_epoch = 4;
    pair.host
        .send(Channel::Video, &packet.encode_validated()?)
        .await?;
    wait_until(|| Ok(receiver.stats().discarded_frames == 1)).await?;
    assert_eq!(
        receiver
            .presentation()
            .layout(42)?
            .ok_or("missing new layout")?
            .epoch
            .layout,
        4
    );
    assert!(receiver.poll_video()?.is_none());
    pair.host
        .send(
            Channel::Video,
            &keyframe(64, 48, 4, 3, 3)?.encode_validated()?,
        )
        .await?;
    wait_until(|| {
        Ok(receiver
            .poll_video()?
            .is_some_and(|frame| frame.epoch.layout == 4 && frame.sequence == 3))
    })
    .await?;
    assert_eq!(receiver.stats().completed_recoveries, 1);
    assert_eq!(
        receiver.shutdown(StopReason::ExplicitExit)?,
        ShutdownReport::Joined
    );
    Ok(())
}
