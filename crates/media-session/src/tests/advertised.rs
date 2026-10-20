use super::*;
use nestlink_protocol::native_displays::{
    DisplayCatalogKey, DisplayDescriptor, DisplaySelection, catalog_key,
};

fn catalog() -> Result<(DisplayCatalogKey, Vec<DisplayDescriptor>)> {
    let displays = [42, 77]
        .into_iter()
        .map(|source| DisplayDescriptor {
            source,
            left: 0,
            top: 0,
            width: 64,
            height: 48,
            label: format!("screen {source}"),
        })
        .collect::<Vec<_>>();
    Ok((
        catalog_key(&random_id(), EPOCH.connection, 1, &displays)?,
        displays,
    ))
}

fn selection(key: &DisplayCatalogKey, source: u32, layout: u64) -> DisplaySelection {
    DisplaySelection {
        catalog: key.clone(),
        sequence: layout,
        source,
        layout_epoch: layout,
        input_epoch: 0,
    }
}

fn packet(source: u32, layout: u64, sequence: u64, pts: u64) -> Result<NativeVideo> {
    let mut encoder = Vp8Encoder::new(selected(source).codec)?;
    let encoded = encoder.encode(&[0, 255, 0, 255].repeat(64 * 48), pts, true)?;
    Ok(NativeVideo {
        codec: 0,
        schema_version: 1,
        connection_generation: EPOCH.connection,
        layout_epoch: layout,
        source,
        sequence,
        pts_90khz: pts,
        width: 64,
        height: 48,
        keyframe: encoded.keyframe,
        repeated_source: false,
        payload: encoded.data,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timed_display_switch_flushes_old_deadlines_and_retains_replay_history() -> Result {
    for quic in [false, true] {
        let mut pair = pair_with_transport(quic).await?;
        let first = packet(42, 1, 1, 90_000)?.encode_validated()?;
        let switched = packet(77, 2, 1, 90_900)?.encode_validated()?;
        let clock = crate::SessionPlayoutClock::default();
        let receiver = VideoReceiver::attach_advertised_channel_timed(
            &mut pair.controller,
            EPOCH.connection,
            clock.clone(),
        )?;
        let presentation = receiver.presentation();
        let (key, displays) = catalog()?;
        presentation.install_display_catalog(key.clone(), displays)?;
        presentation.select_display(&selection(&key, 42, 1))?;
        let _ = clock.schedule(90_000, 90_000, Instant::now() + Duration::from_millis(120))?;
        pair.host.send(Channel::Video, &first).await?;
        wait_until(|| Ok(receiver.scheduled_count_for_test() == 1)).await?;
        assert!(presentation.poll_video()?.is_none());

        presentation.suspend_display()?;
        assert_eq!(receiver.scheduled_count_for_test(), 0);
        presentation.select_display(&selection(&key, 77, 2))?;
        pair.host.send(Channel::Video, &switched).await?;
        wait_until(|| {
            if let Some(frame) = presentation.poll_video()? {
                assert_eq!(
                    (frame.source, frame.epoch.layout, frame.sequence),
                    (77, 2, 1)
                );
                return Ok(true);
            }
            Ok(false)
        })
        .await?;
        pair.host
            .send(
                Channel::Video,
                &packet(77, 2, 2, 900_000)?.encode_validated()?,
            )
            .await?;
        wait_until(|| Ok(receiver.stats().discarded_future_frames == 1)).await?;
        assert_eq!(receiver.scheduled_count_for_test(), 0);
        // A discarded future presentation still passed decoder validation and
        // cannot reset authenticated per-source sequence/PTS history.
        pair.host
            .send(
                Channel::Video,
                &packet(77, 2, 1, 900_001)?.encode_validated()?,
            )
            .await?;
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(receiver.monitor().status().error.is_some());
        assert!(presentation.poll_video().is_err());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertised_receiver_has_no_implicit_source_before_catalogue_and_selection() -> Result {
    for quic in [false, true] {
        for case in 0..5 {
            let mut pair = pair_with_transport(quic).await?;
            let receiver =
                VideoReceiver::attach_advertised_channel(&mut pair.controller, EPOCH.connection)?;
            let presentation = receiver.presentation();
            let (key, displays) = catalog()?;
            assert!(presentation.layout(42)?.is_none());
            if case > 0 {
                presentation.install_display_catalog(key.clone(), displays)?;
            }
            if case > 1 {
                presentation.select_display(&selection(&key, 42, 1))?;
            }
            let frame = match case {
                2 => packet(99, 1, 1, 1)?,
                3 => packet(77, 1, 1, 1)?,
                4 => packet(42, 2, 1, 1)?,
                _ => packet(42, 1, 1, 1)?,
            };
            pair.host
                .send(Channel::Video, &frame.encode_validated()?)
                .await?;
            wait_until(|| Ok(receiver.monitor().status().finished)).await?;
            assert!(receiver.monitor().status().error.is_some());
            assert!(presentation.poll_video().is_err());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertised_switch_back_retires_old_pixels_and_keeps_source_replay_history() -> Result {
    for quic in [false, true] {
        let mut pair = pair_with_transport(quic).await?;
        let receiver =
            VideoReceiver::attach_advertised_channel(&mut pair.controller, EPOCH.connection)?;
        let presentation = receiver.presentation();
        let (key, displays) = catalog()?;
        presentation.install_display_catalog(key.clone(), displays)?;
        presentation.select_display(&selection(&key, 42, 1))?;
        pair.host
            .send(Channel::Video, &packet(42, 1, 1, 10)?.encode_validated()?)
            .await?;
        wait_until(|| Ok(presentation.poll_video()?.is_some())).await?;
        presentation.suspend_display()?;
        assert!(presentation.layout(42)?.is_none());
        assert!(presentation.poll_video()?.is_none());
        presentation.select_display(&selection(&key, 77, 2))?;
        assert!(presentation.layout(42)?.is_none());
        // An application frame already queued in another reliable stream at
        // the ACK boundary is discarded without updating retired history.
        pair.host
            .send(Channel::Video, &packet(42, 1, 2, 11)?.encode_validated()?)
            .await?;
        pair.host
            .send(Channel::Video, &packet(77, 2, 1, 12)?.encode_validated()?)
            .await?;
        wait_until(|| {
            if let Some(frame) = presentation.poll_video()? {
                assert_eq!(
                    (frame.source, frame.epoch.layout, frame.sequence),
                    (77, 2, 1)
                );
                assert!(presentation.layout(42)?.is_none());
                return Ok(true);
            }
            Ok(false)
        })
        .await?;
        presentation.suspend_display()?;
        presentation.select_display(&selection(&key, 42, 3))?;
        pair.host
            .send(Channel::Video, &packet(77, 2, 2, 13)?.encode_validated()?)
            .await?;
        pair.host
            .send(Channel::Video, &packet(42, 3, 2, 20)?.encode_validated()?)
            .await?;
        wait_until(|| {
            if let Some(frame) = presentation.poll_video()? {
                assert_eq!(
                    (frame.source, frame.epoch.layout, frame.sequence),
                    (42, 3, 2)
                );
                assert!(presentation.layout(77)?.is_none());
                return Ok(true);
            }
            Ok(false)
        })
        .await?;
        pair.host
            .send(Channel::Video, &packet(42, 3, 1, 21)?.encode_validated()?)
            .await?;
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(
            receiver
                .monitor()
                .status()
                .error
                .is_some_and(|error| error.contains("sequence or PTS replay"))
        );
        assert!(presentation.poll_video().is_err());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_grant_catalogue_refresh_rotates_same_source_and_retains_replay_history() -> Result {
    for quic in [false, true] {
        let mut pair = pair_with_transport(quic).await?;
        let receiver =
            VideoReceiver::attach_advertised_channel(&mut pair.controller, EPOCH.connection)?;
        let presentation = receiver.presentation();
        let (_, mut displays) = catalog()?;
        displays.truncate(1);
        let request_id = random_id();
        let key = catalog_key(&request_id, EPOCH.connection, 1, &displays)?;
        presentation.install_display_catalog(key.clone(), displays.clone())?;
        presentation.select_display(&selection(&key, 42, 1))?;
        pair.host
            .send(Channel::Video, &packet(42, 1, 1, 10)?.encode_validated()?)
            .await?;
        wait_until(|| Ok(presentation.poll_video()?.is_some())).await?;

        // No ACK may install a different source, connection, request, revision
        // jump, or incorrect hash. Failed attempts leave the old grant intact.
        for (id, connection, revision, source, corrupt) in [
            (request_id.clone(), EPOCH.connection, 2, 77, false),
            (random_id(), EPOCH.connection, 2, 42, false),
            (request_id.clone(), EPOCH.connection + 1, 2, 42, false),
            (request_id.clone(), EPOCH.connection, 3, 42, false),
            (request_id.clone(), EPOCH.connection, 2, 42, true),
        ] {
            let mut changed = displays.clone();
            changed[0].source = source;
            let mut invalid = catalog_key(&id, connection, revision, &changed)?;
            if corrupt {
                invalid.sha256[0] ^= 1;
            }
            assert!(
                presentation
                    .install_display_catalog(invalid, changed)
                    .is_err()
            );
            assert_eq!(
                presentation.layout(42)?.map(|layout| layout.epoch.layout),
                Some(1)
            );
        }
        presentation.suspend_display()?;
        displays[0].width = 48;
        displays[0].height = 64;
        let rotated = catalog_key(&request_id, EPOCH.connection, 2, &displays)?;
        presentation.install_display_catalog(rotated.clone(), displays)?;
        assert!(presentation.layout(42)?.is_none());
        assert!(presentation.poll_video()?.is_none());
        presentation.select_display(&selection(&rotated, 42, 2))?;
        // Old reliable-stream packets are discarded before their old geometry
        // can touch the new decoder or advance source sequence/PTS history.
        pair.host
            .send(Channel::Video, &packet(42, 1, 2, 11)?.encode_validated()?)
            .await?;
        let mut config = selected(42).codec;
        config.width = 48;
        config.height = 64;
        let encoded =
            Vp8Encoder::new(config)?.encode(&[255, 0, 0, 255].repeat(48 * 64), 20, true)?;
        let mut next = packet(42, 2, 2, 20)?;
        next.width = 48;
        next.height = 64;
        next.payload = encoded.data;
        next.keyframe = encoded.keyframe;
        pair.host
            .send(Channel::Video, &next.encode_validated()?)
            .await?;
        wait_until(|| {
            if let Some(frame) = presentation.poll_video()? {
                assert_eq!(
                    (
                        frame.source,
                        frame.epoch.layout,
                        frame.width,
                        frame.height,
                        frame.sequence
                    ),
                    (42, 2, 48, 64, 2)
                );
                return Ok(true);
            }
            Ok(false)
        })
        .await?;
        next.sequence = 1;
        next.pts_90khz = 21;
        pair.host
            .send(Channel::Video, &next.encode_validated()?)
            .await?;
        wait_until(|| Ok(receiver.monitor().status().finished)).await?;
        assert!(
            receiver
                .monitor()
                .status()
                .error
                .is_some_and(|error| error.contains("sequence or PTS replay"))
        );
        assert!(presentation.poll_video().is_err());
    }
    Ok(())
}
