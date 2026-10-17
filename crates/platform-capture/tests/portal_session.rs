//! Production request/FD/controller integration on isolated, owned services.
//! This is development evidence, not compositor consent or product acceptance.
#![cfg(target_os = "linux")]

mod portal_support;
use nestlink_platform_capture::PortalCapture;
use nestlink_platform_input::{
    NativeInput,
    portal::{PortalInput, PortalOptions, PortalView},
};
use nestlink_remote::{
    CleanupStatus,
    input::{InputAction, InputController, InputDevice, InputEpoch, InputEvent, PlatformInput},
    video::{CapturedVideo, VideoController, VideoEpoch},
};
use nestlink_session::StopReason;
use portal_support::{
    Result,
    daemon::Daemon,
    service::{Event, Service},
    session::runtime,
};
use std::time::{Duration, Instant};
use tokio::sync::watch;

fn event(sequence: u64, action: InputAction) -> InputEvent {
    InputEvent {
        epoch: InputEpoch {
            input: 1,
            layout: 1,
            connection: 9,
        },
        sequence,
        action,
    }
}
async fn pixels(video: &VideoController<PortalCapture>) -> Result<CapturedVideo> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(frame) = video.poll()? {
            frame.frame.validate()?;
            assert!(
                frame
                    .frame
                    .pixels
                    .chunks_exact(4)
                    .any(|p| p[0] != 0 || p[1] != 0 || p[2] != 0)
            );
            assert_eq!(frame.logical_point(0, 0)?, (-320, 0));
            return Ok(frame);
        }
        assert!(
            Instant::now() < deadline,
            "owned PipeWire supplied no pixels"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
fn consumer_gone(daemon: &Daemon) -> Result {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let output = daemon.run(daemon.command("pw-dump"))?;
        assert!(output.status.success());
        let objects: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        if !objects
            .as_array()
            .ok_or("invalid pw-dump")?
            .iter()
            .any(|v| v["info"]["props"]["node.name"] == "nestlink-portal-capture")
        {
            return Ok(());
        }
        assert!(Instant::now() < deadline, "capture node survived cleanup");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires scripts/refactor-portal-capture.py and isolated private system/session buses"]
async fn production_portal_pipewire_joint_revocation() -> Result {
    portal_support::isolated()?;
    for with_input in [true, false] {
        let daemon = Daemon::new()?;
        let target = daemon.source()?;
        let service =
            Service::invalid_fd(daemon.socket(), target.node, target.serial, with_input).await?;
        let (_cancel, cancelled) = watch::channel(false);
        if with_input {
            let mut portal =
                PortalInput::request(PortalOptions::current_process(String::new()), cancelled)
                    .await?;
            let control = portal.control();
            assert!(control.is_active());
            assert!(PortalCapture::open(&mut portal).is_err());
            assert!(
                !control.is_active(),
                "failed capture startup must revoke the shared grant immediately"
            );
            assert!(portal.check().is_err());
            assert!(
                portal
                    .inject(PlatformInput::Action(&InputAction::Key {
                        code: 4,
                        down: true
                    }))
                    .is_err()
            );
            assert!(portal.take_pipewire_fd().is_err());
            portal.begin_reset()?;
            portal.reset()?;
        } else {
            let mut portal =
                PortalView::request(PortalOptions::current_process(String::new()), cancelled)
                    .await?;
            let control = portal.control();
            assert!(control.is_active());
            assert!(PortalCapture::open_view(&mut portal).is_err());
            assert!(
                !control.is_active(),
                "failed view startup must revoke the shared grant immediately"
            );
            assert!(portal.check().is_err());
            assert!(portal.take_pipewire_fd().is_err());
            portal.close()?;
        }
        consumer_gone(&daemon)?;
        let events = service.events()?;
        assert_eq!(events.iter().filter(|e| **e == Event::OpenFd).count(), 1);
        assert_eq!(events.iter().filter(|e| **e == Event::Close).count(), 1);
        assert!(!events.iter().any(|e| matches!(
            e,
            Event::Key(..) | Event::Symbol(..) | Event::Button(..) | Event::Motion(..)
        )));
        println!(
            "{}",
            serde_json::json!({"case": "invalid-capture-fd", "with_input": with_input, "grant_revoked": true, "input_calls": 0, "product_acceptance": false})
        );
    }
    for cause in ["logind-lock", "portal-invalidate", "pipewire-source-loss"] {
        let daemon = Daemon::new()?;
        let target = daemon.source()?;
        let service = Service::new(daemon.socket(), target.node, target.serial, true).await?;
        let (_cancel, cancelled) = watch::channel(false);
        // No request_at, synthetic FD, injected PortalInfo or capture start seam.
        let mut portal =
            PortalInput::request(PortalOptions::current_process(String::new()), cancelled).await?;
        assert_eq!(portal.info().streams[0].node_id, target.node);
        assert_eq!(
            portal.info().streams[0].pipewire_serial,
            Some(target.serial)
        );
        let control = portal.control();
        let capture = PortalCapture::open(&mut portal)?;
        assert!(
            portal.take_pipewire_fd().is_err(),
            "FD must transfer exactly once"
        );
        assert!(
            control.is_active(),
            "a rejected duplicate transfer must preserve the running capture"
        );
        let displays = capture.displays().to_vec();
        let layout = portal.layout();
        let mut runtime = runtime(true)?;
        let video = VideoController::attach(
            runtime.channels.lease_control(),
            capture,
            VideoEpoch {
                layout: 1,
                connection: 9,
            },
            displays,
        )?;
        let input = InputController::attach(
            runtime.channels.lease_control(),
            portal,
            InputEpoch {
                input: 1,
                layout: 1,
                connection: 9,
            },
            layout,
        )?;
        daemon.link()?;
        assert_eq!(pixels(&video).await?.frame.source, target.node);
        assert!(input.apply(&event(
            1,
            InputAction::Key {
                code: 0xe4,
                down: true
            }
        ))?);
        assert!(input.apply(&event(
            2,
            InputAction::Pointer {
                button: Some(1),
                down: true,
                x: -200,
                y: 80
            }
        ))?);
        let before = service.events()?;
        assert!(before.contains(&Event::RemoteCreate));
        assert!(before.contains(&Event::RemoteStart));
        assert!(before.contains(&Event::Devices(3, 0)));
        assert!(before.contains(&Event::Sources(2, None)));
        assert!(before.contains(&Event::OpenFd));
        assert!(before.contains(&Event::Key(97, 1)));
        assert!(before.contains(&Event::Button(0x110, 1)));
        assert!(before.contains(&Event::Motion(target.node, 120.0, 80.0)));
        let started = Instant::now();
        match cause {
            "logind-lock" => service.lock().await?,
            "portal-invalidate" => control.invalidate(),
            "pipewire-source-loss" => {
                let mut command = daemon.command("pw-cli");
                command.args(["destroy", &target.node.to_string()]);
                let output = daemon.run(command)?;
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            _ => unreachable!(),
        }
        // Idle detection must stop both controllers without another input or poll.
        let report =
            tokio::time::timeout(Duration::from_secs(2), runtime.channels.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::PlatformChanged, "{cause}");
        // Capture reset conservatively retains the worker's source-loss error
        // even after teardown. Verify that exact report, and independently
        // require all native releases and disappearance of the consumer below.
        let expected_cleanup = if cause == "pipewire-source-loss" {
            CleanupStatus::Failed(std::io::ErrorKind::StaleNetworkFileHandle)
        } else {
            CleanupStatus::Succeeded
        };
        assert_eq!(report.cleanup, expected_cleanup, "{cause}");
        assert!(!control.is_active());
        assert!(video.poll().is_err());
        let stopped = service.events()?;
        assert!(stopped.contains(&Event::Key(97, 0)), "{cause}: {stopped:?}");
        assert!(
            stopped.contains(&Event::Button(0x110, 0)),
            "{cause}: {stopped:?}"
        );
        assert_eq!(stopped.iter().filter(|e| **e == Event::Close).count(), 1);
        service.unlock();
        assert!(
            input
                .apply(&event(
                    3,
                    InputAction::Key {
                        code: 4,
                        down: true
                    }
                ))
                .is_err()
        );
        assert!(video.poll().is_err());
        assert_eq!(
            service.events()?,
            stopped,
            "no input after cleanup or unlock"
        );
        consumer_gone(&daemon)?;
        println!(
            "{}",
            serde_json::json!({"case": cause, "joint_stop": true, "cleanup_report": format!("{:?}", report.cleanup), "input_released": true, "capture_node_removed": true, "elapsed_ms": started.elapsed().as_millis(), "product_acceptance": false})
        );
    }

    // A separate service has no RemoteDesktop interface. A successful request
    // and real pixels prove the view path cannot depend on input authority.
    let daemon = Daemon::new()?;
    let target = daemon.source()?;
    let service = Service::new(daemon.socket(), target.node, target.serial, false).await?;
    let (_cancel, cancelled) = watch::channel(false);
    let mut portal =
        PortalView::request(PortalOptions::current_process(String::new()), cancelled).await?;
    let control = portal.control();
    let capture = PortalCapture::open_view(&mut portal)?;
    assert!(portal.take_pipewire_fd().is_err());
    assert!(
        control.is_active(),
        "a rejected duplicate transfer must preserve the running view"
    );
    let displays = capture.displays().to_vec();
    let mut runtime = runtime(false)?;
    let video = VideoController::attach(
        runtime.channels.lease_control(),
        capture,
        VideoEpoch {
            layout: 1,
            connection: 9,
        },
        displays,
    )?;
    daemon.link()?;
    assert_eq!(pixels(&video).await?.frame.source, target.node);
    service.lock().await?;
    let report =
        tokio::time::timeout(Duration::from_secs(2), runtime.channels.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::PlatformChanged);
    assert_eq!(report.cleanup, CleanupStatus::Succeeded);
    assert!(!control.is_active());
    assert!(video.poll().is_err());
    portal.close()?;
    consumer_gone(&daemon)?;
    let events = service.events()?;
    assert!(events.contains(&Event::ScreenCreate));
    assert!(events.contains(&Event::ScreenStart));
    assert!(events.contains(&Event::Sources(2, Some(0))));
    assert!(events.contains(&Event::OpenFd));
    assert_eq!(events.iter().filter(|e| **e == Event::Close).count(), 1);
    assert!(!events.iter().any(|e| matches!(
        e,
        Event::RemoteCreate
            | Event::RemoteStart
            | Event::Devices(..)
            | Event::Key(..)
            | Event::Symbol(..)
            | Event::Button(..)
            | Event::Motion(..)
    )));
    println!(
        "{}",
        serde_json::json!({"case": "view-only", "real_pixels": true, "remote_interface_present": false, "input_calls": 0, "product_acceptance": false})
    );
    Ok(())
}
