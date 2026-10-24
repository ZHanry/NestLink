//! Run the GitHub-built artifact under an ordinary Windows interactive user.
//! Only its own NOACTIVATE test window is shown; never captures the screen.
//! Submission is distinct from scanout/performance qualification.
#[cfg(windows)]
fn stage(message: &str) {
    use std::io::Write;
    eprintln!("gpu_presenter_stage={message}");
    let _ = std::io::stderr().flush();
}
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{GpuH264Presenter, GpuVideoSurface, MfH264Encoder, VideoConfig};
    use std::{
        io,
        time::{Duration, Instant},
    };
    let config = VideoConfig {
        width: 640,
        height: 480,
        fps: 30,
        bitrate_kbps: 1000,
    };
    stage("surface_create_begin");
    let surface = match GpuVideoSurface::probe_window(config.width, config.height) {
        Ok(surface) => surface,
        Err(error) => {
            println!("SKIP gpu_presenter usable_wgl_surface=false reason={error}");
            return Ok(());
        }
    };
    stage("surface_create_end_place_begin");
    surface.place(0, 0, config.width, config.height, true)?;
    stage("surface_place_end");
    let outcome = (|| -> io::Result<()> {
        stage("software_encoder_open_begin");
        let mut encoder = MfH264Encoder::new(config, false)?;
        stage("software_encoder_open_end_gpu_presenter_open_begin");
        let mut presenter =
            match GpuH264Presenter::new(&surface, config.width, config.height, config.fps) {
                Ok(presenter) => presenter,
                Err(error) => {
                    println!("SKIP gpu_presenter usable_gpu_decoder=false reason={error}");
                    return Ok(());
                }
            };
        stage("gpu_presenter_open_end");
        let wall_deadline = Instant::now() + Duration::from_secs(20);
        let pixels = [32, 160, 64, 255].repeat((config.width * config.height) as usize);
        let mut accepted = 0u64;
        let mut decoded = 0u64;
        let mut submitted = 0u64;
        let mut converted = 0u64;
        let mut completed = 0u64;
        let mut queue = std::collections::VecDeque::new();
        for index in 0..60u64 {
            if Instant::now() > wall_deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "GPU probe wall deadline",
                ));
            }
            stage(&format!("encode_begin frame={index}"));
            if let Some(packet) = encoder.encode(&pixels, index * 3000, index == 0)? {
                queue.push_back(packet);
            }
            stage(&format!("encode_end frame={index}"));
            let deadline = Instant::now() + Duration::from_secs(2);
            while let Some(packet) = queue.front() {
                stage(&format!("submit_begin sequence={}", accepted + 1));
                let step = presenter.submit(accepted + 1, packet.pts_90khz, &packet.data)?;
                stage(&format!(
                    "submit_end accepted={} decoded={} picture={}",
                    step.accepted,
                    step.decoded.is_some(),
                    step.picture.is_some()
                ));
                if step.accepted {
                    accepted += 1;
                    queue.pop_front();
                }
                decoded += u64::from(step.decoded.is_some());
                if let Some(picture) = step.picture {
                    completed += 1;
                    converted += u64::from(picture.gpu_converted);
                    submitted += u64::from(picture.submitted_qpc.is_some());
                }
                if Instant::now() > deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "GPU probe input stalled",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        stage("drain_begin");
        let deadline = Instant::now() + Duration::from_secs(2);
        while completed < accepted && Instant::now() < deadline {
            stage("poll_begin");
            let step = presenter.poll()?;
            stage("poll_end");
            decoded += u64::from(step.decoded.is_some());
            if let Some(picture) = step.picture {
                completed += 1;
                converted += u64::from(picture.gpu_converted);
                submitted += u64::from(picture.submitted_qpc.is_some());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        stage(&format!(
            "drain_end accepted={accepted} decoded={decoded} completed={completed} converted={converted} submitted={submitted}"
        ));
        // Exercise several decoder-surface/IPC-credit pool turnovers. A single
        // successful frame would miss output starvation under continuous input.
        if accepted < 16 || decoded < 16 || converted < 16 || submitted == 0 {
            return Err(io::Error::other(format!(
                "GPU probe did not sustain hardware output/submission: accepted={accepted} decoded={decoded} converted={converted} submitted={submitted}"
            )));
        }
        stage("revoke_begin");
        surface.revoke();
        surface.set_authority_deadline(0);
        if presenter.poll().is_ok() {
            return Err(io::Error::other(
                "revoked GPU presenter accepted processing",
            ));
        }
        stage("revoke_rejected_presenter_drop_begin");
        drop(presenter);
        stage("presenter_drop_end_encoder_drop_begin");
        drop(encoder);
        stage("encoder_drop_end");
        println!(
            "gpu_presenter accepted={accepted} decoded_actual_pts={decoded} gpu_blit={converted} submitted={submitted} hardware_dxgi_output_observed=true cpu_readback=false scanout_verified=false performance_qualified=false revoke_rejected=true"
        );
        Ok(())
    })();
    stage("surface_detach_begin");
    surface.revoke();
    surface.detach();
    stage("surface_detach_end");
    outcome?;
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    println!("UNSUPPORTED: Windows WGL/D3D11/MF probe");
}
