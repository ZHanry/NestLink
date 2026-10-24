//! Run the GitHub-built artifact under an ordinary Windows interactive user.
//! Only its own NOACTIVATE test window is shown; never captures the screen.
//! Submission is distinct from scanout/performance qualification.
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
    let surface = match GpuVideoSurface::probe_window(config.width, config.height) {
        Ok(surface) => surface,
        Err(error) => {
            println!("SKIP gpu_presenter usable_wgl_surface=false reason={error}");
            return Ok(());
        }
    };
    surface.place(0, 0, config.width, config.height, true)?;
    let outcome = (|| -> io::Result<()> {
        let mut encoder = MfH264Encoder::new(config, false)?;
        let mut presenter =
            match GpuH264Presenter::new(&surface, config.width, config.height, config.fps) {
                Ok(presenter) => presenter,
                Err(error) => {
                    println!("SKIP gpu_presenter usable_gpu_decoder=false reason={error}");
                    return Ok(());
                }
            };
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
            if let Some(packet) = encoder.encode(&pixels, index * 3000, index == 0)? {
                queue.push_back(packet);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while let Some(packet) = queue.front() {
                let step = presenter.submit(accepted + 1, packet.pts_90khz, &packet.data)?;
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
        let deadline = Instant::now() + Duration::from_secs(2);
        while completed < accepted && Instant::now() < deadline {
            let step = presenter.poll()?;
            decoded += u64::from(step.decoded.is_some());
            if let Some(picture) = step.picture {
                completed += 1;
                converted += u64::from(picture.gpu_converted);
                submitted += u64::from(picture.submitted_qpc.is_some());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if accepted == 0 || decoded == 0 || submitted == 0 || converted == 0 {
            return Err(io::Error::other(
                "GPU probe produced no actual hardware output/submission",
            ));
        }
        surface.revoke();
        surface.set_authority_deadline(0);
        if presenter.poll().is_ok() {
            return Err(io::Error::other(
                "revoked GPU presenter accepted processing",
            ));
        }
        println!(
            "gpu_presenter accepted={accepted} decoded_actual_pts={decoded} gpu_blit={converted} submitted={submitted} hardware_dxgi_output_observed=true cpu_readback=false scanout_verified=false performance_qualified=false revoke_rejected=true"
        );
        Ok(())
    })();
    surface.revoke();
    surface.detach();
    outcome?;
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    println!("UNSUPPORTED: Windows WGL/D3D11/MF probe");
}
