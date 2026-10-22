#![cfg_attr(windows, windows_subsystem = "windows")]
use clap::Parser;
use nestlink_desktop::{DesktopApp, theme};
use std::{io, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "nestlink-desktop",
    version,
    about = "NestLink desktop workspace"
)]
struct Args {
    /// Isolated NestLink v15 user state. Never reads legacy client settings.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Verify private diagnostic persistence without starting the desktop.
    #[arg(long, hide = true)]
    check_diagnostics: bool,
    /// Private child-process entry point for a cancellable native chooser.
    #[arg(long, hide = true, value_parser = ["file", "folder"])]
    native_file_selector: Option<String>,
}

fn default_state_directory() -> io::Result<PathBuf> {
    #[cfg(windows)]
    let parent = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let parent = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|value| PathBuf::from(value).join(".local/state"))
        });
    let parent = parent.ok_or_else(|| io::Error::other("user state location unavailable"))?;
    if !parent.is_absolute() {
        return Err(io::Error::other("user state location must be absolute"));
    }
    // Parent creation contains no key material. The daemon creates the private
    // final directory and validates ownership/mode without following links.
    std::fs::create_dir_all(&parent)?;
    Ok(parent.join("NestLink-v15"))
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let directory = match args.state_dir {
        Some(path) => path,
        None => default_state_directory()?,
    };
    if !directory.is_absolute() {
        return Err(io::Error::other("state-dir must be absolute").into());
    }
    // Registered before any UI/bridge/selector work; held through run_native.
    let install_start =
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory = install_start.state_directory(&directory)?;
    if args.check_diagnostics {
        nestlink_desktop::check_layout_diagnostics(&directory)?;
        return Ok(());
    }
    let _desktop_lifetime = nestlink_local_ipc::maintenance::DesktopLease::acquire(&directory)?;
    drop(install_start);
    nestlink_desktop::picker::configure_maintenance_directory(&directory)?;
    if let Some(kind) = args.native_file_selector {
        std::process::exit(nestlink_desktop::picker::run_selector(&kind));
    }
    let Some(_instance) =
        nestlink_local_ipc::maintenance::DesktopInstance::acquire_or_activate(&directory)?
    else {
        return Ok(());
    };
    let tokens = theme::tokens()?;
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([tokens.layout.desktop_width, tokens.layout.desktop_height])
            .with_min_inner_size([tokens.layout.minimum_width, tokens.layout.minimum_height])
            .with_icon(std::sync::Arc::new(theme::icon(64))),
        ..Default::default()
    };
    eframe::run_native(
        "NestLink",
        options,
        Box::new(move |creation| Ok(Box::new(DesktopApp::new(creation, directory, tokens)?))),
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}
