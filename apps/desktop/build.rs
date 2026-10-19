//! Embed the same brand icon into Explorer, shortcuts and the taskbar.
use std::{env, fs, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../brand/nestlink.ico");
    if env::var("CARGO_CFG_TARGET_OS")?.as_str() != "windows" {
        return Ok(());
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let icon = root.join("../../brand/nestlink.ico").canonicalize()?;
    let output = PathBuf::from(env::var("OUT_DIR")?);
    let resource = output.join("nestlink.rc");
    let compiled = output.join("nestlink.res");
    let version = env::var("CARGO_PKG_VERSION")?;
    let numeric = version
        .split('-')
        .next()
        .ok_or("version missing")?
        .replace('.', ",");
    fs::write(
        &resource,
        format!(
            r#"#pragma code_page(65001)
1 ICON "{}"
1 VERSIONINFO
FILEVERSION {},1
PRODUCTVERSION {},1
FILEOS 0x40004
FILETYPE 1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "080404b0"
    BEGIN
      VALUE "CompanyName", "NestLink\0"
      VALUE "FileDescription", "NestLink 远程桌面\0"
      VALUE "FileVersion", "{}\0"
      VALUE "ProductName", "NestLink\0"
      VALUE "ProductVersion", "{}\0"
      VALUE "OriginalFilename", "nestlink-desktop.exe\0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0804, 1200
  END
END
"#,
            icon.to_string_lossy().replace('\\', "/"),
            numeric,
            numeric,
            version,
            version
        ),
    )?;
    let status = Command::new(resource_compiler()?)
        .arg("/nologo")
        .arg(format!("/fo{}", compiled.display()))
        .arg(&resource)
        .status()?;
    if !status.success() {
        return Err("Windows icon resource compilation failed".into());
    }
    println!(
        "cargo:rustc-link-arg-bin=nestlink-desktop={}",
        compiled.display()
    );
    Ok(())
}

fn resource_compiler() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join("rc.exe"))
            .find(|candidate| candidate.is_file())
    }) {
        return Ok(path);
    }
    // Cargo discovers MSVC without requiring a Developer Shell. Locate the
    // installed Windows SDK resource compiler in that ordinary shell too.
    let sdk = env::var_os("WindowsSdkDir")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("ProgramFiles(x86)").map(|root| PathBuf::from(root).join("Windows Kits/10"))
        })
        .ok_or("Windows SDK is required to embed the application icon")?;
    let mut candidates = fs::read_dir(sdk.join("bin"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("10."))
        .map(|entry| entry.path().join("x64/rc.exe"))
        .filter(|candidate| candidate.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates
        .pop()
        .ok_or_else(|| "Windows SDK rc.exe was not found".into())
}
