mod build_support;
use std::{env, fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=NESTLINK_CODEC_PREFIX");
    println!("cargo:rerun-if-changed=src/owner_observation.h");
    let prefix = PathBuf::from(env::var_os("NESTLINK_CODEC_PREFIX").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "run scripts/refactor-native-codecs.py build, then set NESTLINK_CODEC_PREFIX to the verified installation")
    })?);
    let root = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| io::Error::other("missing Cargo manifest directory"))?,
    )
    .join("../..");
    let lock = root.join("docs/refactor/native-codecs.lock.json");
    println!("cargo:rerun-if-changed={}", lock.display());
    let triplet = env::var("TARGET").map_err(io::Error::other)?;
    for path in build_support::verify(&prefix, &fs::read(lock)?, &triplet)? {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let include = prefix.join("include");
    let library = prefix.join("lib");
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    assert!(
        matches!(target.as_str(), "windows" | "linux"),
        "native codec target not supported"
    );
    let mut bridge = cc::Build::new();
    bridge.include(&include).files(["src/vp8.c", "src/opus.c"]);
    bridge.warnings(true).warnings_into_errors(true);
    bridge.std("c11");
    if target == "windows" {
        assert!(
            !env::var("CARGO_CFG_TARGET_FEATURE")
                .unwrap_or_default()
                .split(',')
                .any(|f| f == "crt-static"),
            "native codec prefix requires the dynamic MSVC runtime"
        );
        bridge.static_crt(false);
    }
    bridge.compile("nestlink_codec_bridge");
    if target == "windows" {
        cc::Build::new()
            .cpp(true)
            .std("c++17")
            .flag_if_supported("/EHsc")
            .file("src/windows_mf.cpp")
            .file("src/windows_gpu_presenter.cpp")
            .warnings(true)
            .warnings_into_errors(true)
            .static_crt(false)
            .compile("nestlink_mf_bridge");
        for library in [
            "mfplat", "mf", "mfuuid", "ole32", "oleaut32", "strmiids", "d3d11", "dxgi", "opengl32",
            "comctl32", "user32", "gdi32",
        ] {
            println!("cargo:rustc-link-lib={library}");
        }
        println!("cargo:rerun-if-changed=src/windows_mf.cpp");
        println!("cargo:rerun-if-changed=src/windows_gpu_presenter.cpp");
    }
    println!("cargo:rustc-link-search=native={}", library.display());
    println!("cargo:rustc-link-lib=static=vpx");
    println!("cargo:rustc-link-lib=static=opus");
    if target != "windows" {
        println!("cargo:rustc-link-lib=m");
    }
    if target == "linux" {
        println!("cargo:rustc-link-lib=pthread");
    }
    for path in ["src/vp8.c", "src/opus.c"] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed=build_support.rs");
    Ok(())
}
