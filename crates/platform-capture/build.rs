fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/dxgi.cpp");
    println!("cargo:rerun-if-changed=src/dxgi_gpu.cpp");
    if std::env::var("CARGO_CFG_TARGET_OS")? == "windows" {
        cc::Build::new()
            .cpp(true)
            .file("src/dxgi.cpp")
            .file("src/dxgi_gpu.cpp")
            // The Windows SDK C++/WinRT headers select standard <coroutine>
            // in C++20 mode; VS 2026 rejects the C++17 experimental variant.
            .std("c++20")
            .flag_if_supported("/EHsc")
            .warnings(true)
            .warnings_into_errors(true)
            .compile("nestlink_dxgi_capture");
        for library in ["d3d11", "dxgi", "gdi32", "user32", "runtimeobject", "ole32"] {
            println!("cargo:rustc-link-lib={library}");
        }
    }
    println!("cargo:rerun-if-changed=src/pipewire.c");
    if std::env::var("CARGO_CFG_TARGET_OS")? == "linux" {
        let lib = pkg_config::Config::new()
            .atleast_version("1.0.5")
            .probe("libpipewire-0.3")?;
        let mut build = cc::Build::new();
        build
            .file("src/pipewire.c")
            .std("gnu11")
            .warnings(true)
            .warnings_into_errors(true);
        for include in lib.include_paths {
            build.include(include);
        }
        build.compile("nestlink_pipewire_capture");
    }
    Ok(())
}
