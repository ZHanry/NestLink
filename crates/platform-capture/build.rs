fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/dxgi.cpp");
    if std::env::var("CARGO_CFG_TARGET_OS")? == "windows" {
        cc::Build::new()
            .cpp(true)
            .file("src/dxgi.cpp")
            .std("c++17")
            .warnings(true)
            .warnings_into_errors(true)
            .compile("nestlink_dxgi_capture");
        for library in ["d3d11", "dxgi"] {
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
