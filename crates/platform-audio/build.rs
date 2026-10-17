fn main() {
    println!("cargo:rerun-if-changed=src/wasapi.c");
    println!("cargo:rerun-if-changed=src/wasapi_guids.cpp");
    println!("cargo:rerun-if-changed=src/pipewire_audio.c");
    println!("cargo:rerun-if-changed=src/pipewire_audio.h");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        cc::Build::new()
            .file("src/wasapi.c")
            .warnings(true)
            .warnings_into_errors(true)
            .compile("nestlink_wasapi");
        cc::Build::new()
            .cpp(true)
            .file("src/wasapi_guids.cpp")
            .warnings(true)
            .warnings_into_errors(true)
            .compile("nestlink_wasapi_guids");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=uuid");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        let lib = pkg_config::Config::new()
            .atleast_version("1.0.5")
            .probe("libpipewire-0.3")
            .unwrap_or_else(|error| panic!("PipeWire 1.0.5 headers/library required: {error}"));
        let mut build = cc::Build::new();
        build
            .file("src/pipewire_audio.c")
            .std("gnu11")
            .warnings(true)
            .warnings_into_errors(true);
        for include in lib.include_paths {
            build.include(include);
        }
        build.compile("nestlink_pipewire_audio");
    }
}
