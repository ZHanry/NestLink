#[cfg(windows)]
fn main() {
    use clap::Parser;
    let args = nestlink_privileged::windows::BrokerArgs::parse();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| runtime.block_on(nestlink_privileged::windows::run(args)));
    if let Err(error) = result {
        eprintln!("NestLink privileged input broker stopped: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("NestLink privileged input broker is available only on Windows.");
    std::process::exit(1);
}
