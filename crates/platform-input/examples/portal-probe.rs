#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let facts = nestlink_platform_input::portal::probe().await?;
    println!("Wayland OS facts: {facts:?}");
    println!(
        "Read-only availability; OS consent and installed-product input acceptance remain required."
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This read-only probe requires a Linux Wayland desktop.");
    std::process::exit(2);
}
