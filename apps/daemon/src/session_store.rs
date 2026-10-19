//! Opt-in management recovery. No password or platform grant is persisted.
use nestlink_app_core::ManagementLoginStore;
use nestlink_auth::VaultKey;
use nestlink_platform_security::{read_private, replace_private_metadata};
use std::{io, path::PathBuf, sync::Mutex};

pub(crate) struct SessionStore {
    directory: PathBuf,
    key: Mutex<Option<VaultKey>>,
}
impl SessionStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            key: Mutex::new(None),
        }
    }
    fn binding(&self) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(nestlink_auth::token_hash(
            "management-store",
            &self.directory.to_string_lossy(),
        ))
    }
    fn with_key<T>(&self, action: impl FnOnce(&VaultKey) -> io::Result<T>) -> io::Result<T> {
        nestlink_platform_security::check_private_directory(&self.directory)?;
        let mut key = self
            .key
            .lock()
            .map_err(|_| io::Error::other("login store unavailable"))?;
        if key.is_none() {
            *key = Some(VaultKey::from_bytes(self.os_key()?));
        }
        action(
            key.as_ref()
                .ok_or_else(|| io::Error::other("login key unavailable"))?,
        )
    }
    #[cfg(windows)]
    fn os_key(&self) -> io::Result<[u8; 32]> {
        let path = self.directory.join("management-login.key");
        match nestlink_platform_security::load_key(&path) {
            Ok(key) => Ok(*key),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let key = zeroize::Zeroizing::new(nestlink_auth::random_bytes());
                nestlink_platform_security::create_key(&path, &key)?;
                Ok(*key)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(unix)]
    fn os_key(&self) -> io::Result<[u8; 32]> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let binding = self.binding();
        let saved = secret_service(
            &["lookup", "application", "NestLink", "instance", &binding],
            None,
        )?;
        if !saved.is_empty() {
            let bytes = zeroize::Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(saved.trim())
                    .map_err(|_| io::Error::other("invalid login key"))?,
            );
            return bytes
                .as_slice()
                .try_into()
                .map_err(|_| io::Error::other("invalid login key"));
        }
        let key = zeroize::Zeroizing::new(nestlink_auth::random_bytes::<32>());
        let text = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(*key));
        secret_service(
            &[
                "store",
                "--label=NestLink management login",
                "application",
                "NestLink",
                "instance",
                &binding,
            ],
            Some(text.as_bytes()),
        )?;
        Ok(*key)
    }
    pub(crate) async fn restore(&self) -> Option<nestlink_sdk::Sdk> {
        if !self.enabled() {
            return None;
        }
        let cipher = read_private(&self.directory.join("management-login.enc"), 16424).ok()?;
        let plain = self
            .with_key(|key| {
                key.decrypt_management(&self.binding(), &cipher)
                    .map_err(|_| io::Error::other("login recovery could not be decrypted"))
            })
            .ok()?;
        match nestlink_sdk::Sdk::resume_login(&plain).await {
            Ok(sdk) => {
                if let Ok(Some(next)) = sdk.export_login() {
                    let _ = self.save(&next);
                }
                Some(sdk)
            }
            Err(nestlink_sdk::SdkError::SignIn | nestlink_sdk::SdkError::Trust) => {
                let _ = self.clear();
                None
            }
            Err(nestlink_sdk::SdkError::Api(status, _)) if status.as_u16() == 401 => {
                let _ = self.clear();
                None
            }
            Err(_) => None,
        }
    }
}
impl ManagementLoginStore for SessionStore {
    fn enabled(&self) -> bool {
        read_private(&self.directory.join("remember-login.json"), 16)
            .is_ok_and(|bytes| bytes.as_slice() == b"true")
    }
    fn save(&self, bytes: &[u8]) -> io::Result<()> {
        if !self.enabled() {
            return self.clear();
        }
        let cipher = self.with_key(|key| {
            key.encrypt_management(&self.binding(), bytes)
                .map_err(|_| io::Error::other("login recovery encryption failed"))
        })?;
        replace_private_metadata(&self.directory.join("management-login.enc"), &cipher)?;
        Ok(())
    }
    fn clear(&self) -> io::Result<()> {
        match std::fs::remove_file(self.directory.join("management-login.enc")) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

#[cfg(unix)]
fn secret_service(args: &[&str], input: Option<&[u8]>) -> io::Result<zeroize::Zeroizing<String>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    // Fail closed when Secret Service is absent or locked; no plaintext fallback.
    let mut child = Command::new("secret-tool")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("keyring input unavailable"))?
            .write_all(input)?;
    } else {
        drop(child.stdin.take());
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OS keyring unavailable",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    // A missing lookup returns 1; a failed store must never be treated as saved.
    if output.stdout.len() > 1024 || (!output.status.success() && input.is_some()) {
        return Err(io::Error::other("OS keyring unavailable"));
    }
    String::from_utf8(output.stdout)
        .map(zeroize::Zeroizing::new)
        .map_err(io::Error::other)
}
