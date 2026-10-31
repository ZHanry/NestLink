//! The ordinary packet owner shares its complete authorization/carrier path.
//! Only descriptor admission and exact OS observation vary by platform.
use super::*;
#[cfg(windows)]
use nestlink_privileged::windows::network_tun::{PacketReceipt, ProviderIdentity, resources};

pub(super) struct OwnerOs {
    #[cfg(windows)]
    receipt: PathBuf,
    #[cfg(windows)]
    original: std::sync::OnceLock<ProviderIdentity>,
}
impl OwnerOs {
    pub fn new(#[cfg(windows)] receipt: PathBuf) -> Result<Self> {
        #[cfg(windows)]
        if !receipt.is_absolute() {
            return Err(
                io::Error::other("absolute administrator-owned Wintun receipt required").into(),
            );
        }
        Ok(Self {
            #[cfg(windows)]
            receipt,
            #[cfg(windows)]
            original: std::sync::OnceLock::new(),
        })
    }
    pub async fn inspect(&self, plan: &TunPlan) -> Result<Option<TunState>> {
        #[cfg(target_os = "linux")]
        {
            linux::inspect(plan).await
        }
        #[cfg(windows)]
        {
            let binding = plan.windows_binding().await?;
            let receipt = match PacketReceipt::read_for_current_process(&self.receipt, &binding) {
                Ok(receipt) => receipt,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            Self::verify_windows(plan, &receipt)?;
            if let Some(original) = self.original.get() {
                if original != &receipt.provider {
                    return Err(
                        io::Error::other("original Wintun provider identity changed").into(),
                    );
                }
            } else {
                let _ = self.original.set(receipt.provider.clone());
            }
            Ok(Some(receipt))
        }
    }
    pub fn ready(&self, state: &TunState) -> bool {
        #[cfg(target_os = "linux")]
        {
            state.up && state.persistent && state.addresses.len() == 2
        }
        #[cfg(windows)]
        {
            state.schema_version == 1
        }
    }
    pub fn verify(&self, plan: &TunPlan, state: &TunState) -> Result {
        #[cfg(target_os = "linux")]
        {
            linux::verify(plan, state, true)
        }
        #[cfg(windows)]
        {
            Self::verify_windows(plan, state)
        }
    }
    #[cfg(windows)]
    fn verify_windows(plan: &TunPlan, state: &TunState) -> Result {
        let snapshot = resources::inspect(&state.provider)?
            .ok_or_else(|| io::Error::other("original Wintun adapter missing"))?;
        snapshot.verify(&plan.local_hosts, &plan.remote_hosts)?;
        if snapshot.digest()? != state.provider.configuration_sha256 {
            return Err(io::Error::other("administrator-attested Wintun state changed").into());
        }
        Ok(())
    }
    pub async fn adopt(&self, plan: &TunPlan, state: &TunState) -> Result<PacketDevice> {
        #[cfg(target_os = "linux")]
        {
            Ok(PacketDevice::linux(linux::adopt(plan, state).await?))
        }
        #[cfg(windows)]
        {
            let binding = plan.windows_binding().await?;
            state.check_current(&binding)?;
            self.verify(plan, state)?;
            let pipe = state.connect().await?;
            self.verify(plan, state)?;
            Ok(PacketDevice::windows(pipe))
        }
    }
    pub async fn absent(&self, plan: &TunPlan) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            Ok(linux::inspect(plan).await?.is_none())
        }
        #[cfg(windows)]
        {
            // Remember the original receipt before it can disappear during
            // cleanup. A removed pathname alone never proves kernel absence.
            if let Some(original) = self.original.get() {
                return Ok(resources::capture(
                    &original.adapter_guid,
                    &original.name,
                    original.provider_sha256,
                )?
                .is_none());
            }
            match self.inspect(plan).await? {
                Some(_) => Ok(false),
                None => Ok(true),
            }
        }
    }
}
