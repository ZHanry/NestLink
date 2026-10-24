//! Scalar facts read from the exact live decoder/presenter owner.
//! Unknown adapter/driver metadata stays unknown, never a device-name guess.
use std::io;

#[repr(C)]
#[derive(Default)]
pub(crate) struct RawOwnerObservation {
    pub resource_id: [u8; 16],
    pub adapter_luid: u64,
    pub driver_version: u64,
    pub flags: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerObservation {
    pub resource_id: [u8; 16],
    pub adapter_luid: Option<u64>,
    pub driver_version: Option<u64>,
    /// An actual hardware output was observed; constructor success is insufficient.
    pub hardware_output: bool,
}
impl TryFrom<RawOwnerObservation> for OwnerObservation {
    type Error = io::Error;
    fn try_from(raw: RawOwnerObservation) -> io::Result<Self> {
        if raw.resource_id == [0; 16]
            || raw.flags & !7 != 0
            || raw.flags & 2 != 0 && raw.flags & 1 == 0
        {
            return Err(io::Error::other("invalid native owner observation"));
        }
        Ok(Self {
            resource_id: raw.resource_id,
            adapter_luid: (raw.flags & 1 != 0).then_some(raw.adapter_luid),
            driver_version: (raw.flags & 2 != 0).then_some(raw.driver_version),
            hardware_output: raw.flags & 4 != 0,
        })
    }
}
impl OwnerObservation {
    pub fn same_identity(self, next: Self) -> bool {
        self.resource_id == next.resource_id
            && self.adapter_luid == next.adapter_luid
            && self.driver_version == next.driver_version
    }
    /// Missing metadata may be reported diagnostically, but cannot qualify a
    /// hardware direction announcement or a cached executable capability.
    pub fn require_hardware_identity(self) -> io::Result<()> {
        if !self.hardware_output || self.adapter_luid.is_none() || self.driver_version.is_none() {
            return Err(io::Error::other("unqualified hardware owner identity"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_metadata_cannot_qualify_hardware_and_generation_is_exact() -> io::Result<()> {
        assert!(OwnerObservation::try_from(RawOwnerObservation::default()).is_err());
        let a = OwnerObservation::try_from(RawOwnerObservation {
            resource_id: [1; 16],
            flags: 4,
            ..RawOwnerObservation::default()
        })?;
        assert_eq!(a.adapter_luid, None);
        assert!(a.require_hardware_identity().is_err());
        let b = OwnerObservation {
            adapter_luid: Some(0),
            driver_version: Some(0),
            ..a
        };
        b.require_hardware_identity()?; // Zero is data when the native API says known.
        assert!(!a.same_identity(b));
        assert!(!b.same_identity(OwnerObservation {
            resource_id: [2; 16],
            ..b
        }));
        Ok(())
    }
}
