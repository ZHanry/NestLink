//! Explicit local encoder policy. It is never inferred from a failed codec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HevcEncoderBackend {
    #[default]
    SystemMf,
    AmdAmf,
}

/// Local immutable implementation/runtime selection, independent of wire codec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HevcEncoderSelection {
    backend: HevcEncoderBackend,
    runtime_version: Option<u64>,
}
impl HevcEncoderSelection {
    pub fn new(backend: HevcEncoderBackend, runtime_version: Option<u64>) -> std::io::Result<Self> {
        match (backend, runtime_version) {
            (HevcEncoderBackend::SystemMf, None) => {},
            (HevcEncoderBackend::AmdAmf, Some(version)) if version >> 48 == 1 => {},
            _ => return Err(std::io::Error::other("HEVC local backend/runtime selection is incomplete")),
        }
        Ok(Self { backend, runtime_version })
    }
    pub fn backend(self) -> HevcEncoderBackend { self.backend }
    pub fn runtime_version(self) -> Option<u64> { self.runtime_version }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn implementation_runtime_pairs_are_explicit_and_never_interchangeable() -> std::io::Result<()> {
        assert_eq!(HevcEncoderSelection::new(HevcEncoderBackend::SystemMf, None)?, HevcEncoderSelection::default());
        assert!(HevcEncoderSelection::new(HevcEncoderBackend::SystemMf, Some(1 << 48)).is_err());
        for version in [None, Some(0), Some(2 << 48)] {
            assert!(HevcEncoderSelection::new(HevcEncoderBackend::AmdAmf, version).is_err());
        }
        let amf = HevcEncoderSelection::new(HevcEncoderBackend::AmdAmf, Some((1 << 48) | (4 << 32)))?;
        assert_eq!(amf.backend(), HevcEncoderBackend::AmdAmf);
        assert_ne!(amf, HevcEncoderSelection::default());
        assert_ne!(amf, HevcEncoderSelection::new(HevcEncoderBackend::AmdAmf, Some(1 << 48))?);
        Ok(())
    }
}
