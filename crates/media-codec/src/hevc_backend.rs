//! Explicit local encoder policy. It is never inferred from a failed codec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HevcEncoderBackend {
    #[default]
    SystemMf,
    AmdAmf,
}
