// Local desktop consent only. Pins and signed permits never come from this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedInputAction {
    Status,
    Start,
    Stop,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedInputState {
    Unsupported,
    Disabled,
    Starting,
    Ready,
    Active,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedInputStatus {
    pub state: PrivilegedInputState,
    pub cleanup_failed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedInputError {
    Unsupported,
    Unauthorized,
    Busy,
    StaleGeneration,
    Unavailable,
    Cleanup,
    Stopped,
}
