use nestlink_remote::input::{InputAction, InputLayout};
use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const FRAME_BYTES: usize = 65536;
pub const TEXT_BYTES: usize = 4096;
pub const IO_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
pub const CONSENT_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
pub const WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum BrokerError {
    #[error("privileged input authorization rejected")]
    Authorization,
    #[error("privileged input permission missing")]
    Permission,
    #[error("privileged input lease expired")]
    Expired,
    #[error("privileged input replay rejected")]
    Replay,
    #[error("privileged input epoch changed")]
    Epoch,
    #[error("privileged input layout rejected")]
    Layout,
    #[error("privileged input platform is unavailable")]
    Platform,
    #[error("privileged input cleanup did not complete")]
    Cleanup,
    #[error("privileged input clock changed")]
    Clock,
    #[error("privileged input user runtime stopped")]
    Stopped,
    #[error("privileged input protocol rejected")]
    Protocol,
    #[error("privileged input operation is already pending")]
    Busy,
    #[error("privileged input local consent denied")]
    ConsentDenied,
    #[error("privileged input local IPC failed")]
    Io,
    #[error("privileged input local IPC timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, BrokerError>;

/// Created by the broker's local clocks; never accepted from a wire request.
#[derive(Clone, Copy)]
pub struct Stamp {
    pub monotonic_ms: u64,
    pub unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}
impl Layout {
    pub fn valid(self) -> bool {
        self.width > 0
            && self.height > 0
            && self.width <= 32768
            && self.height <= 32768
            && self.left.checked_add_unsigned(self.width).is_some()
            && self.top.checked_add_unsigned(self.height).is_some()
    }
    pub fn contains(self, x: i32, y: i32) -> bool {
        self.valid()
            && i64::from(x) >= i64::from(self.left)
            && i64::from(y) >= i64::from(self.top)
            && i64::from(x) < i64::from(self.left) + i64::from(self.width)
            && i64::from(y) < i64::from(self.top) + i64::from(self.height)
    }
    pub fn contains_layout(self, other: Self) -> bool {
        other.valid()
            && self.contains(other.left, other.top)
            && self.contains(
                (i64::from(other.left) + i64::from(other.width) - 1) as i32,
                (i64::from(other.top) + i64::from(other.height) - 1) as i32,
            )
    }
}
impl From<InputLayout> for Layout {
    fn from(value: InputLayout) -> Self {
        Self {
            left: value.left,
            top: value.top,
            width: value.width,
            height: value.height,
        }
    }
}
impl From<Layout> for InputLayout {
    fn from(value: Layout) -> Self {
        Self {
            left: value.left,
            top: value.top,
            width: value.width,
            height: value.height,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBinding {
    pub session_id: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub input_epoch: u64,
    pub layout_epoch: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub nonce: [u8; 32],
    pub binding: GrantBinding,
    pub layout: Layout,
}

// Intentionally no Debug on signed permits, grants or text-bearing messages.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerAction {
    Key {
        code: u16,
        down: bool,
    },
    Pointer {
        button: Option<u8>,
        down: bool,
        x: i32,
        y: i32,
    },
    Text {
        text: String,
    },
}
impl BrokerAction {
    pub fn into_native(self, layout: Layout) -> Result<InputAction> {
        match self {
            Self::Key { code, down } if (4..=0xe7).contains(&code) => {
                Ok(InputAction::Key { code, down })
            }
            Self::Pointer { button, down, x, y }
                if button.is_none_or(|value| (1..=5).contains(&value))
                    && (button.is_some() || !down)
                    && layout.contains(x, y) =>
            {
                Ok(InputAction::Pointer { button, down, x, y })
            }
            Self::Text { text }
                if !text.is_empty()
                    && text.len() <= TEXT_BYTES
                    && !text
                        .chars()
                        .any(|value| value.is_control() && value != '\n' && value != '\t') =>
            {
                Ok(InputAction::Text(text))
            }
            _ => Err(BrokerError::Protocol),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Authorize {
        signed_permit: String,
        connection_generation: u64,
        input_epoch: u64,
        layout_epoch: u64,
        layout: Layout,
    },
    Renew {
        nonce: [u8; 32],
        signed_permit: String,
    },
    Input {
        nonce: [u8; 32],
        binding: GrantBinding,
        sequence: u64,
        action: BrokerAction,
    },
    ReleaseAll {
        nonce: [u8; 32],
        binding: GrantBinding,
        sequence: u64,
    },
    Revoke {
        nonce: [u8; 32],
    },
    // Empty struct variants still serialize as {"operation":"..."}, while
    // serde checks deny_unknown_fields instead of ignoring unit-variant data.
    StopUser {},
    Status {},
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub id: u64,
    pub command: Command,
}
impl Request {
    pub fn validate(&self, previous_id: u64) -> Result<()> {
        if self.version != VERSION
            || self.id <= previous_id
            || self.id == 0
            || self.id > i64::MAX as u64
        {
            return Err(BrokerError::Protocol);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerState {
    Idle,
    Active,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub state: BrokerState,
    pub cleanup_failed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplyValue {
    Granted { grant: Grant },
    Renewed { binding: GrantBinding },
    Applied {},
    Released {},
    Revoked {},
    Stopped {},
    State { value: Status },
    Denied { code: BrokerError },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u16,
    pub id: u64,
    pub result: ReplyValue,
}

pub async fn read<S: tokio::io::AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    stream: &mut S,
) -> Result<T> {
    use tokio::io::AsyncReadExt;
    let length = stream.read_u32_le().await.map_err(|_| BrokerError::Io)? as usize;
    if length == 0 || length > FRAME_BYTES {
        return Err(BrokerError::Protocol);
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| BrokerError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| BrokerError::Protocol)
}
pub async fn write<S: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    stream: &mut S,
    value: &T,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| BrokerError::Protocol)?);
    if bytes.is_empty() || bytes.len() > FRAME_BYTES {
        return Err(BrokerError::Protocol);
    }
    stream
        .write_u32_le(bytes.len() as u32)
        .await
        .map_err(|_| BrokerError::Io)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| BrokerError::Io)?;
    stream.flush().await.map_err(|_| BrokerError::Io)
}
