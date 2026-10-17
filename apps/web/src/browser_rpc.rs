//! Native business RPC sequencing on a proved browser peer. Each owned actor
//! validates and consumes its response even if its UI waiter is abandoned.
use crate::browser_data::{BrowserDataChannels, BrowserDataError, LocalDataConsent};
use crate::i18n::text as t;
use futures_channel::oneshot;
use nestlink_protocol::{
    NativeClipboard, NativeFileRead, NativeFileWrite, SCHEMA_VERSION, native_clipboard,
    native_file_read, native_file_write, webrtc_data::WebRtcDataChannel,
};
use std::{cell::Cell, rc::Rc};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserRpcError {
    Data(BrowserDataError),
    Protocol,
    Busy,
    Refused { code: i32, write_effect: i32 },
    Storage,
    Capacity,
    ClipboardReadUnavailable,
    ClipboardReadTimedOut,
    ClipboardWriteUnconfirmed,
    Cancelled,
}
impl From<BrowserDataError> for BrowserRpcError {
    fn from(error: BrowserDataError) -> Self {
        Self::Data(error)
    }
}
impl std::fmt::Display for BrowserRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Data(BrowserDataError::Denied) => t("本机没有批准这项操作，或批准已撤销。", "This operation has no local approval, or its approval was revoked."),
            Self::Busy | Self::Data(BrowserDataError::Busy) => {
                t("这项操作正在执行，请等待当前操作结束。", "This operation is already running. Wait for it to finish.")
            }
            Self::Refused {
                write_effect: 1, ..
            } => t("被控设备报告剪贴板已写入，但后续处理失败。请先检查结果。", "The remote device reports that its clipboard changed, but later processing failed. Check the result first."),
            Self::Refused {
                write_effect: 2, ..
            } => t("设备剪贴板写入结果未确认。请先检查结果，再决定是否重新发送。", "The remote clipboard write is unconfirmed. Check the result before sending again."),
            Self::Refused { .. } => t("被控设备拒绝了操作，请检查批准范围或重新选择文件夹。", "The remote device refused this operation. Check the approved scope or choose a folder again."),
            Self::Storage => t("浏览器无法读写文件，请检查存储空间和文件权限。", "The browser cannot read or write the file. Check storage space and file permissions."),
            Self::Capacity => t("文件或浏览器暂存空间已达到本次允许的上限。", "The file or temporary browser storage has reached the allowed limit."),
            Self::ClipboardReadUnavailable => {
                t("浏览器无法读取本机剪贴板。请检查站点剪贴板权限与浏览器支持，并在点击后立即重试。", "The browser cannot read your clipboard. Check site permissions and browser support, then retry with a click.")
            }
            Self::ClipboardReadTimedOut => {
                t("读取本机剪贴板超时，文本尚未发送；如果浏览器原操作仍在运行，请等待结束后再试。", "Reading your clipboard timed out. No text was sent. If the browser operation is still running, wait before retrying.")
            }
            Self::ClipboardWriteUnconfirmed => {
                t("本机剪贴板写入结果未确认，内容可能已经改变；浏览器操作结束前不能再次写入。请先检查结果，再决定是否重试。", "Your clipboard write is unconfirmed and its contents may have changed. Wait for the browser operation to finish and check the result before retrying.")
            }
            Self::Cancelled => t("操作已取消。", "Operation cancelled."),
            Self::Protocol | Self::Data(BrowserDataError::Protocol) => {
                t("连接数据核验失败，连接已停止。", "Connection data verification failed. The connection has stopped.")
            }
            _ => t("连接或授权已停止，请重新连接后再试。", "The connection or authorization ended. Reconnect before trying again."),
        })
    }
}
impl std::error::Error for BrowserRpcError {}

struct Direction {
    kind: WebRtcDataChannel,
    sequence: Cell<u64>,
    busy: Cell<bool>,
}
struct Owner {
    data: BrowserDataChannels,
    generation: u64,
    directions: Vec<Rc<Direction>>,
}
#[derive(Clone)]
pub struct BrowserRpc(Rc<Owner>);

enum Envelope {
    Read(NativeFileRead),
    Write(NativeFileWrite),
    Clipboard(NativeClipboard),
}
impl Drop for Envelope {
    fn drop(&mut self) {
        match self {
            Self::Read(message) => {
                if let Some(native_file_read::Action::Chunk(chunk)) = &mut message.action {
                    chunk.data.zeroize();
                }
            }
            Self::Write(message) => {
                if let Some(native_file_write::Action::Chunk(chunk)) = &mut message.action {
                    chunk.data.zeroize();
                }
            }
            Self::Clipboard(message) => match &mut message.action {
                Some(native_clipboard::Action::Write(text)) => text.zeroize(),
                Some(native_clipboard::Action::Text(text)) => {
                    if let Some(text) = &mut text.text {
                        text.zeroize();
                    }
                }
                _ => {}
            },
        }
    }
}
impl Envelope {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, BrowserRpcError> {
        let wire = match self {
            Self::Read(message) => message.encode_validated(),
            Self::Write(message) => message.encode_validated(),
            Self::Clipboard(message) => message.encode_validated(),
        }
        .map_err(|_| BrowserRpcError::Protocol)?;
        Ok(Zeroizing::new(wire))
    }
    fn sequence(&self) -> u64 {
        match self {
            Self::Read(value) => value.sequence,
            Self::Write(value) => value.sequence,
            Self::Clipboard(value) => value.sequence,
        }
    }
    fn decode_reply(&self, wire: &[u8], kind: WebRtcDataChannel) -> Result<Self, BrowserRpcError> {
        let response = match self {
            Self::Read(request) => {
                let response = NativeFileRead::decode_validated(wire)
                    .map_err(|_| BrowserRpcError::Protocol)?;
                if response.connection_generation != request.connection_generation
                    || response.sequence != request.sequence
                    || response.transfer_id != request.transfer_id
                    || !matches!(
                        response.action,
                        Some(
                            native_file_read::Action::Manifest(_)
                                | native_file_read::Action::Chunk(_)
                                | native_file_read::Action::End(_)
                                | native_file_read::Action::Cancelled(true)
                                | native_file_read::Action::Failure(_)
                                | native_file_read::Action::BrowsePage(_)
                                | native_file_read::Action::Roots(_)
                        )
                    )
                {
                    return Err(BrowserRpcError::Protocol);
                }
                Self::Read(response)
            }
            Self::Write(request) => {
                let mut response = Self::Write(
                    NativeFileWrite::decode_validated(wire)
                        .map_err(|_| BrowserRpcError::Protocol)?,
                );
                let Self::Write(value) = &mut response else {
                    return Err(BrowserRpcError::Protocol);
                };
                if value.connection_generation != request.connection_generation
                    || value.sequence != request.sequence
                    || value.transfer_id != request.transfer_id
                    || !matches!(
                        value.action,
                        Some(
                            native_file_write::Action::Ready(_)
                                | native_file_write::Action::Ack(_)
                                | native_file_write::Action::Committed(_)
                                | native_file_write::Action::Cancelled(_)
                                | native_file_write::Action::Failure(_)
                                | native_file_write::Action::Roots(_)
                        )
                    )
                {
                    return Err(BrowserRpcError::Protocol);
                }
                response
            }
            Self::Clipboard(request) => {
                // Protect even an invalid typed reply; its text must not survive
                // rejection in an abandoned actor or protocol mismatch.
                let response = Self::Clipboard(
                    NativeClipboard::decode_validated(wire)
                        .map_err(|_| BrowserRpcError::Protocol)?,
                );
                let Self::Clipboard(value) = &response else {
                    return Err(BrowserRpcError::Protocol);
                };
                let allowed = matches!(
                    value.action,
                    Some(
                        native_clipboard::Action::Failure(_)
                            | native_clipboard::Action::Cancelled(true)
                    )
                ) || (kind == WebRtcDataChannel::ClipboardRead
                    && matches!(value.action, Some(native_clipboard::Action::Text(_))))
                    || (kind == WebRtcDataChannel::ClipboardWrite
                        && matches!(value.action, Some(native_clipboard::Action::Written(true))));
                if value.connection_generation != request.connection_generation
                    || value.sequence != request.sequence
                    || !allowed
                {
                    return Err(BrowserRpcError::Protocol);
                }
                response
            }
        };
        Ok(response)
    }
}

impl BrowserRpc {
    pub fn new(data: BrowserDataChannels, generation: u64) -> Result<Self, BrowserRpcError> {
        if generation == 0 || generation > i64::MAX as u64 {
            return Err(BrowserRpcError::Protocol);
        }
        let directions = [
            WebRtcDataChannel::FileRead,
            WebRtcDataChannel::FileWrite,
            WebRtcDataChannel::ClipboardRead,
            WebRtcDataChannel::ClipboardWrite,
        ]
        .into_iter()
        .filter(|kind| data.has(*kind))
        .map(|kind| {
            Rc::new(Direction {
                kind,
                sequence: Cell::new(0),
                busy: Cell::new(false),
            })
        })
        .collect();
        Ok(Self(Rc::new(Owner {
            data,
            generation,
            directions,
        })))
    }
    pub fn has(&self, kind: WebRtcDataChannel) -> bool {
        self.0.data.has(kind)
    }
    pub fn check(&self, kind: WebRtcDataChannel) -> Result<(), BrowserRpcError> {
        self.0.data.check(kind).map_err(Into::into)
    }
    pub fn close(&self) {
        self.0.data.close();
    }
    fn direction(&self, kind: WebRtcDataChannel) -> Result<Rc<Direction>, BrowserRpcError> {
        self.check(kind)?;
        self.0
            .directions
            .iter()
            .find(|entry| entry.kind == kind)
            .cloned()
            .ok_or(BrowserDataError::Denied.into())
    }
    async fn request(
        &self,
        direction: Rc<Direction>,
        request: Envelope,
        consent: LocalDataConsent,
    ) -> Result<Envelope, BrowserRpcError> {
        if !consent() {
            return Err(BrowserDataError::Denied.into());
        }
        if direction.busy.replace(true) {
            return Err(BrowserRpcError::Busy);
        }
        let guard = DirectionGuard(direction.clone());
        let wire = request.encode()?;
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = async {
                let reply = owner.0.data.exchange(direction.kind, wire, consent.clone()).await?;
                let reply = request.decode_reply(&reply, direction.kind).inspect_err(|_| owner.close())?;
                direction.sequence.set(request.sequence());
                if !consent() {
                    // A completed write is an observed effect, even when a
                    // local toggle changed while its reply was in flight.
                    // Preserve the exact receipt without delivering read data.
                    let write_receipt = (direction.kind == WebRtcDataChannel::ClipboardWrite)
                        || matches!(&reply, Envelope::Write(message)
                            if matches!(message.action, Some(native_file_write::Action::Committed(_)
                                | native_file_write::Action::Cancelled(_) | native_file_write::Action::Failure(_))));
                    if !write_receipt { return Err(BrowserDataError::Denied.into()); }
                }
                Ok(reply)
            }.await;
            drop(guard);
            let _ = sent.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
    }
    fn next_sequence(direction: &Direction) -> Result<u64, BrowserRpcError> {
        direction
            .sequence
            .get()
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or(BrowserRpcError::Protocol)
    }
    pub async fn read(
        &self,
        transfer_id: String,
        action: native_file_read::Action,
        consent: LocalDataConsent,
    ) -> Result<native_file_read::Action, BrowserRpcError> {
        let direction = self.direction(WebRtcDataChannel::FileRead)?;
        let request = Envelope::Read(NativeFileRead {
            schema_version: SCHEMA_VERSION,
            connection_generation: self.0.generation,
            sequence: Self::next_sequence(&direction)?,
            transfer_id,
            action: Some(action),
        });
        let mut response = self.request(direction, request, consent).await?;
        let Envelope::Read(message) = &mut response else {
            return Err(BrowserRpcError::Protocol);
        };
        message.action.take().ok_or(BrowserRpcError::Protocol)
    }
    pub async fn write(
        &self,
        transfer_id: String,
        action: native_file_write::Action,
        consent: LocalDataConsent,
    ) -> Result<native_file_write::Action, BrowserRpcError> {
        let direction = self.direction(WebRtcDataChannel::FileWrite)?;
        let request = Envelope::Write(NativeFileWrite {
            schema_version: SCHEMA_VERSION,
            connection_generation: self.0.generation,
            sequence: Self::next_sequence(&direction)?,
            transfer_id,
            action: Some(action),
        });
        let mut response = self.request(direction, request, consent).await?;
        let Envelope::Write(message) = &mut response else {
            return Err(BrowserRpcError::Protocol);
        };
        message.action.take().ok_or(BrowserRpcError::Protocol)
    }
    pub async fn clipboard(
        &self,
        kind: WebRtcDataChannel,
        action: native_clipboard::Action,
        consent: LocalDataConsent,
    ) -> Result<native_clipboard::Action, BrowserRpcError> {
        if !matches!(
            kind,
            WebRtcDataChannel::ClipboardRead | WebRtcDataChannel::ClipboardWrite
        ) {
            return Err(BrowserRpcError::Protocol);
        }
        let direction = self.direction(kind)?;
        let request = Envelope::Clipboard(NativeClipboard {
            schema_version: SCHEMA_VERSION,
            connection_generation: self.0.generation,
            sequence: Self::next_sequence(&direction)?,
            action: Some(action),
        });
        let mut response = self.request(direction, request, consent).await?;
        let Envelope::Clipboard(message) = &mut response else {
            return Err(BrowserRpcError::Protocol);
        };
        message.action.take().ok_or(BrowserRpcError::Protocol)
    }
}
struct DirectionGuard(Rc<Direction>);
impl Drop for DirectionGuard {
    fn drop(&mut self) {
        self.0.busy.set(false);
    }
}
