// Four reliable, ordered, binary WebRTC data channels. Their label is part of
// the authorization boundary: a packet on one label never grants authority
// for a different permission.

pub const WEBRTC_FILE_READ_LABEL: &str = "nestlink-file-read-v1";
pub const WEBRTC_FILE_WRITE_LABEL: &str = "nestlink-file-write-v1";
pub const WEBRTC_CLIPBOARD_READ_LABEL: &str = "nestlink-clipboard-read-v1";
pub const WEBRTC_CLIPBOARD_WRITE_LABEL: &str = "nestlink-clipboard-write-v1";

/// One original native business envelope may span up to six SCTP messages.
pub const MAX_WEBRTC_DATA_ENVELOPE_BYTES: usize = 65_536;
/// Maximum encoded protobuf fragment sent as one SCTP message.
pub const MAX_WEBRTC_DATA_FRAGMENT_BYTES: usize = 12_288;
/// Maximum native bytes carried by one fragment.
pub const WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES: usize = 12_000;
pub const MAX_WEBRTC_DATA_FRAGMENTS: usize = 6;

/// Values carried by [`WebRtcDataFragment::channel`]. The DataChannel label
/// must map to this exact value before reassembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum WebRtcDataChannel {
    Unspecified = 0,
    FileRead = 1,
    FileWrite = 2,
    ClipboardRead = 3,
    ClipboardWrite = 4,
}

/// Authenticated outer envelope for one ordered fragment. The permit digest is
/// the immutable permit/transcript binding established by mutual proof for the
/// current peer connection; live authorization is checked separately for each
/// send, dequeue and response consume so a normal lease renewal does not change
/// the identity of an already-proved connection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WebRtcDataFragment {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub permit_sha256: Vec<u8>,
    #[prost(string, tag = "3")]
    pub session_id: String,
    #[prost(uint64, tag = "4")]
    pub connection_generation: u64,
    #[prost(uint64, tag = "5")]
    pub lease_sequence: u64,
    #[prost(enumeration = "WebRtcDataChannel", tag = "6")]
    pub channel: i32,
    #[prost(uint64, tag = "7")]
    pub message_sequence: u64,
    #[prost(uint32, tag = "8")]
    pub fragment_index: u32,
    #[prost(uint32, tag = "9")]
    pub fragment_count: u32,
    #[prost(uint32, tag = "10")]
    pub original_len: u32,
    #[prost(bytes = "vec", tag = "11")]
    pub payload: Vec<u8>,
}
