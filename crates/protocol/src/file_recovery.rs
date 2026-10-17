//! Local restart facts. A persisted task never grants current remote access.
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol-spec/native-file-recovery.rs"
));
