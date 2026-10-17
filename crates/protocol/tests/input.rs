use nestlink_protocol::{
    ErrorCode, INPUT_BYTES, InputCommand, decode_bounded, input_command::Action,
};
use prost::Message;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    let text = value.as_str().ok_or("invalid vector")?;
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
#[test]
fn shared_input_matches_independent_utf8_and_signed_coordinate_vectors() -> Result {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/vectors/input-v1.json"))?;
    for (field, pointer) in [("text_hex", false), ("pointer_hex", true)] {
        let encoded = bytes(&vector[field])?;
        let command: InputCommand = decode_bounded(&encoded, INPUT_BYTES)?;
        command.validate()?;
        assert_eq!(command.connection_generation, 9);
        assert_eq!(command.encode_to_vec(), encoded);
        if pointer {
            let Some(Action::Pointer(point)) = command.action else {
                return Err("missing pointer".into());
            };
            assert_eq!(
                (point.x, point.y, point.button, point.down),
                (-5, 10, Some(1), true)
            );
        } else {
            assert_eq!(command.action, Some(Action::Text("中文提交".into())));
        }
    }
    Ok(())
}
#[test]
fn unknown_action_future_schema_and_oversized_input_fail_closed() -> Result {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/vectors/input-v1.json"))?;
    let mut encoded = bytes(&vector["text_hex"])?;
    encoded[10] = 0x52; // unknown oneof field 10, with the same wire type
    let command: InputCommand = decode_bounded(&encoded, INPUT_BYTES)?;
    assert!(command.validate().is_err());
    let mut command: InputCommand = decode_bounded(&bytes(&vector["text_hex"])?, INPUT_BYTES)?;
    command.schema_version = 2;
    assert_eq!(
        command.validate().err().map(|e| e.code),
        Some(ErrorCode::ProtocolMismatch)
    );
    command.schema_version = 1;
    command.action = Some(Action::Text("x".repeat(INPUT_BYTES as usize)));
    assert_eq!(
        command.validate().err().map(|e| e.code),
        Some(ErrorCode::CapacityExceeded)
    );
    assert!(
        decode_bounded::<InputCommand>(&vec![0; INPUT_BYTES as usize + 1], INPUT_BYTES).is_err()
    );
    Ok(())
}

#[test]
fn ordered_release_and_host_logical_layout_match_independent_vectors() -> Result {
    // Protobuf field order and signed zigzag coordinates written independently
    // of the generated Rust encoder. Input layout includes a negative origin.
    let release = [0x08, 1, 0x10, 2, 0x18, 3, 0x20, 9, 0x28, 5, 0x48, 1];
    let mut command: InputCommand = decode_bounded(&release, INPUT_BYTES)?;
    command.validate()?;
    assert_eq!(command.action, Some(Action::ReleaseAll(true)));
    assert_eq!(command.encode_to_vec(), release);
    command.action = Some(Action::ReleaseAll(false));
    assert!(command.validate().is_err());
    let bytes = [
        0x08, 1, 0x10, 9, 0x18, 1, 0x20, 2, 0x30, 0x9f, 1, 0x40, 80, 0x48, 40,
    ];
    let mut layout: nestlink_protocol::NativeInputLayout = decode_bounded(&bytes, INPUT_BYTES)?;
    layout.validate()?;
    assert_eq!(
        (layout.left, layout.top, layout.width, layout.height),
        (-80, 0, 80, 40)
    );
    assert_eq!(layout.encode_to_vec(), bytes);
    layout.width = 0;
    assert!(layout.validate().is_err());
    layout.width = 80;
    layout.left = i32::MAX;
    assert!(layout.validate().is_err());
    Ok(())
}
