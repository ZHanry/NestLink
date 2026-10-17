//! Shared conversion from browser-generated session descriptions to the
//! dictionary accepted by the WebRTC set-description APIs.
use js_sys::Reflect;
use wasm_bindgen::JsValue;
use web_sys::{RtcSdpType, RtcSessionDescriptionInit};

pub(crate) fn rtc_session_description_init(
    description: JsValue,
    kind: RtcSdpType,
) -> Result<RtcSessionDescriptionInit, JsValue> {
    let sdp = Reflect::get(&description, &"sdp".into())?
        .as_string()
        .ok_or_else(|| JsValue::from_str("RTC session description omitted SDP"))?;
    let result = RtcSessionDescriptionInit::new(kind);
    result.set_sdp(&sdp);
    Ok(result)
}
