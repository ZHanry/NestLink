//! Receiver observations on the original authenticated VideoFeedback route.
//! These measurements grant no permission, format or replacement session.
use crate::{ContractError, ErrorCode, VIDEO_FEEDBACK_BYTES};
use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "native-receiver-qos-v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverContext {
    pub connection_generation: u64,
    pub layout_epoch: u64,
    pub source: u32,
    pub format_epoch: u64,
    pub format_sha256: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverReport {
    pub context: ReceiverContext,
    pub report_sequence: u64,
    pub last_sequence: u64,
    pub window_ms: u32,
    pub received_payload_bytes: u64,
    pub received_frames: u32,
    /// External decoder output is asynchronous; absence means unmeasured.
    pub decoded_frames: Option<u32>,
    pub maximum_decode_us: Option<u64>,
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid receiver QoS report")
}
impl ReceiverReport {
    pub fn validate(&self) -> Result<(), ContractError> {
        let c = &self.context;
        if [c.connection_generation,c.layout_epoch,self.report_sequence,self.last_sequence].iter().any(|v| *v==0 || *v>i64::MAX as u64)
            || c.format_epoch>i64::MAX as u64
            || !((c.format_epoch==0 && c.format_sha256.is_empty()) || (c.format_epoch>0 && c.format_sha256.len()==32 && c.format_sha256.iter().any(|b|*b!=0)))
            || !(250..=2000).contains(&self.window_ms)
            || self.received_payload_bytes==0 || self.received_payload_bytes>256*1024*1024
            || self.received_frames==0 || self.received_frames>4096
            || self.decoded_frames.is_some_and(|v|v>self.received_frames)
            || self.maximum_decode_us.is_some_and(|v|v>10_000_000)
            || self.decoded_frames.is_some()!=self.maximum_decode_us.is_some()
        {return Err(invalid());}
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut out=b"NLQF\x01".to_vec();
        out.extend_from_slice(&serde_json::to_vec(self).map_err(|_|invalid())?);
        if out.len() as u64>VIDEO_FEEDBACK_BYTES {return Err(invalid());}
        Ok(out)
    }
    pub fn decode(bytes:&[u8])->Result<Self,ContractError>{
        if bytes.len() as u64>VIDEO_FEEDBACK_BYTES || bytes.get(..5)!=Some(b"NLQF\x01") {return Err(invalid());}
        let value:Self=serde_json::from_slice(&bytes[5..]).map_err(|_|invalid())?;
        if value.encode()?.as_slice()!=bytes {return Err(invalid());}
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_receiver_observations_preserve_unknown_and_reject_malformed_context() -> Result<(),ContractError> {
        let value=ReceiverReport{context:ReceiverContext{connection_generation:2,layout_epoch:3,source:0,format_epoch:0,format_sha256:Vec::new()},report_sequence:1,last_sequence:10,window_ms:500,received_payload_bytes:6000,received_frames:10,decoded_frames:None,maximum_decode_us:None};
        let bytes=value.encode()?;
        assert_eq!(ReceiverReport::decode(&bytes)?,value);
        for end in 0..bytes.len(){assert!(ReceiverReport::decode(&bytes[..end]).is_err());}
        let mut tail=bytes.clone();tail.push(b' ');assert!(ReceiverReport::decode(&tail).is_err());
        let mut invalid_value=value.clone();invalid_value.context.format_epoch=1;assert!(invalid_value.encode().is_err());
        invalid_value=value.clone();invalid_value.decoded_frames=Some(0);assert!(invalid_value.encode().is_err());
        invalid_value=value;invalid_value.maximum_decode_us=Some(0);assert!(invalid_value.encode().is_err());
        Ok(())
    }
}
