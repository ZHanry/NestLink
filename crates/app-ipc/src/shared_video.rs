//! Original-decoder NV12 descriptors on one authenticated native TLS stream.
//! JSON values describe resources; only the private native leases own them.
use crate::{Error, compressed_video::CompressedContext};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVideoContext {
    pub media: CompressedContext,
    pub ring_id: [u8;16],
    pub adapter_luid: u64,
    pub handles: [u64;3],
    pub resource_ids: [[u8;16];3],
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub qpc_frequency: u64,
}
impl SharedVideoContext {
    pub fn validate(&self) -> Result<(),Error> {
        self.media.validate()?;
        let b = &self.media.binding;
        let Some(format) = self.media.video_format()? else {return Err(Error::Protocol);};
        let contract = nestlink_app_core::hevc_main8_contract(format).map_err(|_| Error::Protocol)?;
        let counters = [b.ui_generation,b.connection_generation,b.stream_epoch,self.media.catalog_revision,self.media.selection_sequence,self.media.layout_epoch,self.media.decode_epoch,self.media.configuration_id];
        if self.media.ipc_version != 3 || !nestlink_protocol::valid_id(&b.runtime_id) || !nestlink_protocol::valid_id(&b.request_id)
            || counters.iter().any(|value| *value == 0 || *value > i64::MAX as u64)
            || b.stream_id == [0;16] || self.media.decode_epoch != b.stream_epoch
            || self.media.configuration_id != self.media.format_epoch
            || self.media.decoder_hardware.is_none_or(|hardware| hardware.adapter_luid != self.adapter_luid)
            || (self.width,self.height) != (contract.config().width,contract.config().height)
            || self.ring_id == [0;16] || self.resource_ids.contains(&[0;16])
            || self.handles.iter().any(|handle| *handle == 0 || usize::try_from(*handle).is_err())
            || self.handles[0] == self.handles[1] || self.handles[0] == self.handles[2] || self.handles[1] == self.handles[2]
            || self.resource_ids[0] == self.resource_ids[1] || self.resource_ids[0] == self.resource_ids[2] || self.resource_ids[1] == self.resource_ids[2]
            || self.bytes != u64::from(self.width)*u64::from(self.height)*3/2*3 || self.bytes > 128*1024*1024
            || self.qpc_frequency == 0 || self.qpc_frequency > i64::MAX as u64 / 5
        {return Err(Error::Protocol);}
        Ok(())
    }
    #[cfg(windows)]
    pub fn native_ring(&self) -> Result<nestlink_app_core::SharedRingDescriptor,Error> {
        self.validate()?;
        Ok(nestlink_app_core::SharedRingDescriptor {ring_id:self.ring_id, adapter_luid:self.adapter_luid, handles:self.handles, resource_ids:self.resource_ids, width:self.width,height:self.height,bytes:self.bytes})
    }
    #[cfg(windows)]
    pub(crate) fn binding(&self) -> crate::NativeVideoBinding {
        let b = &self.media.binding;
        crate::NativeVideoBinding {runtime_id:b.runtime_id.clone(),ui_generation:b.ui_generation,request_id:b.request_id.clone(),connection_generation:b.connection_generation,source:b.source}
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedFrameDescriptor {
    pub context: SharedVideoContext,
    pub native_sequence: u64,
    pub token: u64,
    pub pts_90khz: u64,
    pub slot: u32,
    pub acquire_key: u64,
    pub release_key: u64,
    pub resource_expires_qpc: u64,
    pub not_after_qpc: u64,
}
impl SharedFrameDescriptor {
    pub fn validate(&self) -> Result<(),Error> {
        self.context.validate()?;
        if self.native_sequence == 0 || self.native_sequence > i64::MAX as u64 || self.token == 0 || self.token > i64::MAX as u64
            || self.pts_90khz > i64::MAX as u64 || self.slot >= 3 || self.acquire_key == 0 || self.acquire_key >= i64::MAX as u64
            || self.acquire_key.is_multiple_of(2) || self.release_key != self.acquire_key + 1
            || self.resource_expires_qpc == 0 || self.resource_expires_qpc > i64::MAX as u64
            || self.not_after_qpc == 0 || self.not_after_qpc > self.resource_expires_qpc
        {return Err(Error::Protocol);}
        Ok(())
    }
    #[cfg(windows)]
    pub fn native_frame(&self) -> Result<nestlink_app_core::SharedFrameDescriptor,Error> {
        self.validate()?;
        Ok(nestlink_app_core::SharedFrameDescriptor {token:self.token,pts_90khz:self.pts_90khz,acquire_key:self.acquire_key,release_key:self.release_key,expires_qpc:self.resource_expires_qpc,slot:self.slot,reserved:0})
    }
}
#[cfg(windows)]
#[derive(Serialize,Deserialize)]
#[serde(tag="kind",rename_all="snake_case",deny_unknown_fields)]
enum SurfaceMessage {
    Authority {context:SharedVideoContext,sequence:u64,not_after_qpc:u64},
    Frame {descriptor:SharedFrameDescriptor},
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{ImportedSharedFrame,SharedVideoClient,SharedVideoMessage};
#[cfg(windows)]
pub(crate) use native::{open,serve};

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(),Box<dyn std::error::Error + Send + Sync>>;
    fn syntax_context() -> Result<SharedVideoContext,Error> {
        use nestlink_protocol::media_format::{FrameRate,VideoFormat};
        let mut ptl = [0;12]; ptl[0] = 1; ptl[11] = 120;
        let format = VideoFormat::hevc_main8_observed(ptl,640,480,FrameRate::new(30,1).map_err(|_| Error::Protocol)?,4000).map_err(|_| Error::Protocol)?;
        Ok(SharedVideoContext {
            media:CompressedContext {ipc_version:3,catalog_sha256:[1;32],format_epoch:1,format_sha256:format.digest().map_err(|_| Error::Protocol)?,
                format:Some(crate::compressed_video::WireVideoFormat::new(format)?),decoder_hardware:Some(nestlink_protocol::media_authority::HardwareMediaTarget {adapter_luid:7,driver_version:9}),
                binding:crate::compressed_video::NativeCompressedBinding {runtime_id:"00000000-0000-4000-8000-000000000001".into(),ui_generation:1,request_id:"00000000-0000-4000-8000-000000000002".into(),connection_generation:1,source:1,stream_id:[1;16],stream_epoch:2},
                catalog_revision:1,selection_sequence:1,layout_epoch:1,decode_epoch:2,configuration_id:1},
            ring_id:[2;16],adapter_luid:7,handles:[100,101,102],resource_ids:[[3;16],[4;16],[5;16]],width:640,height:480,bytes:640*480*3/2*3,qpc_frequency:10_000_000,
        })
    }
    #[test]
    fn shared_descriptor_syntax_requires_exact_format_owner_ring_and_budget() -> TestResult {
        // Syntax fixtures confer no process capability or GPU execution receipt.
        let context = syntax_context()?;
        context.validate()?;
        for mutation in 0..12 {
            let mut wrong = context.clone();
            match mutation {
                0 => wrong.media.ipc_version = 2,
                1 => wrong.media.binding.stream_id = [0;16],
                2 => wrong.media.binding.stream_epoch += 1,
                3 => wrong.media.binding.runtime_id = "not-a-runtime".into(),
                4 => wrong.media.format_sha256[0] ^= 1,
                5 => wrong.media.configuration_id += 1,
                6 => wrong.adapter_luid += 1,
                7 => wrong.handles[1] = wrong.handles[0],
                8 => wrong.resource_ids[2] = wrong.resource_ids[0],
                9 => wrong.bytes += 1,
                10 => wrong.width += 2,
                _ => wrong.qpc_frequency = 0,
            }
            assert!(wrong.validate().is_err(),"mutation {mutation}");
        }
        Ok(())
    }
    #[test]
    fn shared_frame_cannot_change_keys_slot_sequence_or_resource_deadline() -> TestResult {
        let descriptor = SharedFrameDescriptor {context:syntax_context()?,native_sequence:1,token:1,pts_90khz:100,slot:0,acquire_key:1,release_key:2,resource_expires_qpc:50_000_000,not_after_qpc:1_000_000};
        descriptor.validate()?;
        for mutation in 0..8 {
            let mut wrong = descriptor.clone();
            match mutation {
                0 => wrong.native_sequence = 0,
                1 => wrong.token = 0,
                2 => wrong.pts_90khz = u64::MAX,
                3 => wrong.slot = 3,
                4 => wrong.acquire_key = 2,
                5 => wrong.release_key = 9,
                6 => wrong.resource_expires_qpc = 0,
                _ => wrong.not_after_qpc = wrong.resource_expires_qpc + 1,
            }
            assert!(wrong.validate().is_err(),"mutation {mutation}");
        }
        let mut unknown = serde_json::to_value(&descriptor)?;
        unknown["presented"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SharedFrameDescriptor>(unknown).is_err());
        Ok(())
    }
}
