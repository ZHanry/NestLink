//! One explicitly selected encoder on the original worker. Errors never select
//! another implementation, adapter, profile or source.
#![allow(unsafe_code)]
use crate::{
    HevcBackendObservation, HevcEncoderBackend, OwnerObservation, VideoConfig, windows_amf,
    windows_mf,
};
use std::{ffi::c_void, io};

pub(crate) enum Encoder {
    Mf(windows_mf::Transform),
    Amf(windows_amf::Transform),
}
impl Encoder {
    pub(crate) fn backend(&self) -> HevcEncoderBackend {
        match self {
            Self::Mf(_) => HevcEncoderBackend::SystemMf,
            Self::Amf(_) => HevcEncoderBackend::AmdAmf,
        }
    }
    pub(crate) unsafe fn open(
        config: VideoConfig,
        device: *mut c_void,
        depth: u8,
        backend: HevcEncoderBackend,
    ) -> io::Result<Self> {
        // SAFETY: delegated original owner-thread device and exact depth contract.
        unsafe {
            match backend {
                HevcEncoderBackend::SystemMf => (if depth == 8 {
                    windows_mf::Transform::new_hevc(config, device, true, true)
                } else {
                    windows_mf::Transform::new_hevc_depth(config, device, true, true, depth)
                })
                .map(Self::Mf),
                HevcEncoderBackend::AmdAmf => {
                    windows_amf::Transform::new(config, device, depth).map(Self::Amf)
                }
            }
        }
    }
    pub(crate) fn owner_observation(&self) -> io::Result<OwnerObservation> {
        match self {
            Self::Mf(value) => crate::windows_hevc_owner::observation(value),
            Self::Amf(value) => Ok(value.observation()?.owner),
        }
    }
    pub(crate) fn runtime_version(&self) -> io::Result<Option<u64>> {
        match self {
            Self::Mf(_) => Ok(None),
            Self::Amf(value) => Ok(Some(value.observation()?.runtime)),
        }
    }
    pub(crate) fn backend_observation(&self) -> io::Result<HevcBackendObservation> {
        match self {
            Self::Mf(value) => crate::windows_hevc::observation(value),
            Self::Amf(value) => {
                let actual = value.observation()?;
                Ok(HevcBackendObservation {
                    asynchronous: true,
                    d3d_manager: false,
                    actual_hardware_output: actual.owner.hardware_output,
                    gpu_input: actual.gpu_input,
                    drain_started: actual.drain_started,
                    drain_complete: actual.drain_complete,
                    adapter_luid: actual.owner.adapter_luid,
                })
            }
        }
    }
    pub(crate) unsafe fn process_gpu(
        &mut self,
        texture: *mut c_void,
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        // SAFETY: exact texture borrowed on original device/thread through synchronous copy.
        unsafe {
            match self {
                Self::Mf(value) => value.process_gpu(texture, pts, keyframe, output),
                Self::Amf(value) => value.process_gpu(texture, pts, keyframe, output),
            }
        }
    }
    pub(crate) fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, u64)>> {
        match self {
            Self::Mf(value) => value.receive(output),
            Self::Amf(value) => value.receive(output),
        }
    }
    pub(crate) fn begin_hevc_drain(&mut self) -> io::Result<()> {
        match self {
            Self::Mf(value) => value.begin_hevc_drain(),
            Self::Amf(value) => value.begin_hevc_drain(),
        }
    }
    pub(crate) fn pending_frames(&self) -> usize {
        match self {
            Self::Mf(value) => value.pending_frames(),
            Self::Amf(value) => value.pending_frames(),
        }
    }
    pub(crate) fn close(&mut self) -> io::Result<()> {
        match self {
            Self::Mf(value) => value.close(),
            Self::Amf(value) => value.close(),
        }
    }
}
