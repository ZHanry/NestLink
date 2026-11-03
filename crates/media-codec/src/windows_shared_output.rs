//! A finite original-decoder surface export. Public descriptor values are only
//! syntax; the private frame lease, actual process target and native mutex own it.
#![allow(unsafe_code)]
use crate::{VideoConfig, windows_mf::Transform};
use nestlink_platform_security::local_stream::VerifiedProcessExportTarget;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedRingDescriptor {
    pub ring_id: [u8; 16],
    pub adapter_luid: u64,
    pub handles: [u64; 3],
    pub resource_ids: [[u8; 16]; 3],
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub bit_depth: u32,
    pub reserved: u32,
}
impl SharedRingDescriptor {
    /// A distinct version, never inferred from ten-bit storage alone.
    pub fn is_hdr10(&self) -> bool {
        self.reserved == 5 && self.bit_depth == 10
    }
    pub fn validate(&self, config: VideoConfig) -> io::Result<()> {
        if self.ring_id == [0; 16]
            || self.handles.iter().any(|value| {
                *value == 0 || *value > isize::MAX as u64 || usize::try_from(*value).is_err()
            })
            || self.resource_ids.contains(&[0; 16])
            || self.handles[0] == self.handles[1]
            || self.handles[0] == self.handles[2]
            || self.handles[1] == self.handles[2]
            || self.resource_ids[0] == self.resource_ids[1]
            || self.resource_ids[0] == self.resource_ids[2]
            || self.resource_ids[1] == self.resource_ids[2]
            || (self.width, self.height) != (config.width, config.height)
            || self.width == 0
            || self.height == 0
            || !self.width.is_multiple_of(2)
            || !self.height.is_multiple_of(2)
            || self.width > 8192
            || self.height > 8192
            || !matches!(self.bit_depth, 8 | 10)
            || (self.reserved != 0 && !self.is_hdr10())
            || self.bytes
                != u64::from(self.width) * u64::from(self.height) * 3 / 2
                    * 3
                    * if self.bit_depth == 10 { 2 } else { 1 }
            || self.bytes > 128 * 1024 * 1024
        {
            return Err(io::Error::other("original shared ring descriptor invalid"));
        }
        Ok(())
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedFrameDescriptor {
    pub token: u64,
    pub pts_90khz: u64,
    pub acquire_key: u64,
    pub release_key: u64,
    pub expires_qpc: u64,
    pub slot: u32,
    pub reserved: u32,
}
impl SharedFrameDescriptor {
    pub fn validate(&self) -> io::Result<()> {
        if self.token == 0
            || self.token > i64::MAX as u64
            || self.pts_90khz > i64::MAX as u64
            || self.slot >= 3
            || self.reserved != 0
            || self.acquire_key == 0
            || self.acquire_key >= i64::MAX as u64
            || self.acquire_key.is_multiple_of(2)
            || self.release_key != self.acquire_key + 1
            || self.expires_qpc == 0
            || self.expires_qpc > i64::MAX as u64
        {
            return Err(io::Error::other("original shared frame descriptor invalid"));
        }
        Ok(())
    }
}
unsafe extern "C" {
    fn nl_mf_enable_shared_output(
        owner: *mut c_void,
        process: *mut c_void,
        ring: *mut SharedRingDescriptor,
    ) -> i32;
    fn nl_mf_shared_frame(owner: *mut c_void, pts: u64, frame: *mut SharedFrameDescriptor) -> i32;
    fn nl_mf_discard_shared_frame(owner: *mut c_void, slot: u32, token: u64) -> i32;
    fn nl_mf_shared_frame_status(owner: *mut c_void, slot: u32, token: u64) -> i32;
}
fn checked(code: i32) -> io::Result<i32> {
    if (0..=1).contains(&code) {
        Ok(code)
    } else {
        Err(io::Error::other(format!(
            "original shared surface failed {code:#010x}"
        )))
    }
}
struct Pending {
    frame: SharedFrameDescriptor,
    status: Arc<AtomicU8>,
}
pub(crate) struct SharedOutput {
    descriptor: SharedRingDescriptor,
    peer: VerifiedProcessExportTarget,
    authority: Arc<AtomicBool>,
    pending: Vec<Pending>,
}
impl SharedOutput {
    pub(crate) fn enable(
        owner: &Transform,
        config: VideoConfig,
        peer: VerifiedProcessExportTarget,
        authority: Arc<AtomicBool>,
        bit_depth: u8,
        hdr10: bool,
    ) -> io::Result<Self> {
        let mut descriptor = SharedRingDescriptor::default();
        peer.with_process_handle(|process| {
            // SAFETY: the capability borrows the exact original OS process;
            // native code retains a duplicate and touches D3D only on this worker.
            checked(unsafe {
                nl_mf_enable_shared_output(
                    owner.handle.as_ptr(),
                    process.as_raw_handle().cast(),
                    &mut descriptor,
                )
            })
            .map(|_| ())
        })?;
        descriptor.validate(config)?;
        if descriptor.bit_depth != u32::from(bit_depth) || descriptor.is_hdr10() != hdr10 {
            return Err(io::Error::other(
                "original native ring depth differs from exact decoder target",
            ));
        }
        Ok(Self {
            descriptor,
            peer,
            authority,
            pending: Vec::new(),
        })
    }
    pub(crate) fn check(&self) -> io::Result<()> {
        if !self.authority.load(Ordering::Acquire) {
            return Err(io::Error::other("shared decoder authority retired"));
        }
        self.peer.check_current()
    }
    pub(crate) fn descriptor(&self) -> SharedRingDescriptor {
        self.descriptor
    }
    pub(crate) fn reap(&mut self, owner: &Transform) -> io::Result<()> {
        self.check()?;
        let mut retained = Vec::with_capacity(3);
        for pending in self.pending.drain(..) {
            let code = match pending.status.load(Ordering::Acquire) {
                // This private lease was dropped before descriptor writing.
                2 => {
                    checked(unsafe {
                        nl_mf_discard_shared_frame(
                            owner.handle.as_ptr(),
                            pending.frame.slot,
                            pending.frame.token,
                        )
                    })?;
                    1
                }
                // Even after transfer, only the real native return key frees it.
                1 => checked(unsafe {
                    nl_mf_shared_frame_status(
                        owner.handle.as_ptr(),
                        pending.frame.slot,
                        pending.frame.token,
                    )
                })?,
                0 => 0,
                _ => return Err(io::Error::other("invalid original shared lease state")),
            };
            if code == 0 {
                retained.push(pending);
            }
        }
        self.pending = retained;
        Ok(())
    }
    pub(crate) fn output(
        &mut self,
        owner: &Transform,
        pts: u64,
    ) -> io::Result<Option<SharedDecodedFrame>> {
        self.reap(owner)?;
        let mut frame = SharedFrameDescriptor::default();
        // SAFETY: original owner-thread transform and fixed initialized ABI.
        let code = checked(unsafe { nl_mf_shared_frame(owner.handle.as_ptr(), pts, &mut frame) })?;
        if code == 1 {
            return Ok(None);
        }
        frame.validate()?;
        if frame.pts_90khz != pts || self.pending.len() >= 3 {
            return Err(io::Error::other(
                "shared output ledger differs from native output",
            ));
        }
        let status = Arc::new(AtomicU8::new(0));
        self.pending.push(Pending {
            frame,
            status: status.clone(),
        });
        Ok(Some(SharedDecodedFrame {
            ring: self.descriptor,
            frame,
            status,
            peer: self.peer.clone(),
            authority: self.authority.clone(),
        }))
    }
}
/// One actual copied NV12 output. No public constructor, Clone or serde path.
pub struct SharedDecodedFrame {
    ring: SharedRingDescriptor,
    frame: SharedFrameDescriptor,
    status: Arc<AtomicU8>,
    peer: VerifiedProcessExportTarget,
    authority: Arc<AtomicBool>,
}
impl SharedDecodedFrame {
    pub fn ring(&self) -> SharedRingDescriptor {
        self.ring
    }
    pub fn descriptor(&self) -> SharedFrameDescriptor {
        self.frame
    }
    pub fn check_current(&self) -> io::Result<()> {
        if !self.authority.load(Ordering::Acquire)
            || self.status.load(Ordering::Acquire) == 2
            || crate::gpu_qpc()?.0 >= self.frame.expires_qpc
        {
            return Err(io::Error::other("original shared frame retired or expired"));
        }
        self.peer.check_current()
    }
    /// Call before the first asynchronous descriptor write. Any uncertain
    /// transfer thereafter waits for native consumption or retires the ring.
    pub fn begin_transfer(&self) -> io::Result<()> {
        self.check_current()?;
        self.status
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::other("original shared frame already transferred or discarded")
            })?;
        Ok(())
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.ring.ring_id);
        if self.ring.is_hdr10() {
            hash.update(b"nestlink/shared-p010-hdr10/v5\0");
        }
        hash.update(self.ring.adapter_luid.to_be_bytes());
        hash.update(self.ring.bit_depth.to_be_bytes());
        hash.update(self.ring.width.to_be_bytes());
        hash.update(self.ring.height.to_be_bytes());
        hash.update(self.ring.bytes.to_be_bytes());
        hash.update(self.ring.resource_ids[self.frame.slot as usize]);
        hash.update(self.frame.token.to_be_bytes());
        hash.update(self.frame.pts_90khz.to_be_bytes());
        hash.update(self.frame.acquire_key.to_be_bytes());
        hash.update(self.frame.release_key.to_be_bytes());
        hash.update(self.frame.expires_qpc.to_be_bytes());
        hash.finalize().into()
    }
}
impl Drop for SharedDecodedFrame {
    fn drop(&mut self) {
        let _ = self
            .status
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}

struct TransferredRingOwner {
    descriptor: SharedRingDescriptor,
    _handles: [OwnedHandle; 3],
    peer: VerifiedProcessExportTarget,
}
// Tombstones remain for this desktop process lifetime. An old ring identifier
// can never cause a closed numeric handle to be adopted again after ABA reuse.
struct TransferClaims<T> {
    entries: BTreeMap<[u8; 16], Weak<T>>,
}
impl<T> TransferClaims<T> {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
    fn find(&self, id: [u8; 16]) -> io::Result<Option<Arc<T>>> {
        match self.entries.get(&id) {
            None => Ok(None),
            Some(owner) => owner.upgrade().map(Some).ok_or_else(|| {
                io::Error::other(
                    "destination ring already retired; numeric handles cannot be readopted",
                )
            }),
        }
    }
    fn insert(&mut self, id: [u8; 16], owner: &Arc<T>) -> io::Result<()> {
        if self.entries.contains_key(&id) || self.entries.len() >= 4096 {
            return Err(io::Error::other(
                "destination ring identity already claimed or process ledger exhausted",
            ));
        }
        self.entries.insert(id, Arc::downgrade(owner));
        Ok(())
    }
}
fn transfer_claims() -> &'static Mutex<TransferClaims<TransferredRingOwner>> {
    static CLAIMS: OnceLock<Mutex<TransferClaims<TransferredRingOwner>>> = OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(TransferClaims::new()))
}
/// Destination-owned NT handles received once over the authenticated native
/// connection. Clones retain the same handles; no serialized execution proof.
#[derive(Clone)]
pub struct TransferredSurfaceRing(Arc<TransferredRingOwner>);
impl TransferredSurfaceRing {
    /// Claim once, after checking the exact native TLS descriptor and peer.
    /// This owns only the destination handles, never the daemon decoder.
    pub fn from_authenticated_peer(
        descriptor: SharedRingDescriptor,
        peer: VerifiedProcessExportTarget,
    ) -> io::Result<Self> {
        peer.check_current()?;
        descriptor.validate(VideoConfig {
            width: descriptor.width,
            height: descriptor.height,
            fps: 1,
            bitrate_kbps: 64,
        })?;
        let mut claims = transfer_claims()
            .lock()
            .map_err(|_| io::Error::other("destination ring ownership poisoned"))?;
        if let Some(existing) = claims.find(descriptor.ring_id)? {
            if existing.descriptor != descriptor {
                return Err(io::Error::other(
                    "destination ring identity changed native handles",
                ));
            }
            existing.peer.check_current()?;
            return Ok(Self(existing));
        }
        if claims
            .entries
            .values()
            .filter_map(Weak::upgrade)
            .any(|owner| {
                owner
                    .descriptor
                    .handles
                    .iter()
                    .any(|handle| descriptor.handles.contains(handle))
            })
        {
            return Err(io::Error::other(
                "destination numeric handle already belongs to another live ring",
            ));
        }
        if claims.entries.len() >= 4096 {
            return Err(io::Error::other(
                "destination ring process ledger exhausted",
            ));
        }
        // SAFETY: the native TLS producer duplicated these distinct NT handles
        // into this process. The authenticated consumer calls this once; Arc
        // clones, never a second numeric adoption, retain their ownership.
        let handles = descriptor
            .handles
            .map(|handle| unsafe { OwnedHandle::from_raw_handle(handle as usize as *mut c_void) });
        let owner = Self(Arc::new(TransferredRingOwner {
            descriptor,
            _handles: handles,
            peer,
        }));
        claims.insert(descriptor.ring_id, &owner.0)?;
        drop(claims);
        owner.check_current()?;
        Ok(owner)
    }
    pub fn descriptor(&self) -> SharedRingDescriptor {
        self.0.descriptor
    }
    pub fn check_current(&self) -> io::Result<()> {
        self.0.peer.check_current()
    }
}

#[cfg(test)]
mod transfer_claim_tests {
    use super::*;
    #[test]
    fn hdr_ring_marker_requires_p010_and_never_infers_hdr_from_depth_alone() -> io::Result<()> {
        let config = VideoConfig {
            width: 640,
            height: 480,
            fps: 30,
            bitrate_kbps: 4000,
        };
        let mut descriptor = SharedRingDescriptor {
            ring_id: [1; 16],
            adapter_luid: 7,
            handles: [100, 101, 102],
            resource_ids: [[2; 16], [3; 16], [4; 16]],
            width: 640,
            height: 480,
            bytes: 640 * 480 * 3 / 2 * 3 * 2,
            bit_depth: 10,
            reserved: 0,
        };
        descriptor.validate(config)?;
        assert!(!descriptor.is_hdr10());
        descriptor.reserved = 5;
        descriptor.validate(config)?;
        assert!(descriptor.is_hdr10());
        for marker in [1, 2, 3, 4, 6, u32::MAX] {
            descriptor.reserved = marker;
            assert!(descriptor.validate(config).is_err());
        }
        descriptor.reserved = 5;
        descriptor.bit_depth = 8;
        descriptor.bytes /= 2;
        assert!(descriptor.validate(config).is_err());
        Ok(())
    }
    #[test]
    fn destination_claim_retains_one_owner_and_tombstones_closed_numeric_handles() -> io::Result<()>
    {
        // Ownership-ledger test only. No GPU handle, surface or native decoder
        // receipt is constructed by this non-hardware lifecycle fixture.
        let mut claims = TransferClaims::new();
        let original = Arc::new(1u8);
        claims.insert([1; 16], &original)?;
        let same = claims
            .find([1; 16])?
            .ok_or_else(|| io::Error::other("missing live claim"))?;
        assert!(Arc::ptr_eq(&original, &same));
        assert!(claims.insert([1; 16], &Arc::new(2)).is_err());
        drop(same);
        drop(original);
        assert!(claims.find([1; 16]).is_err());
        assert!(claims.insert([1; 16], &Arc::new(3)).is_err());
        assert!(claims.find([2; 16])?.is_none());
        Ok(())
    }
}
