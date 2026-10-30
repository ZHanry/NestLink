//! Shared bounded assembly for legacy and independently versioned routed UDP.
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Packet {
    pub(crate) born: Instant,
    pub(crate) bytes: Vec<u8>,
}
struct Pending {
    born: Instant,
    length: usize,
    parts: Vec<Option<Vec<u8>>>,
}
pub(crate) struct Fragment<'a> {
    pub(crate) packet: u64,
    pub(crate) length: usize,
    pub(crate) index: usize,
    pub(crate) payload: &'a [u8],
}
pub(crate) struct Reassembly {
    high: u64,
    pending: BTreeMap<u64, Pending>,
    finished: BTreeSet<u64>,
    fragment_bytes: usize,
    capacity: usize,
    window: u64,
    age: Duration,
}
impl Reassembly {
    pub(crate) fn new(fragment_bytes: usize, capacity: usize, window: u64, age: Duration) -> Self {
        Self {
            high: 0,
            pending: BTreeMap::new(),
            finished: BTreeSet::new(),
            fragment_bytes,
            capacity,
            window,
            age,
        }
    }
    /// Only a validated wire fragment enters this shared assembler. Its codec
    /// has already enforced the packet size, index and exact fragment length.
    pub(crate) fn insert(&mut self, f: Fragment<'_>, now: Instant) -> io::Result<Option<Packet>> {
        self.high = self.high.max(f.packet);
        let floor = self.high.saturating_sub(self.window);
        self.finished.retain(|id| *id >= floor);
        self.pending.retain(|id, p| {
            if *id < floor || now.saturating_duration_since(p.born) >= self.age {
                if *id >= floor {
                    self.finished.insert(*id);
                }
                false
            } else {
                true
            }
        });
        if f.packet < floor || self.finished.contains(&f.packet) {
            return Ok(None);
        }
        if !self.pending.contains_key(&f.packet) {
            if self.pending.len() >= self.capacity {
                self.finished.insert(f.packet);
                return Ok(None);
            }
            self.pending.insert(
                f.packet,
                Pending {
                    born: now,
                    length: f.length,
                    parts: vec![None; f.length.div_ceil(self.fragment_bytes)],
                },
            );
        }
        let p = self.pending.get_mut(&f.packet).ok_or_else(invalid)?;
        if p.length != f.length {
            return Err(invalid());
        }
        let part = p.parts.get_mut(f.index).ok_or_else(invalid)?;
        if let Some(part) = part {
            if part != f.payload {
                return Err(invalid());
            }
            return Ok(None);
        }
        *part = Some(f.payload.to_vec());
        if p.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let p = self.pending.remove(&f.packet).ok_or_else(invalid)?;
        self.finished.insert(f.packet);
        Ok(Some(Packet {
            born: p.born,
            bytes: p.parts.into_iter().flatten().flatten().collect(),
        }))
    }
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }
    #[cfg(test)]
    pub(crate) fn finished_len(&self) -> usize {
        self.finished.len()
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "opaque packet fragment binding changed",
    )
}
