//! Restricted diagnostic HEVC Annex-B validator, not the product network parser.
//! Main8 4:2:0, single layer, IDR-only, no reorder; unsupported syntax fails closed.
use std::io;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "HEVC probe requires bounded Main8 4:2:0 SDR IDR syntax",
    )
}
struct Bits {
    bytes: Vec<u8>,
    pos: usize,
}
impl Bits {
    fn new(nal: &[u8]) -> io::Result<Self> {
        if nal.len() < 3 || nal.len() > 65536 {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(nal.len() - 2);
        let mut zeros = 0;
        for (i, b) in nal[2..].iter().copied().enumerate() {
            if zeros >= 2 {
                if b == 3 {
                    if nal.get(i + 3).is_none_or(|v| *v > 3) {
                        return Err(invalid());
                    }
                    zeros = 0;
                    continue;
                }
                if b <= 2 {
                    return Err(invalid());
                }
            }
            bytes.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        Ok(Self { bytes, pos: 0 })
    }
    fn read(&mut self, n: usize) -> io::Result<u32> {
        if n > 32 || self.pos + n > self.bytes.len() * 8 {
            return Err(invalid());
        }
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | u32::from((self.bytes[self.pos / 8] >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Ok(v)
    }
    fn ue(&mut self, max: u32) -> io::Result<u32> {
        let mut z = 0;
        while self.read(1)? == 0 {
            z += 1;
            if z > 24 {
                return Err(invalid());
            }
        }
        let v = ((1u32 << z) - 1) + self.read(z)?;
        if v > max {
            return Err(invalid());
        }
        Ok(v)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sps {
    pub profile: u32,
    pub level: u32,
    pub width: u32,
    pub height: u32,
    pub vps: u32,
    pub id: u32,
}
fn sps(nal: &[u8], width: u32, height: u32) -> io::Result<Sps> {
    let mut b = Bits::new(nal)?;
    let vps = b.read(4)?;
    let layers = b.read(3)?;
    b.read(1)?;
    if layers != 0 {
        return Err(invalid());
    } // No temporal sublayer reorder in this diagnostic contract.
    if b.read(2)? != 0 {
        return Err(invalid());
    }
    b.read(1)?;
    let profile = b.read(5)?;
    b.read(32)?;
    b.read(32)?;
    b.read(16)?;
    let level = b.read(8)?;
    if profile != 1 || !matches!(level, 30 | 60 | 63 | 90 | 93 | 120 | 123 | 150 | 153) {
        return Err(invalid());
    }
    let id = b.ue(15)?;
    if b.ue(3)? != 1 {
        return Err(invalid());
    }
    let coded_width = b.ue(8192)?;
    let coded_height = b.ue(8192)?;
    let (mut left, mut right, mut top, mut bottom) = (0u32, 0u32, 0u32, 0u32);
    if b.read(1)? != 0 {
        left = b.ue(4096)?;
        right = b.ue(4096)?;
        top = b.ue(4096)?;
        bottom = b.ue(4096)?;
    }
    let visible_width = coded_width
        .checked_sub((left + right) * 2)
        .ok_or_else(invalid)?;
    let visible_height = coded_height
        .checked_sub((top + bottom) * 2)
        .ok_or_else(invalid)?;
    if visible_width != width
        || visible_height != height
        || left != 0
        || top != 0
        || b.ue(8)? != 0
        || b.ue(8)? != 0
    {
        return Err(invalid());
    }
    let poc_bits = b.ue(12)? as usize + 4;
    b.read(1)?;
    b.ue(16)?;
    if b.ue(16)? != 0 {
        return Err(invalid());
    }
    b.ue(65535)?;
    for _ in 0..6 {
        b.ue(6)?;
    }
    if b.read(1)? != 0 && b.read(1)? != 0 {
        return Err(invalid());
    } // Custom scaling lists not implemented.
    b.read(1)?;
    b.read(1)?;
    if b.read(1)? != 0 {
        b.read(4)?;
        b.read(4)?;
        b.ue(6)?;
        b.ue(6)?;
        b.read(1)?;
    }
    let sets = b.ue(64)?;
    for i in 0..sets {
        if i > 0 && b.read(1)? != 0 {
            return Err(invalid());
        } // Predicted RPS is a future parser dependency.
        let neg = b.ue(16)?;
        let pos = b.ue(16)?;
        if neg + pos > 16 {
            return Err(invalid());
        }
        for _ in 0..neg + pos {
            b.ue(65535)?;
            b.read(1)?;
        }
    }
    if b.read(1)? != 0 {
        let n = b.ue(16)?;
        for _ in 0..n {
            b.read(poc_bits)?;
            b.read(1)?;
        }
    }
    b.read(1)?;
    b.read(1)?;
    if b.read(1)? != 0 {
        if b.read(1)? != 0 && b.read(8)? == 255 {
            b.read(16)?;
            b.read(16)?;
        }
        if b.read(1)? != 0 {
            b.read(1)?;
        }
        if b.read(1)? != 0 {
            b.read(3)?;
            if b.read(1)? != 0 {
                return Err(invalid());
            }
            if b.read(1)? != 0 && (b.read(8)? != 1 || b.read(8)? != 1 || b.read(8)? != 1) {
                return Err(invalid());
            }
        }
    }
    Ok(Sps {
        profile,
        level,
        width: visible_width,
        height: visible_height,
        vps,
        id,
    })
}
#[derive(Clone, Default)]
pub(crate) struct Validator {
    vps: Option<u32>,
    sps: Option<Sps>,
    pps: Option<u32>,
}
impl Validator {
    pub fn info(&self) -> Option<Sps> {
        self.sps
    }
    pub fn validate(&mut self, data: &[u8], width: u32, height: u32) -> io::Result<()> {
        let mut next = self.clone();
        let mut slices = 0;
        for nal in crate::h264::nals(data)? {
            if nal.len() < 3 || nal[0] & 0x81 != 0 || nal[1] != 1 {
                return Err(invalid());
            } // forbidden/layer/temporal ID.
            let kind = (nal[0] >> 1) & 63;
            match kind {
                32 => {
                    let mut b = Bits::new(nal)?;
                    next.vps = Some(b.read(4)?);
                }
                33 => {
                    let info = sps(nal, width, height)?;
                    if next.vps != Some(info.vps) {
                        return Err(invalid());
                    }
                    next.sps = Some(info);
                }
                34 => {
                    let mut b = Bits::new(nal)?;
                    let pps = b.ue(63)?;
                    let sps = b.ue(15)?;
                    if next.sps.is_none_or(|v| v.id != sps) {
                        return Err(invalid());
                    }
                    next.pps = Some(pps);
                }
                19 | 20 => {
                    let mut b = Bits::new(nal)?;
                    if b.read(1)? != 1 {
                        return Err(invalid());
                    }
                    b.read(1)?;
                    let pps = b.ue(63)?;
                    if next.pps != Some(pps) {
                        return Err(invalid());
                    }
                    slices += 1;
                }
                35 | 38 | 39 | 40 => {} // AUD/filler/SEI do not count as decoded pictures.
                _ => return Err(invalid()),
            }
        }
        if slices != 1 || next.sps.is_none() {
            return Err(invalid());
        }
        *self = next;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(full_range: bool, depth: u32, matrix: u32) -> Vec<u8> {
        fn bits(out: &mut Vec<u8>, n: usize, v: u32) {
            for shift in (0..n).rev() {
                out.push(((v >> shift) & 1) as u8);
            }
        }
        fn ue(out: &mut Vec<u8>, v: u32) {
            let n = (32 - (v + 1).leading_zeros()) as usize;
            out.extend(std::iter::repeat_n(0, n - 1));
            bits(out, n, v + 1);
        }
        let mut b = Vec::new();
        bits(&mut b, 4, 0);
        bits(&mut b, 3, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 2, 0);
        bits(&mut b, 1, 0);
        bits(&mut b, 5, 1);
        bits(&mut b, 32, 0);
        bits(&mut b, 32, 0);
        bits(&mut b, 16, 0);
        bits(&mut b, 8, 120);
        ue(&mut b, 0);
        ue(&mut b, 1);
        ue(&mut b, 640);
        ue(&mut b, 480);
        bits(&mut b, 1, 0);
        ue(&mut b, depth);
        ue(&mut b, depth);
        ue(&mut b, 4);
        bits(&mut b, 1, 0);
        ue(&mut b, 0);
        ue(&mut b, 0);
        ue(&mut b, 0);
        for _ in 0..6 {
            ue(&mut b, 0);
        }
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 0);
        ue(&mut b, 0);
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 3, 5);
        bits(&mut b, 1, u32::from(full_range));
        bits(&mut b, 1, 1);
        bits(&mut b, 8, 1);
        bits(&mut b, 8, 1);
        bits(&mut b, 8, matrix);
        bits(&mut b, 1, 1);
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let raw = b
            .chunks_exact(8)
            .map(|c| c.iter().fold(0, |v, b| (v << 1) | b))
            .collect::<Vec<u8>>();
        let mut nal = vec![0x42, 1];
        let mut zeros = 0;
        for byte in raw {
            if zeros >= 2 && byte <= 3 {
                nal.push(3);
                zeros = 0;
            }
            nal.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        nal
    }
    #[test]
    fn restricted_main8_sps_and_explicit_color_conflicts() -> io::Result<()> {
        let info = sps(&fixture(false, 0, 1), 640, 480)?;
        assert_eq!(
            (info.profile, info.level, info.width, info.height),
            (1, 120, 640, 480)
        );
        assert!(sps(&fixture(true, 0, 1), 640, 480).is_err());
        assert!(sps(&fixture(false, 2, 1), 640, 480).is_err());
        assert!(sps(&fixture(false, 0, 9), 640, 480).is_err());
        assert!(sps(&fixture(false, 0, 1), 1280, 720).is_err());
        Ok(())
    }
    #[test]
    fn h264_and_truncated_hevc_are_rejected() {
        let mut v = Validator::default();
        assert!(v.validate(&[0, 0, 1, 0x65, 0x80], 640, 480).is_err());
        assert!(v.validate(&[0, 0, 1, 0x42, 1, 0], 640, 480).is_err());
    }
}
