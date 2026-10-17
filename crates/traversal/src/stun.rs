//! RFC 5389 Binding and XOR-MAPPED-ADDRESS with source/transaction checks by caller.
use rand_core::{OsRng, RngCore};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub const MAXIMUM: usize = 512;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid STUN binding message")
}
pub fn transaction() -> [u8; 12] {
    let mut value = [0; 12];
    OsRng.fill_bytes(&mut value);
    value
}
pub fn request(transaction: &[u8; 12]) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[1] = 1;
    bytes[4..8].copy_from_slice(&COOKIE);
    bytes[8..20].copy_from_slice(transaction);
    bytes
}
pub fn is_stun(bytes: &[u8]) -> bool {
    bytes.len() >= 20 && bytes[0] & 0xc0 == 0 && bytes[4..8] == COOKIE
}
fn header(bytes: &[u8], kind: u16) -> io::Result<()> {
    if !is_stun(bytes)
        || bytes.len() > MAXIMUM
        || u16::from_be_bytes([bytes[0], bytes[1]]) != kind
        || usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) + 20 != bytes.len()
        || !bytes.len().is_multiple_of(4)
    {
        return Err(invalid());
    }
    Ok(())
}
fn crc(bytes: &[u8]) -> u32 {
    let mut value = 0xffff_ffff_u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320_u32 & 0_u32.wrapping_sub(value & 1));
        }
    }
    !value ^ 0x5354_554e
}
fn attributes(bytes: &[u8]) -> io::Result<Vec<(u16, usize, &[u8])>> {
    let mut offset = 20;
    let mut attributes = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(invalid());
        }
        let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
        let end = offset + 4 + length;
        if end > bytes.len() {
            return Err(invalid());
        }
        let value = &bytes[offset + 4..end];
        if kind == 0x8028
            && (length != 4 || end != bytes.len() || value != crc(&bytes[..offset]).to_be_bytes())
        {
            return Err(invalid());
        }
        attributes.push((kind, offset, value));
        offset = end.next_multiple_of(4);
    }
    if offset != bytes.len() {
        return Err(invalid());
    }
    Ok(attributes)
}
pub fn response(request: &[u8], observed: SocketAddr) -> io::Result<Vec<u8>> {
    header(request, 1)?;
    for (kind, _, _) in attributes(request)? {
        if kind < 0x8000 {
            return Err(invalid());
        }
    }
    if observed.port() == 0 || observed.ip().is_unspecified() || observed.ip().is_multicast() {
        return Err(invalid());
    }
    let mapped = match observed.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    let mut value = vec![0, if mapped.is_ipv4() { 1 } else { 2 }];
    value.extend_from_slice(&(observed.port() ^ 0x2112).to_be_bytes());
    match mapped {
        IpAddr::V4(ip) => value.extend(ip.octets().into_iter().zip(COOKIE).map(|(a, b)| a ^ b)),
        IpAddr::V6(ip) => {
            let mut mask = [0; 16];
            mask[..4].copy_from_slice(&COOKIE);
            mask[4..].copy_from_slice(&request[8..20]);
            value.extend(ip.octets().into_iter().zip(mask).map(|(a, b)| a ^ b));
        }
    }
    let length = value.len() + 12;
    let mut bytes = vec![1, 1];
    bytes.extend_from_slice(&(length as u16).to_be_bytes());
    bytes.extend_from_slice(&COOKIE);
    bytes.extend_from_slice(&request[8..20]);
    bytes.extend_from_slice(&[0, 0x20]);
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&value);
    let fingerprint = crc(&bytes);
    bytes.extend_from_slice(&[0x80, 0x28, 0, 4]);
    bytes.extend_from_slice(&fingerprint.to_be_bytes());
    Ok(bytes)
}
pub fn mapped_address(bytes: &[u8], transaction: &[u8; 12]) -> io::Result<SocketAddr> {
    header(bytes, 0x0101)?;
    if bytes[8..20] != *transaction {
        return Err(invalid());
    }
    let mut result = None;
    for (kind, _, value) in attributes(bytes)? {
        if kind == 0x0020 {
            if result.is_some() || value.len() < 4 || value[0] != 0 {
                return Err(invalid());
            }
            let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
            let ip = match (value[1], value.len()) {
                (1, 8) => {
                    let mut ip = [0; 4];
                    for index in 0..4 {
                        ip[index] = value[index + 4] ^ COOKIE[index];
                    }
                    IpAddr::V4(Ipv4Addr::from(ip))
                }
                (2, 20) => {
                    let mut mask = [0; 16];
                    mask[..4].copy_from_slice(&COOKIE);
                    mask[4..].copy_from_slice(transaction);
                    let mut ip = [0; 16];
                    for index in 0..16 {
                        ip[index] = value[index + 4] ^ mask[index];
                    }
                    IpAddr::V6(Ipv6Addr::from(ip))
                }
                _ => return Err(invalid()),
            };
            if port == 0 || ip.is_unspecified() || ip.is_multicast() {
                return Err(invalid());
            }
            result = Some(SocketAddr::new(ip, port));
        } else if kind < 0x8000 {
            return Err(invalid());
        }
    }
    result.ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_families_transaction_and_fingerprint_are_checked() -> io::Result<()> {
        let transaction = transaction();
        for address in ["203.0.113.17:54321", "[2001:db8:1234::a]:54321"] {
            let address: SocketAddr = address.parse().map_err(io::Error::other)?;
            let bytes = response(&request(&transaction), address)?;
            assert_eq!(mapped_address(&bytes, &transaction)?, address);
            assert!(mapped_address(&bytes, &[0; 12]).is_err());
            let mut modified = bytes;
            modified[26] ^= 1;
            assert!(mapped_address(&modified, &transaction).is_err());
        }
        let mut bytes = request(&transaction).to_vec();
        bytes[3] = 4;
        assert!(response(&bytes, "127.0.0.1:1".parse().map_err(io::Error::other)?).is_err());
        Ok(())
    }
}
