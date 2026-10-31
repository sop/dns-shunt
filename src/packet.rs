use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Range,
};
use thiserror::Error;

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowTuple {
    #[allow(dead_code)]
    pub fn new(
        source: impl Into<IpAddr>,
        source_port: u16,
        destination: impl Into<IpAddr>,
        destination_port: u16,
    ) -> Self {
        Self {
            source: source.into(),
            source_port,
            destination: destination.into(),
            destination_port,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.source.is_ipv4() && self.destination.is_ipv4()
    }

    #[allow(dead_code)]
    pub fn is_ipv6(&self) -> bool {
        self.source.is_ipv6() && self.destination.is_ipv6()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub tuple: FlowTuple,
    pub payload_range: Range<usize>,
    pub ip_ttl: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("not a valid unfragmented IPv4 or IPv6 UDP packet")]
    Unsupported,
    #[error("packet is truncated or has inconsistent lengths")]
    Malformed,
}

#[allow(dead_code)]
pub fn parse_ipv4_udp(packet: &[u8]) -> Result<(FlowTuple, &[u8]), PacketError> {
    let (tuple, payload_range) = parse_ipv4_udp_range(packet)?;
    Ok((tuple, &packet[payload_range]))
}

pub fn parse_ipv4_udp_range(packet: &[u8]) -> Result<(FlowTuple, Range<usize>), PacketError> {
    let parsed = parse_packet_range(packet)?;
    if parsed.tuple.is_ipv4() {
        Ok((parsed.tuple, parsed.payload_range))
    } else {
        Err(PacketError::Unsupported)
    }
}

pub fn parse_packet_range(packet: &[u8]) -> Result<ParsedPacket, PacketError> {
    if packet.is_empty() {
        return Err(PacketError::Malformed);
    }
    match packet[0] >> 4 {
        4 => parse_ipv4_packet_range(packet),
        6 => parse_ipv6_packet_range(packet),
        _ => Err(PacketError::Malformed),
    }
}

fn parse_ipv4_packet_range(packet: &[u8]) -> Result<ParsedPacket, PacketError> {
    if packet.len() < IPV4_HEADER_LEN {
        return Err(PacketError::Malformed);
    }
    let header_len = (packet[0] as usize & 0x0f) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if header_len < IPV4_HEADER_LEN || total_len != packet.len() || header_len > total_len {
        return Err(PacketError::Malformed);
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_offset & 0x3fff != 0 {
        return Err(PacketError::Unsupported);
    }
    if packet[9] != 17 {
        return Err(PacketError::Unsupported);
    }
    if header_len + UDP_HEADER_LEN > total_len {
        return Err(PacketError::Malformed);
    }
    let udp_len = u16::from_be_bytes([packet[header_len + 4], packet[header_len + 5]]) as usize;
    if udp_len < UDP_HEADER_LEN || header_len + udp_len != total_len {
        return Err(PacketError::Malformed);
    }
    let tuple = FlowTuple {
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        source_port: u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        destination_port: u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
    };
    Ok(ParsedPacket {
        tuple,
        payload_range: header_len + UDP_HEADER_LEN..total_len,
        ip_ttl: packet[8],
    })
}

fn parse_ipv6_packet_range(packet: &[u8]) -> Result<ParsedPacket, PacketError> {
    if packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        return Err(PacketError::Malformed);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = IPV6_HEADER_LEN + payload_len;
    if packet.len() != total_len {
        return Err(PacketError::Malformed);
    }
    let next_header = packet[6];
    if next_header != 17 {
        return Err(PacketError::Unsupported);
    }
    let udp_len =
        u16::from_be_bytes([packet[IPV6_HEADER_LEN + 4], packet[IPV6_HEADER_LEN + 5]]) as usize;
    if udp_len < UDP_HEADER_LEN || udp_len != payload_len {
        return Err(PacketError::Malformed);
    }
    let src_bytes: [u8; 16] = packet[8..24].try_into().unwrap();
    let dst_bytes: [u8; 16] = packet[24..40].try_into().unwrap();
    let tuple = FlowTuple {
        source: IpAddr::V6(Ipv6Addr::from(src_bytes)),
        source_port: u16::from_be_bytes([packet[IPV6_HEADER_LEN], packet[IPV6_HEADER_LEN + 1]]),
        destination: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        destination_port: u16::from_be_bytes([
            packet[IPV6_HEADER_LEN + 2],
            packet[IPV6_HEADER_LEN + 3],
        ]),
    };
    Ok(ParsedPacket {
        tuple,
        payload_range: IPV6_HEADER_LEN + UDP_HEADER_LEN..total_len,
        ip_ttl: packet[7],
    })
}

pub fn build_ipv4_udp(tuple: FlowTuple, payload: &[u8]) -> Result<Vec<u8>, PacketError> {
    build_ipv4_udp_with_ttl(tuple, payload, 64)
}

pub fn build_ipv4_udp_with_ttl(
    tuple: FlowTuple,
    payload: &[u8],
    ttl: u8,
) -> Result<Vec<u8>, PacketError> {
    let (src, dst) = match (tuple.source, tuple.destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => return Err(PacketError::Unsupported),
    };
    let total_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    if total_len > u16::MAX as usize || UDP_HEADER_LEN + payload.len() > u16::MAX as usize {
        return Err(PacketError::Malformed);
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_offset = IPV4_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&tuple.source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&tuple.destination_port.to_be_bytes());
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + udp_len as usize);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&packet[udp_offset..]);
    let mut udp_checksum = checksum(&pseudo);
    if udp_checksum == 0 {
        udp_checksum = u16::MAX;
    }
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

pub fn build_ipv6_udp(
    tuple: FlowTuple,
    payload: &[u8],
    hop_limit: u8,
) -> Result<Vec<u8>, PacketError> {
    let (src, dst) = match (tuple.source, tuple.destination) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => return Err(PacketError::Unsupported),
    };
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV6_HEADER_LEN + udp_len;
    if total_len > u16::MAX as usize || udp_len > u16::MAX as usize {
        return Err(PacketError::Malformed);
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());

    let udp_offset = IPV6_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&tuple.source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&tuple.destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(40 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&packet[udp_offset..]);
    let mut udp_checksum = checksum(&pseudo);
    if udp_checksum == 0 {
        udp_checksum = u16::MAX;
    }
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

pub fn build_udp(tuple: FlowTuple, payload: &[u8], ttl: u8) -> Result<Vec<u8>, PacketError> {
    match (tuple.source, tuple.destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => build_ipv4_udp_with_ttl(tuple, payload, ttl),
        (IpAddr::V6(_), IpAddr::V6(_)) => build_ipv6_udp(tuple, payload, ttl),
        _ => Err(PacketError::Unsupported),
    }
}

pub fn response_tuple(query: FlowTuple) -> FlowTuple {
    FlowTuple {
        source: query.destination,
        source_port: query.destination_port,
        destination: query.source,
        destination_port: query.source_port,
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum_is_valid(bytes: &[u8]) -> bool {
        checksum(bytes) == 0
    }

    fn udp_checksum_is_valid(packet: &[u8]) -> bool {
        let udp = &packet[20..];
        let mut pseudo = Vec::with_capacity(12 + udp.len());
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.extend_from_slice(&[0, packet[9]]);
        pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(udp);
        checksum_is_valid(&pseudo)
    }

    fn ipv6_udp_checksum_is_valid(packet: &[u8]) -> bool {
        let udp = &packet[40..];
        let mut pseudo = Vec::with_capacity(40 + udp.len());
        pseudo.extend_from_slice(&packet[8..24]);
        pseudo.extend_from_slice(&packet[24..40]);
        let udp_len = u16::from_be_bytes([packet[44], packet[45]]) as u32;
        pseudo.extend_from_slice(&udp_len.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(udp);
        checksum_is_valid(&pseudo)
    }

    #[test]
    fn parses_and_builds_reversed_udp_tuple_with_valid_lengths_checksums() {
        let tuple = FlowTuple {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 49152,
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
            destination_port: 53,
        };
        let response = response_tuple(tuple);
        let packet = build_ipv4_udp(response, b"dns answer").unwrap();
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]) as usize,
            packet.len()
        );
        assert!(checksum_is_valid(&packet[..20]));
        assert!(udp_checksum_is_valid(&packet));
        let (parsed, payload) = parse_ipv4_udp(&packet).unwrap();
        assert_eq!(parsed, response);
        assert_eq!(payload, b"dns answer");
        let (parsed, payload_range) = parse_ipv4_udp_range(&packet).unwrap();
        assert_eq!(parsed, response);
        assert_eq!(&packet[payload_range], b"dns answer");
    }

    #[test]
    fn parses_and_builds_ipv6_udp_packet() {
        let tuple = FlowTuple::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            5353,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
            5353,
        );
        assert!(tuple.is_ipv6());
        assert!(!tuple.is_ipv4());
        let packet = build_udp(tuple, b"mdns query", 255).unwrap();
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(packet[7], 255);
        assert!(ipv6_udp_checksum_is_valid(&packet));

        let parsed = parse_packet_range(&packet).unwrap();
        assert_eq!(parsed.tuple, tuple);
        assert_eq!(parsed.ip_ttl, 255);
        assert_eq!(&packet[parsed.payload_range], b"mdns query");
    }

    #[test]
    fn rejects_fragments_and_malformed_lengths() {
        let tuple = FlowTuple {
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: 1234,
            destination: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            destination_port: 53,
        };
        let mut packet = build_ipv4_udp(tuple, b"x").unwrap();
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert_eq!(parse_ipv4_udp(&packet), Err(PacketError::Unsupported));
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        let malformed_len = (packet.len() - 1) as u16;
        packet[2..4].copy_from_slice(&malformed_len.to_be_bytes());
        assert_eq!(parse_ipv4_udp(&packet), Err(PacketError::Malformed));
    }

    #[test]
    fn rejects_unsupported_ipv6_next_header() {
        let tuple = FlowTuple {
            source: IpAddr::V6(Ipv6Addr::LOCALHOST),
            source_port: 5353,
            destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination_port: 5353,
        };
        let mut packet = build_ipv6_udp(tuple, b"payload", 255).unwrap();
        packet[6] = 0; // Hop-by-Hop options
        assert_eq!(parse_packet_range(&packet), Err(PacketError::Unsupported));
    }
}
