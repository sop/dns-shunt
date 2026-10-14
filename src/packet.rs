use std::{net::Ipv4Addr, ops::Range};
use thiserror::Error;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub source: Ipv4Addr,
    pub source_port: u16,
    pub destination: Ipv4Addr,
    pub destination_port: u16,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("not a valid unfragmented IPv4 UDP packet")]
    Unsupported,
    #[error("IPv4/UDP packet is truncated or has inconsistent lengths")]
    Malformed,
}

#[allow(dead_code)]
pub fn parse_ipv4_udp(packet: &[u8]) -> Result<(FlowTuple, &[u8]), PacketError> {
    let (tuple, payload_range) = parse_ipv4_udp_range(packet)?;
    Ok((tuple, &packet[payload_range]))
}

pub fn parse_ipv4_udp_range(packet: &[u8]) -> Result<(FlowTuple, Range<usize>), PacketError> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
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
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        source_port: u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        destination_port: u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
    };
    Ok((tuple, header_len + UDP_HEADER_LEN..total_len))
}

pub fn build_ipv4_udp(tuple: FlowTuple, payload: &[u8]) -> Result<Vec<u8>, PacketError> {
    let total_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    if total_len > u16::MAX as usize || UDP_HEADER_LEN + payload.len() > u16::MAX as usize {
        return Err(PacketError::Malformed);
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&tuple.source.octets());
    packet[16..20].copy_from_slice(&tuple.destination.octets());
    let ip_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_offset = IPV4_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&tuple.source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&tuple.destination_port.to_be_bytes());
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + udp_len as usize);
    pseudo.extend_from_slice(&tuple.source.octets());
    pseudo.extend_from_slice(&tuple.destination.octets());
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

    #[test]
    fn parses_and_builds_reversed_udp_tuple_with_valid_lengths_checksums() {
        let tuple = FlowTuple {
            source: Ipv4Addr::new(192, 0, 2, 10),
            source_port: 49152,
            destination: Ipv4Addr::new(198, 51, 100, 53),
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
    fn rejects_fragments_and_malformed_lengths() {
        let tuple = FlowTuple {
            source: Ipv4Addr::LOCALHOST,
            source_port: 1234,
            destination: Ipv4Addr::new(1, 1, 1, 1),
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
}
