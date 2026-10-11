use crate::{backend::BackendError, packet::FlowTuple};
use std::net::Ipv4Addr;

pub const PROTOCOL_MAGIC: u32 = u32::from_le_bytes(*b"WFP1");
pub const PROTOCOL_VERSION: u16 = 1;
pub const CAPTURE_HEADER_LEN: usize = 36;
pub const COMMAND_HEADER_LEN: usize = 24;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize - 28;
pub const IOCTL_RESOLVE: u32 = 0x0022_e004;
pub const IOCTL_SHUTDOWN: u32 = 0x0022_e008;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedDatagram {
    pub token: u64,
    pub tuple: FlowTuple,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution<'a> {
    Reinject { token: u64 },
    Response { token: u64, payload: &'a [u8] },
}

pub fn decode_capture(record: &[u8]) -> Result<CapturedDatagram, BackendError> {
    if record.len() < CAPTURE_HEADER_LEN {
        return Err(BackendError("truncated WFP capture header".into()));
    }
    let magic = read_u32(record, 0);
    let version = read_u16(record, 4);
    let header_len = read_u16(record, 6) as usize;
    let total_len = read_u32(record, 8) as usize;
    let payload_len = read_u32(record, 12) as usize;
    if magic != PROTOCOL_MAGIC
        || version != PROTOCOL_VERSION
        || header_len != CAPTURE_HEADER_LEN
        || total_len != record.len()
        || total_len != CAPTURE_HEADER_LEN.saturating_add(payload_len)
        || payload_len > MAX_PAYLOAD_LEN
    {
        return Err(BackendError("invalid WFP capture framing".into()));
    }
    let source = Ipv4Addr::new(record[24], record[25], record[26], record[27]);
    let destination =
        Ipv4Addr::new(record[28], record[29], record[30], record[31]);
    let source_port = read_u16(record, 32);
    let destination_port = read_u16(record, 34);
    if destination_port != 53 {
        return Err(BackendError("WFP capture is not outbound DNS".into()));
    }
    Ok(CapturedDatagram {
        token: read_u64(record, 16),
        tuple: FlowTuple {
            source,
            source_port,
            destination,
            destination_port,
        },
        payload: record[CAPTURE_HEADER_LEN..].to_vec(),
    })
}

pub fn encode_resolution(
    resolution: Resolution<'_>,
) -> Result<Vec<u8>, BackendError> {
    let (command, token, payload) = match resolution {
        Resolution::Reinject { token } => (1u16, token, &[][..]),
        Resolution::Response { token, payload } => (2u16, token, payload),
    };
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(BackendError(
            "WFP response exceeds UDP payload limit".into(),
        ));
    }
    let total_len = COMMAND_HEADER_LEN + payload.len();
    let mut bytes = vec![0; total_len];
    bytes[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
    bytes[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes[6..8].copy_from_slice(&command.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total_len as u32).to_le_bytes());
    bytes[12..20].copy_from_slice(&token.to_le_bytes());
    bytes[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes[COMMAND_HEADER_LEN..].copy_from_slice(payload);
    Ok(bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed protocol field"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed protocol field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![0; CAPTURE_HEADER_LEN + payload.len()];
        let total_len = record.len() as u32;
        record[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
        record[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        record[6..8]
            .copy_from_slice(&(CAPTURE_HEADER_LEN as u16).to_le_bytes());
        record[8..12].copy_from_slice(&total_len.to_le_bytes());
        record[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        record[16..24].copy_from_slice(&99u64.to_le_bytes());
        record[24..28].copy_from_slice(&[192, 0, 2, 7]);
        record[28..32].copy_from_slice(&[1, 1, 1, 1]);
        record[32..34].copy_from_slice(&53000u16.to_le_bytes());
        record[34..36].copy_from_slice(&53u16.to_le_bytes());
        record[CAPTURE_HEADER_LEN..].copy_from_slice(payload);
        record
    }

    #[test]
    fn validates_capture_framing_and_decodes_tuple() {
        let decoded = decode_capture(&capture(b"dns")).unwrap();
        assert_eq!(decoded.token, 99);
        assert_eq!(decoded.tuple.source, Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(decoded.tuple.source_port, 53000);
        assert_eq!(decoded.payload, b"dns");

        let mut truncated = capture(b"dns");
        let truncated_len = (truncated.len() - 1) as u32;
        truncated[8..12].copy_from_slice(&truncated_len.to_le_bytes());
        assert!(decode_capture(&truncated).is_err());
    }

    #[test]
    fn encodes_one_terminal_command_and_bounds_dns_payload() {
        let command = encode_resolution(Resolution::Response {
            token: 123,
            payload: b"answer",
        })
        .unwrap();
        assert_eq!(read_u16(&command, 6), 2);
        assert_eq!(read_u64(&command, 12), 123);
        assert_eq!(&command[COMMAND_HEADER_LEN..], b"answer");
        assert!(
            encode_resolution(Resolution::Response {
                token: 1,
                payload: &vec![0; MAX_PAYLOAD_LEN + 1],
            })
            .is_err()
        );
    }
}
