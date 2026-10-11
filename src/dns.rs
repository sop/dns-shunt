use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("DNS message is truncated or malformed")]
    Malformed,
    #[error("DNS message is not a standard single-question query")]
    Unsupported,
}

pub fn parse_query(message: &[u8]) -> Result<Question, DnsError> {
    if message.len() < 12 {
        return Err(DnsError::Malformed);
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 {
        return Err(DnsError::Unsupported);
    }
    if u16::from_be_bytes([message[4], message[5]]) != 1 {
        return Err(DnsError::Unsupported);
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = *message.get(offset).ok_or(DnsError::Malformed)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > message.len() {
            return Err(DnsError::Malformed);
        }
        let label = std::str::from_utf8(&message[offset..offset + length])
            .map_err(|_| DnsError::Malformed)?;
        if !label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
        }) {
            return Err(DnsError::Malformed);
        }
        labels.push(label.to_ascii_lowercase());
        offset += length;
        if labels
            .iter()
            .map(|label: &String| label.len() + 1)
            .sum::<usize>()
            > 254
        {
            return Err(DnsError::Malformed);
        }
    }
    if offset + 4 > message.len() {
        return Err(DnsError::Malformed);
    }
    let qtype = u16::from_be_bytes([message[offset], message[offset + 1]]);
    let qclass = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
    let record_count = [6, 8, 10]
        .into_iter()
        .map(|index| {
            u16::from_be_bytes([message[index], message[index + 1]]) as usize
        })
        .sum::<usize>();
    let mut section_offset = offset + 4;
    for _ in 0..record_count {
        section_offset = skip_name(message, section_offset)?;
        if section_offset + 10 > message.len() {
            return Err(DnsError::Malformed);
        }
        let data_len = u16::from_be_bytes([
            message[section_offset + 8],
            message[section_offset + 9],
        ]) as usize;
        section_offset += 10 + data_len;
        if section_offset > message.len() {
            return Err(DnsError::Malformed);
        }
    }
    if section_offset != message.len() {
        return Err(DnsError::Malformed);
    }
    Ok(Question {
        id: u16::from_be_bytes([message[0], message[1]]),
        name: labels.join("."),
        qtype,
        qclass,
    })
}

fn skip_name(message: &[u8], offset: usize) -> Result<usize, DnsError> {
    let mut cursor = offset;
    let mut resume = None;
    let mut steps = 0;
    loop {
        let length = *message.get(cursor).ok_or(DnsError::Malformed)?;
        steps += 1;
        if steps > message.len() {
            return Err(DnsError::Malformed);
        }
        match length & 0xc0 {
            0 => {
                cursor += 1;
                if length == 0 {
                    return Ok(resume.unwrap_or(cursor));
                }
                let end = cursor + length as usize;
                if end > message.len() {
                    return Err(DnsError::Malformed);
                }
                cursor = end;
            }
            0xc0 => {
                let low =
                    *message.get(cursor + 1).ok_or(DnsError::Malformed)?;
                let target = (((length & 0x3f) as usize) << 8) | low as usize;
                if target >= message.len() {
                    return Err(DnsError::Malformed);
                }
                resume.get_or_insert(cursor + 2);
                cursor = target;
            }
            _ => return Err(DnsError::Malformed),
        }
    }
}

pub fn build_a_response(
    query: &[u8],
    question: &Question,
    address: Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, DnsError> {
    if query.len() < 12 || question.qtype != 1 || question.qclass != 1 {
        return Err(DnsError::Unsupported);
    }
    let mut question_end = 12;
    loop {
        let length =
            *query.get(question_end).ok_or(DnsError::Malformed)? as usize;
        question_end += 1;
        if length == 0 {
            break;
        }
        if length > 63 || question_end + length > query.len() {
            return Err(DnsError::Malformed);
        }
        question_end += length;
    }
    if question_end + 4 > query.len() {
        return Err(DnsError::Malformed);
    }
    question_end += 4;

    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(&query[..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&address.octets());
    response.extend_from_slice(&query[question_end..]);
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags = 0x8400 | (request_flags & 0x0110);
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message
    }

    #[test]
    fn builds_a_response_preserving_id_and_question() {
        let original = query("example.com", 1);
        let question = parse_query(&original).unwrap();
        let response = build_a_response(
            &original,
            &question,
            Ipv4Addr::new(192, 0, 2, 42),
            120,
        )
        .unwrap();
        assert_eq!(&response[12..original.len()], &original[12..]);
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x8400,
            0x8400
        );
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(
            &response[original.len()..],
            &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 42]
        );
    }

    #[test]
    fn unsupported_query_types_are_parseable_but_not_overridden() {
        let message = query("example.com", 28);
        let question = parse_query(&message).unwrap();
        assert_eq!(question.qtype, 28);
        assert!(
            build_a_response(&message, &question, Ipv4Addr::LOCALHOST, 60)
                .is_err()
        );
    }

    #[test]
    fn keeps_query_additional_records_after_the_answer_section() {
        let mut original = query("example.com", 1);
        original[11] = 1;
        original.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let question = parse_query(&original).unwrap();
        let response = build_a_response(
            &original,
            &question,
            Ipv4Addr::new(192, 0, 2, 3),
            60,
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        let answer_end = original.len() + 5;
        assert_eq!(&response[answer_end..], &original[original.len() - 11..]);
    }

    #[test]
    fn rejects_truncated_or_response_messages_as_queries() {
        assert_eq!(parse_query(&[0; 5]), Err(DnsError::Malformed));
        let mut response = query("example.com", 1);
        response[2] |= 0x80;
        assert_eq!(parse_query(&response), Err(DnsError::Unsupported));
        assert_eq!(
            parse_query(&query("example.com", 1)[..14]),
            Err(DnsError::Malformed)
        );
        let mut malformed_additional = query("example.com", 1);
        malformed_additional[11] = 1;
        malformed_additional
            .extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8]);
        assert_eq!(
            parse_query(&malformed_additional),
            Err(DnsError::Malformed)
        );
        let mut trailing_data = query("example.com", 1);
        trailing_data.push(0);
        assert_eq!(parse_query(&trailing_data), Err(DnsError::Malformed));
    }
}
