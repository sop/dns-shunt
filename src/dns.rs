use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    question_end: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("DNS message is truncated or malformed")]
    Malformed,
    #[error("DNS message is not a standard single-question query")]
    Unsupported,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum QueryClassification {
    UnsupportedQuestion,
    Eligible(Question),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnswerRecord {
    A {
        owner: String,
        address: Ipv4Addr,
        ttl: u32,
    },
    Cname {
        owner: String,
        target: String,
        ttl: u32,
    },
}

struct ParsedQuestion {
    id: u16,
    qtype: u16,
    qclass: u16,
    question_end: usize,
    label_offsets: [u16; 127],
    label_count: usize,
}

#[allow(dead_code)]
pub fn parse_query(message: &[u8]) -> Result<Question, DnsError> {
    let parsed = parse_question(message)?;
    validate_sections(message, parsed.question_end)?;
    Ok(parsed.materialize(message))
}

pub(crate) fn classify_query(message: &[u8]) -> Result<QueryClassification, DnsError> {
    let parsed = parse_question(message)?;
    if !matches!(parsed.qtype, 1 | 5 | 28) || parsed.qclass != 1 {
        return Ok(QueryClassification::UnsupportedQuestion);
    }
    validate_sections(message, parsed.question_end)?;
    Ok(QueryClassification::Eligible(parsed.materialize(message)))
}

fn parse_question(message: &[u8]) -> Result<ParsedQuestion, DnsError> {
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
    let mut label_offsets = [0; 127];
    let mut label_count = 0;
    let mut wire_name_length = 0;
    loop {
        let length = *message.get(offset).ok_or(DnsError::Malformed)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > message.len() {
            return Err(DnsError::Malformed);
        }
        if !message[offset..offset + length]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return Err(DnsError::Malformed);
        }
        if label_count == label_offsets.len() {
            return Err(DnsError::Malformed);
        }
        label_offsets[label_count] = offset as u16 - 1;
        label_count += 1;
        wire_name_length += length + 1;
        offset += length;
        if wire_name_length > 254 {
            return Err(DnsError::Malformed);
        }
    }
    if offset + 4 > message.len() {
        return Err(DnsError::Malformed);
    }
    let qtype = u16::from_be_bytes([message[offset], message[offset + 1]]);
    let qclass = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
    Ok(ParsedQuestion {
        id: u16::from_be_bytes([message[0], message[1]]),
        qtype,
        qclass,
        question_end: offset + 4,
        label_offsets,
        label_count,
    })
}

impl ParsedQuestion {
    fn materialize(&self, message: &[u8]) -> Question {
        let name_length = self.label_offsets[..self.label_count]
            .iter()
            .map(|&offset| message[offset as usize] as usize)
            .sum::<usize>()
            + self.label_count.saturating_sub(1);
        let mut name = String::with_capacity(name_length);
        for (index, &offset) in self.label_offsets[..self.label_count].iter().enumerate() {
            if index > 0 {
                name.push('.');
            }
            let start = offset as usize + 1;
            let end = start + message[offset as usize] as usize;
            for &byte in &message[start..end] {
                name.push(byte.to_ascii_lowercase() as char);
            }
        }
        Question {
            id: self.id,
            name,
            qtype: self.qtype,
            qclass: self.qclass,
            question_end: self.question_end,
        }
    }
}

fn validate_sections(message: &[u8], question_end: usize) -> Result<(), DnsError> {
    let record_count = [6, 8, 10]
        .into_iter()
        .map(|index| u16::from_be_bytes([message[index], message[index + 1]]) as usize)
        .sum::<usize>();
    let mut section_offset = question_end;
    for _ in 0..record_count {
        section_offset = skip_name(message, section_offset)?;
        if section_offset + 10 > message.len() {
            return Err(DnsError::Malformed);
        }
        let data_len =
            u16::from_be_bytes([message[section_offset + 8], message[section_offset + 9]]) as usize;
        section_offset += 10 + data_len;
        if section_offset > message.len() {
            return Err(DnsError::Malformed);
        }
    }
    if section_offset != message.len() {
        return Err(DnsError::Malformed);
    }
    Ok(())
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
                let low = *message.get(cursor + 1).ok_or(DnsError::Malformed)?;
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

#[cfg(test)]
pub fn build_a_response(
    query: &[u8],
    question: &Question,
    address: Ipv4Addr,
    ttl: u32,
) -> Result<Vec<u8>, DnsError> {
    build_response(
        query,
        question,
        &[AnswerRecord::A {
            owner: question.name.clone(),
            address,
            ttl,
        }],
    )
}

#[cfg(test)]
pub(crate) fn build_response(
    query: &[u8],
    question: &Question,
    answers: &[AnswerRecord],
) -> Result<Vec<u8>, DnsError> {
    build_response_with_count(query, question, answers).map(|(response, _)| response)
}

pub(crate) fn build_response_with_count(
    query: &[u8],
    question: &Question,
    answers: &[AnswerRecord],
) -> Result<(Vec<u8>, usize), DnsError> {
    if query.len() < 12
        || !matches!(question.qtype, 1 | 5 | 28)
        || question.qclass != 1
        || answers.is_empty()
    {
        return Err(DnsError::Unsupported);
    }
    let question_end = question.question_end;
    if !(16..=query.len()).contains(&question_end) {
        return Err(DnsError::Malformed);
    }
    validate_sections(query, question_end)?;
    let max_payload = advertised_udp_size(query, question_end)?.min(1232);
    let additional_start = additional_start(query, question_end)?;
    let retained_len = query.len() - additional_start;
    let base_len = question_end
        .checked_add(retained_len)
        .ok_or(DnsError::Malformed)?;
    if base_len > max_payload {
        return Err(DnsError::Malformed);
    }

    let mut encoded = Vec::new();
    let mut answer_count = 0usize;
    for answer in answers {
        let mut record = Vec::new();
        encode_answer(&mut record, answer)?;
        if base_len + encoded.len() + record.len() > max_payload {
            break;
        }
        encoded.extend_from_slice(&record);
        answer_count += 1;
    }
    if answer_count == 0 {
        return Err(DnsError::Malformed);
    }

    let mut response = Vec::with_capacity(base_len + encoded.len());
    response.extend_from_slice(&query[..question_end]);
    response.extend_from_slice(&encoded);
    response.extend_from_slice(&query[additional_start..]);
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags = 0x8400 | (request_flags & 0x0110);
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[6..8].copy_from_slice(&(answer_count as u16).to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    Ok((response, answer_count))
}

fn additional_start(query: &[u8], question_end: usize) -> Result<usize, DnsError> {
    let answer_count = u16::from_be_bytes([query[6], query[7]]) as usize;
    let authority_count = u16::from_be_bytes([query[8], query[9]]) as usize;
    let mut offset = question_end;
    for _ in 0..answer_count + authority_count {
        offset = skip_name(query, offset)?;
        if offset + 10 > query.len() {
            return Err(DnsError::Malformed);
        }
        let data_len = u16::from_be_bytes([query[offset + 8], query[offset + 9]]) as usize;
        offset += 10 + data_len;
        if offset > query.len() {
            return Err(DnsError::Malformed);
        }
    }
    Ok(offset)
}

fn advertised_udp_size(query: &[u8], question_end: usize) -> Result<usize, DnsError> {
    let counts = [6, 8, 10]
        .into_iter()
        .map(|index| u16::from_be_bytes([query[index], query[index + 1]]) as usize)
        .collect::<Vec<_>>();
    let mut offset = question_end;
    let mut advertised = 512usize;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            offset = skip_name(query, offset)?;
            if offset + 10 > query.len() {
                return Err(DnsError::Malformed);
            }
            let rr_type = u16::from_be_bytes([query[offset], query[offset + 1]]);
            let class = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);
            let data_len = u16::from_be_bytes([query[offset + 8], query[offset + 9]]) as usize;
            if section == 2 && rr_type == 41 {
                advertised = advertised.max(class as usize);
            }
            offset += 10 + data_len;
        }
    }
    Ok(advertised.clamp(512, 1232))
}

fn encode_answer(output: &mut Vec<u8>, answer: &AnswerRecord) -> Result<(), DnsError> {
    let (owner, rr_type, ttl) = match answer {
        AnswerRecord::A { owner, ttl, .. } => (owner, 1u16, *ttl),
        AnswerRecord::Cname { owner, ttl, .. } => (owner, 5u16, *ttl),
    };
    encode_name(output, owner)?;
    output.extend_from_slice(&rr_type.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&ttl.to_be_bytes());
    let length_offset = output.len();
    output.extend_from_slice(&0u16.to_be_bytes());
    let data_start = output.len();
    match answer {
        AnswerRecord::A { address, .. } => output.extend_from_slice(&address.octets()),
        AnswerRecord::Cname { target, .. } => encode_name(output, target)?,
    }
    let data_len = output.len() - data_start;
    let data_len = u16::try_from(data_len).map_err(|_| DnsError::Malformed)?;
    output[length_offset..length_offset + 2].copy_from_slice(&data_len.to_be_bytes());
    Ok(())
}

fn encode_name(output: &mut Vec<u8>, name: &str) -> Result<(), DnsError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::Malformed);
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DnsError::Malformed);
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
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
        let response =
            build_a_response(&original, &question, Ipv4Addr::new(192, 0, 2, 42), 120).unwrap();
        assert_eq!(&response[12..original.len()], &original[12..]);
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x8400,
            0x8400
        );
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(
            &response[original.len()..],
            &[
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0,
                0, 0, 120, 0, 4, 192, 0, 2, 42,
            ]
        );
    }

    #[test]
    fn unsupported_query_types_are_parseable_but_not_overridden() {
        let message = query("example.com", 15);
        let question = parse_query(&message).unwrap();
        assert_eq!(question.qtype, 15);
        assert!(build_a_response(&message, &question, Ipv4Addr::LOCALHOST, 60).is_err());
    }

    #[test]
    fn keeps_query_additional_records_after_the_answer_section() {
        let mut original = query("example.com", 1);
        original[11] = 1;
        original.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let question = parse_query(&original).unwrap();
        let response =
            build_a_response(&original, &question, Ipv4Addr::new(192, 0, 2, 3), 60).unwrap();
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(
            &response[response.len() - 11..],
            &original[original.len() - 11..]
        );
    }

    #[test]
    fn drops_query_authority_records_but_preserves_additional_edns() {
        let mut original = query("example.com", 1);
        original[9] = 1;
        original[11] = 1;
        original.extend_from_slice(&[1, b'x', 0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);
        original.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let question = parse_query(&original).unwrap();
        let response =
            build_a_response(&original, &question, Ipv4Addr::new(192, 0, 2, 4), 60).unwrap();
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(
            &response[response.len() - 11..],
            &original[original.len() - 11..]
        );
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
        malformed_additional.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8]);
        assert_eq!(parse_query(&malformed_additional), Err(DnsError::Malformed));
        let mut trailing_data = query("example.com", 1);
        trailing_data.push(0);
        assert_eq!(parse_query(&trailing_data), Err(DnsError::Malformed));
    }

    #[test]
    fn classifies_unsupported_question_before_validating_trailing_sections() {
        let mut unsupported = query("example.com", 15);
        unsupported[11] = 1;
        unsupported.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8]);
        assert!(matches!(
            classify_query(&unsupported),
            Ok(QueryClassification::UnsupportedQuestion)
        ));

        let qtype_offset = unsupported.len() - 11 - 4;
        unsupported[qtype_offset..qtype_offset + 2].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(classify_query(&unsupported), Err(DnsError::Malformed));
    }

    #[test]
    fn malformed_header_and_question_remain_errors_for_classifier() {
        assert_eq!(classify_query(&[0; 5]), Err(DnsError::Malformed));

        let mut unsupported_header = query("example.com", 28);
        unsupported_header[2] |= 0x80;
        assert_eq!(
            classify_query(&unsupported_header),
            Err(DnsError::Unsupported)
        );

        let mut malformed_question = query("example.com", 28);
        malformed_question[13] = b'!';
        assert_eq!(
            classify_query(&malformed_question),
            Err(DnsError::Malformed)
        );
    }

    #[test]
    fn enforces_wire_name_length_without_changing_the_limit() {
        let maximum_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let oversized_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert!(parse_query(&query(&maximum_name, 1)).is_ok());
        assert_eq!(
            parse_query(&query(&oversized_name, 1)),
            Err(DnsError::Malformed)
        );
    }

    #[test]
    fn classifies_a_aaaa_and_cname_in_questions() {
        for qtype in [1, 5, 28] {
            assert!(matches!(
                classify_query(&query("alias.example", qtype)),
                Ok(QueryClassification::Eligible(_))
            ));
        }
        assert_eq!(
            classify_query(&query("alias.example", 15)).unwrap(),
            QueryClassification::UnsupportedQuestion
        );
    }

    fn read_name(message: &[u8], mut offset: usize) -> (String, usize) {
        let mut labels = Vec::new();
        loop {
            let length = message[offset] as usize;
            offset += 1;
            if length == 0 {
                return (labels.join("."), offset);
            }
            labels.push(String::from_utf8(message[offset..offset + length].to_vec()).unwrap());
            offset += length;
        }
    }

    #[test]
    fn builds_ordered_cname_and_a_answers_with_ttls_and_additional_data() {
        let mut original = query("alias.example", 1);
        original[11] = 1;
        original.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let question = parse_query(&original).unwrap();
        let response = build_response(
            &original,
            &question,
            &[
                AnswerRecord::Cname {
                    owner: "alias.example".into(),
                    target: "target.example".into(),
                    ttl: 30,
                },
                AnswerRecord::A {
                    owner: "target.example".into(),
                    address: Ipv4Addr::new(192, 0, 2, 7),
                    ttl: 45,
                },
            ],
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 2);
        assert_eq!(
            &response[response.len() - 11..],
            &original[original.len() - 11..]
        );

        let mut offset = question.question_end;
        let (owner, next) = read_name(&response, offset);
        assert_eq!(owner, "alias.example");
        offset = next;
        assert_eq!(
            u16::from_be_bytes([response[offset], response[offset + 1]]),
            5
        );
        assert_eq!(
            u16::from_be_bytes([response[offset + 2], response[offset + 3]]),
            1
        );
        assert_eq!(
            u32::from_be_bytes(response[offset + 4..offset + 8].try_into().unwrap()),
            30
        );
        let data_len = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        let (target, _) = read_name(&response, offset + 10);
        assert_eq!(target, "target.example");
        offset += 10 + data_len;

        let (owner, next) = read_name(&response, offset);
        assert_eq!(owner, "target.example");
        offset = next;
        assert_eq!(
            u16::from_be_bytes([response[offset], response[offset + 1]]),
            1
        );
        assert_eq!(
            u16::from_be_bytes([response[offset + 2], response[offset + 3]]),
            1
        );
        assert_eq!(&response[offset + 10..offset + 14], &[192, 0, 2, 7]);
    }

    #[test]
    fn keeps_the_longest_cname_prefix_that_fits_udp_budget() {
        let original = query("alias.example", 28);
        let question = parse_query(&original).unwrap();
        let long_name = format!(
            "{}.{}.{}.example",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63)
        );
        let response = build_response(
            &original,
            &question,
            &[
                AnswerRecord::Cname {
                    owner: "alias.example".into(),
                    target: long_name.clone(),
                    ttl: 1,
                },
                AnswerRecord::Cname {
                    owner: long_name.clone(),
                    target: long_name.clone(),
                    ttl: 2,
                },
            ],
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert!(response.len() <= 512);
    }

    #[test]
    fn fails_open_when_the_first_cname_cannot_fit() {
        let long_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(55)
        );
        let original = query(&long_name, 1);
        let question = parse_query(&original).unwrap();
        assert!(
            build_response(
                &original,
                &question,
                &[AnswerRecord::Cname {
                    owner: long_name.clone(),
                    target: long_name,
                    ttl: 60,
                }],
            )
            .is_err()
        );
    }
}
