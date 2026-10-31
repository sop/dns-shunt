use crate::config::{CompiledRules, Rule, RuleType};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};
use thiserror::Error;

#[allow(dead_code)]
pub const MDNS_PORT: u16 = 5353;
pub const MDNS_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_IPV6_ADDR: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

pub const MAX_NATIVE_TTL: u32 = 120;
pub const MAX_LEGACY_TTL: u32 = 10;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MdnsError {
    #[error("mDNS message is malformed or truncated")]
    Malformed,
    #[error("mDNS query has TC bit set")]
    Truncated,
    #[error("mDNS query has probe authority records")]
    Probe,
    #[error("mDNS query is unsupported")]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    QmOnly,
    QuOnly,
    Both,
    Legacy,
}

impl DeliveryMode {
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Legacy, _) | (_, Self::Legacy) => Self::Legacy,
            (Self::Both, _) | (_, Self::Both) => Self::Both,
            (Self::QmOnly, Self::QuOnly) | (Self::QuOnly, Self::QmOnly) => Self::Both,
            (Self::QmOnly, Self::QmOnly) => Self::QmOnly,
            (Self::QuOnly, Self::QuOnly) => Self::QuOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MdnsRrKey {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsRecord {
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
    Raw {
        owner: String,
        rr_type: u16,
        class: u16,
        ttl: u32,
        rdata: Vec<u8>,
    },
}

impl MdnsRecord {
    pub fn owner(&self) -> &str {
        match self {
            Self::A { owner, .. } | Self::Cname { owner, .. } | Self::Raw { owner, .. } => owner,
        }
    }

    pub fn rr_type(&self) -> u16 {
        match self {
            Self::A { .. } => 1,
            Self::Cname { .. } => 5,
            Self::Raw { rr_type, .. } => *rr_type,
        }
    }

    pub fn class(&self) -> u16 {
        match self {
            Self::A { .. } | Self::Cname { .. } => 1,
            Self::Raw { class, .. } => *class,
        }
    }

    pub fn ttl(&self) -> u32 {
        match self {
            Self::A { ttl, .. } | Self::Cname { ttl, .. } | Self::Raw { ttl, .. } => *ttl,
        }
    }

    pub fn key(&self) -> MdnsRrKey {
        let mut rdata = Vec::new();
        match self {
            Self::A { address, .. } => {
                rdata.extend_from_slice(&address.octets());
            }
            Self::Cname { target, .. } => {
                let _ = encode_name(&mut rdata, target);
            }
            Self::Raw {
                rdata: raw_rdata, ..
            } => {
                rdata.extend_from_slice(raw_rdata);
            }
        }
        MdnsRrKey {
            name: self.owner().to_ascii_lowercase(),
            rr_type: self.rr_type(),
            class: self.class() & 0x7fff,
            rdata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub unicast_response: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsQuery {
    pub id: u16,
    pub is_legacy: bool,
    pub questions: Vec<MdnsQuestion>,
    pub known_answers: Vec<MdnsRecord>,
    pub raw_questions_section: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsResponseInfo {
    pub id: u16,
    pub answers: Vec<MdnsRecord>,
}

pub fn parse_mdns_query(message: &[u8], is_legacy: bool) -> Result<MdnsQuery, MdnsError> {
    if message.len() < 12 {
        return Err(MdnsError::Malformed);
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);

    // QR must be 0 (query)
    if flags & 0x8000 != 0 {
        return Err(MdnsError::Unsupported);
    }
    // Opcode must be 0
    if flags & 0x7800 != 0 {
        return Err(MdnsError::Unsupported);
    }
    // TC bit: queries with TC set pass through unchanged
    if flags & 0x0200 != 0 {
        return Err(MdnsError::Truncated);
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let nscount = u16::from_be_bytes([message[8], message[9]]) as usize;
    let arcount = u16::from_be_bytes([message[10], message[11]]) as usize;

    if qdcount == 0 {
        return Err(MdnsError::Unsupported);
    }
    // Probe query has proposed records in Authority section
    if nscount > 0 {
        return Err(MdnsError::Probe);
    }

    let mut cursor = 12;
    let questions_start = cursor;
    let mut questions = Vec::with_capacity(qdcount);

    for _ in 0..qdcount {
        let (name, next) = parse_name(message, cursor)?;
        if next + 4 > message.len() {
            return Err(MdnsError::Malformed);
        }
        let qtype = u16::from_be_bytes([message[next], message[next + 1]]);
        let raw_class = u16::from_be_bytes([message[next + 2], message[next + 3]]);
        let unicast_response = (raw_class & 0x8000) != 0;
        let qclass = raw_class & 0x7fff;
        questions.push(MdnsQuestion {
            name,
            qtype,
            qclass,
            unicast_response,
        });
        cursor = next + 4;
    }

    let questions_end = cursor;
    let raw_questions_section = message[questions_start..questions_end].to_vec();

    // Parse known answers in Answer section
    let mut known_answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (record, next) = parse_record(message, cursor)?;
        known_answers.push(record);
        cursor = next;
    }

    // Skip/validate Additional records
    for _ in 0..arcount {
        let (_, next) = parse_record(message, cursor)?;
        cursor = next;
    }

    if cursor != message.len() {
        return Err(MdnsError::Malformed);
    }

    Ok(MdnsQuery {
        id,
        is_legacy,
        questions,
        known_answers,
        raw_questions_section,
    })
}

pub fn parse_mdns_response(message: &[u8]) -> Result<MdnsResponseInfo, MdnsError> {
    if message.len() < 12 {
        return Err(MdnsError::Malformed);
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);

    // QR must be 1 (response)
    if flags & 0x8000 == 0 {
        return Err(MdnsError::Unsupported);
    }
    // Opcode must be 0
    if flags & 0x7800 != 0 {
        return Err(MdnsError::Unsupported);
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let nscount = u16::from_be_bytes([message[8], message[9]]) as usize;
    let arcount = u16::from_be_bytes([message[10], message[11]]) as usize;

    let mut cursor = 12;
    for _ in 0..qdcount {
        let (_, next) = parse_name(message, cursor)?;
        if next + 4 > message.len() {
            return Err(MdnsError::Malformed);
        }
        cursor = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (record, next) = parse_record(message, cursor)?;
        answers.push(record);
        cursor = next;
    }

    for _ in 0..nscount {
        let (record, next) = parse_record(message, cursor)?;
        answers.push(record);
        cursor = next;
    }

    for _ in 0..arcount {
        let (record, next) = parse_record(message, cursor)?;
        answers.push(record);
        cursor = next;
    }

    if cursor != message.len() {
        return Err(MdnsError::Malformed);
    }

    Ok(MdnsResponseInfo { id, answers })
}

fn parse_record(message: &[u8], offset: usize) -> Result<(MdnsRecord, usize), MdnsError> {
    let (owner, next) = parse_name(message, offset)?;
    if next + 10 > message.len() {
        return Err(MdnsError::Malformed);
    }
    let rr_type = u16::from_be_bytes([message[next], message[next + 1]]);
    let class_raw = u16::from_be_bytes([message[next + 2], message[next + 3]]);
    let class = class_raw & 0x7fff;
    let ttl = u32::from_be_bytes(message[next + 4..next + 8].try_into().unwrap());
    let rdlength = u16::from_be_bytes([message[next + 8], message[next + 9]]) as usize;
    let rdata_start = next + 10;
    let rdata_end = rdata_start + rdlength;
    if rdata_end > message.len() {
        return Err(MdnsError::Malformed);
    }

    let record = match rr_type {
        1 if rdlength == 4 => {
            let addr = Ipv4Addr::new(
                message[rdata_start],
                message[rdata_start + 1],
                message[rdata_start + 2],
                message[rdata_start + 3],
            );
            MdnsRecord::A {
                owner,
                address: addr,
                ttl,
            }
        }
        5 => {
            let (target, target_end) = parse_name(message, rdata_start)?;
            if target_end != rdata_end {
                // If compression/formatting inside RDATA does not match rdlength exactly,
                // fall back to Raw with original bytes
                MdnsRecord::Raw {
                    owner,
                    rr_type,
                    class,
                    ttl,
                    rdata: message[rdata_start..rdata_end].to_vec(),
                }
            } else {
                MdnsRecord::Cname { owner, target, ttl }
            }
        }
        _ => MdnsRecord::Raw {
            owner,
            rr_type,
            class,
            ttl,
            rdata: message[rdata_start..rdata_end].to_vec(),
        },
    };

    Ok((record, rdata_end))
}

fn parse_name(message: &[u8], offset: usize) -> Result<(String, usize), MdnsError> {
    let mut cursor = offset;
    let mut resume = None;
    let mut steps = 0;
    let mut labels = Vec::new();
    let mut wire_len = 0;

    loop {
        steps += 1;
        if steps > message.len() {
            return Err(MdnsError::Malformed);
        }
        let length = *message.get(cursor).ok_or(MdnsError::Malformed)?;
        match length & 0xc0 {
            0 => {
                cursor += 1;
                if length == 0 {
                    return Ok((labels.join("."), resume.unwrap_or(cursor)));
                }
                let len = length as usize;
                if len > 63 || cursor + len > message.len() {
                    return Err(MdnsError::Malformed);
                }
                let label_bytes = &message[cursor..cursor + len];
                for &b in label_bytes {
                    if !b.is_ascii_alphanumeric() && b != b'-' && b != b'_' {
                        return Err(MdnsError::Malformed);
                    }
                }
                let label = std::str::from_utf8(label_bytes)
                    .map_err(|_| MdnsError::Malformed)?
                    .to_ascii_lowercase();
                wire_len += len + 1;
                if wire_len > 254 {
                    return Err(MdnsError::Malformed);
                }
                labels.push(label);
                cursor += len;
            }
            0xc0 => {
                let low = *message.get(cursor + 1).ok_or(MdnsError::Malformed)?;
                let target = (((length & 0x3f) as usize) << 8) | low as usize;
                if target >= message.len() {
                    return Err(MdnsError::Malformed);
                }
                if resume.is_none() {
                    resume = Some(cursor + 2);
                }
                cursor = target;
            }
            _ => return Err(MdnsError::Malformed),
        }
    }
}

pub struct CandidateAnswer<'a> {
    pub record: MdnsRecord,
    pub contributing_rule: &'a Rule,
    pub delivery: DeliveryMode,
}

pub fn resolve_mdns_query<'a>(
    rules: &'a CompiledRules,
    query: &MdnsQuery,
) -> Vec<CandidateAnswer<'a>> {
    let mut candidates: Vec<CandidateAnswer<'a>> = Vec::new();
    let mut seen_keys: HashMap<MdnsRrKey, usize> = HashMap::new();

    for q in &query.questions {
        if q.qclass != 1 {
            continue;
        }
        let mode = if query.is_legacy {
            DeliveryMode::Legacy
        } else if q.unicast_response {
            DeliveryMode::QuOnly
        } else {
            DeliveryMode::QmOnly
        };

        // Match explicit rule only; do NOT match built-in GUI name
        let Some(rule) = rules.lookup_normalized(&q.name) else {
            continue;
        };

        match rule.record_type {
            RuleType::A => {
                if q.qtype == 1 {
                    let record = MdnsRecord::A {
                        owner: q.name.clone(),
                        address: rule.address.expect("validated A address"),
                        ttl: rule.ttl,
                    };
                    add_or_combine(&mut candidates, &mut seen_keys, record, rule, mode, query);
                }
            }
            RuleType::Cname => {
                let target = rule.target.as_deref().expect("validated CNAME target");
                match q.qtype {
                    1 => {
                        // For A query: synthesize CNAME with concrete queried name as owner,
                        // and include target's exact A record if present.
                        let cname_record = MdnsRecord::Cname {
                            owner: q.name.clone(),
                            target: target.to_owned(),
                            ttl: rule.ttl,
                        };
                        add_or_combine(
                            &mut candidates,
                            &mut seen_keys,
                            cname_record,
                            rule,
                            mode,
                            query,
                        );

                        if let Some(target_rule) = rules.lookup_exact(target)
                            && target_rule.record_type == RuleType::A
                            && let Some(address) = target_rule.address
                        {
                            let a_record = MdnsRecord::A {
                                owner: target.to_owned(),
                                address,
                                ttl: target_rule.ttl,
                            };
                            add_or_combine(
                                &mut candidates,
                                &mut seen_keys,
                                a_record,
                                target_rule,
                                mode,
                                query,
                            );
                        }
                    }
                    5 | 28 => {
                        // For CNAME or AAAA query: synthesize CNAME alias with concrete queried name
                        let cname_record = MdnsRecord::Cname {
                            owner: q.name.clone(),
                            target: target.to_owned(),
                            ttl: rule.ttl,
                        };
                        add_or_combine(
                            &mut candidates,
                            &mut seen_keys,
                            cname_record,
                            rule,
                            mode,
                            query,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    candidates
}

fn add_or_combine<'a>(
    candidates: &mut Vec<CandidateAnswer<'a>>,
    seen_keys: &mut HashMap<MdnsRrKey, usize>,
    record: MdnsRecord,
    contributing_rule: &'a Rule,
    mode: DeliveryMode,
    query: &MdnsQuery,
) {
    let key = record.key();
    let max_ttl = if query.is_legacy {
        MAX_LEGACY_TTL
    } else {
        MAX_NATIVE_TTL
    };
    let emitted_ttl = record.ttl().min(max_ttl);

    // Known-answer suppression:
    // Suppress local answer when query already carries equivalent record
    // with TTL at least half the emitted (capped) answer TTL.
    let half_emitted_ttl = emitted_ttl.div_ceil(2);
    for known in &query.known_answers {
        if known.key() == key && known.ttl() >= half_emitted_ttl {
            return;
        }
    }

    if let Some(&index) = seen_keys.get(&key) {
        // Deduplicate equivalent answers from repeated questions
        candidates[index].delivery = candidates[index].delivery.combine(mode);
    } else {
        seen_keys.insert(key, candidates.len());
        candidates.push(CandidateAnswer {
            record,
            contributing_rule,
            delivery: mode,
        });
    }
}

pub type PartitionedAnswers<'a> = (
    Vec<(&'a MdnsRecord, &'a Rule)>,
    Vec<(&'a MdnsRecord, &'a Rule)>,
);

#[allow(dead_code)]
pub fn partition_native_answers<'a>(
    candidates: &'a [CandidateAnswer<'a>],
    suppressed_keys: &HashSet<MdnsRrKey>,
    is_rate_limited: impl Fn(&MdnsRrKey) -> bool,
) -> PartitionedAnswers<'a> {
    let mut qm_answers = Vec::new();
    let mut qu_answers = Vec::new();

    for candidate in candidates {
        let key = candidate.record.key();
        if suppressed_keys.contains(&key) {
            continue;
        }
        match candidate.delivery {
            DeliveryMode::QmOnly => {
                if !is_rate_limited(&key) {
                    qm_answers.push((&candidate.record, candidate.contributing_rule));
                }
            }
            DeliveryMode::QuOnly => {
                qu_answers.push((&candidate.record, candidate.contributing_rule));
            }
            DeliveryMode::Both => {
                if !is_rate_limited(&key) {
                    qm_answers.push((&candidate.record, candidate.contributing_rule));
                } else {
                    // Fall back to QU if QM is rate-limited
                    qu_answers.push((&candidate.record, candidate.contributing_rule));
                }
            }
            DeliveryMode::Legacy => {}
        }
    }

    (qm_answers, qu_answers)
}

#[allow(dead_code)]
pub fn filter_legacy_answers<'a>(
    candidates: &'a [CandidateAnswer<'a>],
    suppressed_keys: &HashSet<MdnsRrKey>,
) -> Vec<(&'a MdnsRecord, &'a Rule)> {
    let mut legacy_answers = Vec::new();
    for candidate in candidates {
        let key = candidate.record.key();
        if suppressed_keys.contains(&key) {
            continue;
        }
        if candidate.delivery == DeliveryMode::Legacy {
            legacy_answers.push((&candidate.record, candidate.contributing_rule));
        }
    }
    legacy_answers
}

pub fn build_native_response(records: &[&MdnsRecord]) -> Result<Vec<u8>, MdnsError> {
    if records.is_empty() {
        return Err(MdnsError::Unsupported);
    }
    let mut output = Vec::with_capacity(512);
    // Header
    output.extend_from_slice(&0u16.to_be_bytes()); // ID: 0
    output.extend_from_slice(&0x8400u16.to_be_bytes()); // Flags: QR=1, AA=1
    output.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT: 0
    output.extend_from_slice(&(records.len() as u16).to_be_bytes()); // ANCOUNT
    output.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
    output.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0

    for &record in records {
        encode_record(&mut output, record, MAX_NATIVE_TTL)?;
    }
    Ok(output)
}

pub fn build_legacy_response(
    query_id: u16,
    questions_raw: &[u8],
    question_count: u16,
    records: &[&MdnsRecord],
) -> Result<Vec<u8>, MdnsError> {
    if records.is_empty() {
        return Err(MdnsError::Unsupported);
    }
    let mut output = Vec::with_capacity(512);
    // Header
    output.extend_from_slice(&query_id.to_be_bytes()); // ID echoed
    output.extend_from_slice(&0x8400u16.to_be_bytes()); // Flags: QR=1, AA=1
    output.extend_from_slice(&question_count.to_be_bytes()); // QDCOUNT echoed
    output.extend_from_slice(&(records.len() as u16).to_be_bytes()); // ANCOUNT
    output.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
    output.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0

    // Echo questions verbatim
    output.extend_from_slice(questions_raw);

    for &record in records {
        encode_record(&mut output, record, MAX_LEGACY_TTL)?;
    }
    Ok(output)
}

fn encode_record(output: &mut Vec<u8>, record: &MdnsRecord, max_ttl: u32) -> Result<(), MdnsError> {
    encode_name(output, record.owner())?;
    output.extend_from_slice(&record.rr_type().to_be_bytes());
    // Class 1 (IN), cache-flush bit NOT set per RFC 6762 for shared records
    output.extend_from_slice(&1u16.to_be_bytes());
    let ttl = record.ttl().min(max_ttl);
    output.extend_from_slice(&ttl.to_be_bytes());

    let len_offset = output.len();
    output.extend_from_slice(&0u16.to_be_bytes());
    let data_start = output.len();

    match record {
        MdnsRecord::A { address, .. } => {
            output.extend_from_slice(&address.octets());
        }
        MdnsRecord::Cname { target, .. } => {
            encode_name(output, target)?;
        }
        MdnsRecord::Raw { rdata, .. } => {
            output.extend_from_slice(rdata);
        }
    }

    let rdlen = output.len() - data_start;
    let rdlen_u16 = u16::try_from(rdlen).map_err(|_| MdnsError::Malformed)?;
    output[len_offset..len_offset + 2].copy_from_slice(&rdlen_u16.to_be_bytes());
    Ok(())
}

fn encode_name(output: &mut Vec<u8>, name: &str) -> Result<(), MdnsError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(MdnsError::Malformed);
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(MdnsError::Malformed);
        }
        output.push(label.len() as u8);
        for &b in label.as_bytes() {
            output.push(b.to_ascii_lowercase());
        }
    }
    output.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleInput;

    fn build_wire_query(
        id: u16,
        questions: &[(&str, u16, u16)],
        known_answers: &[(&str, u16, u32, &[u8])],
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&0x0000u16.to_be_bytes()); // Flags: query, opcode 0
        msg.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        msg.extend_from_slice(&(known_answers.len() as u16).to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        for &(name, qtype, qclass) in questions {
            encode_name(&mut msg, name).unwrap();
            msg.extend_from_slice(&qtype.to_be_bytes());
            msg.extend_from_slice(&qclass.to_be_bytes());
        }

        for &(name, rr_type, ttl, rdata) in known_answers {
            encode_name(&mut msg, name).unwrap();
            msg.extend_from_slice(&rr_type.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&ttl.to_be_bytes());
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(rdata);
        }

        msg
    }

    #[test]
    fn parses_mdns_query_with_multiple_questions_and_qu_bits() {
        let wire = build_wire_query(
            0,
            &[
                ("test.local", 1, 1),        // QM
                ("alias.local", 28, 0x8001), // QU
            ],
            &[],
        );
        let query = parse_mdns_query(&wire, false).unwrap();
        assert_eq!(query.id, 0);
        assert_eq!(query.questions.len(), 2);
        assert_eq!(query.questions[0].name, "test.local");
        assert_eq!(query.questions[0].qtype, 1);
        assert_eq!(query.questions[0].qclass, 1);
        assert!(!query.questions[0].unicast_response);

        assert_eq!(query.questions[1].name, "alias.local");
        assert_eq!(query.questions[1].qtype, 28);
        assert_eq!(query.questions[1].qclass, 1);
        assert!(query.questions[1].unicast_response);
    }

    #[test]
    fn probe_queries_and_truncated_queries_are_identified() {
        let mut probe_wire = build_wire_query(0, &[("probe.local", 1, 1)], &[]);
        probe_wire[8..10].copy_from_slice(&1u16.to_be_bytes()); // NSCOUNT = 1
        assert_eq!(parse_mdns_query(&probe_wire, false), Err(MdnsError::Probe));

        let mut tc_wire = build_wire_query(0, &[("tc.local", 1, 1)], &[]);
        tc_wire[2] |= 0x02; // TC bit
        assert_eq!(parse_mdns_query(&tc_wire, false), Err(MdnsError::Truncated));
    }

    #[test]
    fn suppresses_known_answer_when_ttl_is_at_least_half_emitted() {
        let rules_vec = crate::config::validate_rules(
            vec![RuleInput {
                name: "example.local".into(),
                record_type: RuleType::A,
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(100),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        // Native response emitted TTL is min(100, 120) = 100.
        // Half TTL is 50.
        // Known answer with TTL 50 should suppress
        let wire_suppressed = build_wire_query(
            0,
            &[("example.local", 1, 1)],
            &[("example.local", 1, 50, &[192, 0, 2, 1])],
        );
        let query_suppressed = parse_mdns_query(&wire_suppressed, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query_suppressed);
        assert!(answers.is_empty());

        // Known answer with TTL 49 should NOT suppress
        let wire_kept = build_wire_query(
            0,
            &[("example.local", 1, 1)],
            &[("example.local", 1, 49, &[192, 0, 2, 1])],
        );
        let query_kept = parse_mdns_query(&wire_kept, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query_kept);
        assert_eq!(answers.len(), 1);
    }

    #[test]
    fn motivates_cname_alias_and_exact_target_a_in_one_response() {
        let rules_vec = crate::config::validate_rules(
            vec![
                RuleInput {
                    name: "example.local".into(),
                    record_type: RuleType::A,
                    address: Some("192.0.2.80".into()),
                    target: None,
                    ttl: Some(80),
                },
                RuleInput {
                    name: "*.example.local".into(),
                    record_type: RuleType::Cname,
                    address: None,
                    target: Some("example.local".into()),
                    ttl: Some(40),
                },
            ],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        let wire = build_wire_query(0, &[("test.example.local", 1, 1)], &[]);
        let query = parse_mdns_query(&wire, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query);

        assert_eq!(answers.len(), 2);
        // Record 1: CNAME for test.example.local -> example.local
        match &answers[0].record {
            MdnsRecord::Cname { owner, target, ttl } => {
                assert_eq!(owner, "test.example.local");
                assert_eq!(target, "example.local");
                assert_eq!(*ttl, 40);
            }
            _ => panic!("expected CNAME record"),
        }
        // Record 2: exact target A record for example.local -> 192.0.2.80
        match &answers[1].record {
            MdnsRecord::A {
                owner,
                address,
                ttl,
            } => {
                assert_eq!(owner, "example.local");
                assert_eq!(*address, Ipv4Addr::new(192, 0, 2, 80));
                assert_eq!(*ttl, 80);
            }
            _ => panic!("expected A record"),
        }

        let resp_records: Vec<&MdnsRecord> = answers.iter().map(|a| &a.record).collect();
        let resp_bytes = build_native_response(&resp_records).unwrap();
        assert_eq!(u16::from_be_bytes([resp_bytes[0], resp_bytes[1]]), 0); // ID 0
        assert_eq!(u16::from_be_bytes([resp_bytes[4], resp_bytes[5]]), 0); // QDCOUNT 0
        assert_eq!(u16::from_be_bytes([resp_bytes[6], resp_bytes[7]]), 2); // ANCOUNT 2
    }

    #[test]
    fn cname_wildcard_answers_aaaa_without_target_a() {
        let rules_vec = crate::config::validate_rules(
            vec![
                RuleInput {
                    name: "example.local".into(),
                    record_type: RuleType::A,
                    address: Some("192.0.2.80".into()),
                    target: None,
                    ttl: Some(80),
                },
                RuleInput {
                    name: "*.example.local".into(),
                    record_type: RuleType::Cname,
                    address: None,
                    target: Some("example.local".into()),
                    ttl: Some(40),
                },
            ],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        let wire = build_wire_query(0, &[("test.example.local", 28, 1)], &[]);
        let query = parse_mdns_query(&wire, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query);

        assert_eq!(answers.len(), 1);
        match &answers[0].record {
            MdnsRecord::Cname { owner, target, .. } => {
                assert_eq!(owner, "test.example.local");
                assert_eq!(target, "example.local");
            }
            _ => panic!("expected CNAME record"),
        }
    }

    #[test]
    fn legacy_query_echoes_id_and_questions_and_caps_ttl_at_ten() {
        let rules_vec = crate::config::validate_rules(
            vec![RuleInput {
                name: "host.local".into(),
                record_type: RuleType::A,
                address: Some("192.0.2.5".into()),
                target: None,
                ttl: Some(60),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        let wire = build_wire_query(0x4321, &[("host.local", 1, 1)], &[]);
        let query = parse_mdns_query(&wire, true).unwrap();
        let answers = resolve_mdns_query(&rules, &query);

        assert_eq!(answers.len(), 1);
        let resp_records: Vec<&MdnsRecord> = answers.iter().map(|a| &a.record).collect();
        let resp_bytes = build_legacy_response(
            query.id,
            &query.raw_questions_section,
            query.questions.len() as u16,
            &resp_records,
        )
        .unwrap();

        assert_eq!(&resp_bytes[..2], &[0x43, 0x21]); // ID echoed
        assert_eq!(u16::from_be_bytes([resp_bytes[4], resp_bytes[5]]), 1); // QDCOUNT 1
        assert_eq!(u16::from_be_bytes([resp_bytes[6], resp_bytes[7]]), 1); // ANCOUNT 1

        let parsed_resp = parse_mdns_response(&resp_bytes).unwrap();
        assert_eq!(parsed_resp.id, 0x4321);
        assert_eq!(parsed_resp.answers.len(), 1);
        assert_eq!(parsed_resp.answers[0].ttl(), 10); // Capped at 10 for legacy
    }

    #[test]
    fn partitions_native_answers_with_rate_limiting_and_suppression() {
        let rule = Rule {
            name: "example.local".into(),
            wildcard: false,
            record_type: RuleType::A,
            address: Some(Ipv4Addr::new(192, 0, 2, 1)),
            target: None,
            ttl: 60,
        };
        let candidates = vec![
            CandidateAnswer {
                record: MdnsRecord::A {
                    owner: "example.local".into(),
                    address: Ipv4Addr::new(192, 0, 2, 1),
                    ttl: 60,
                },
                contributing_rule: &rule,
                delivery: DeliveryMode::Both,
            },
            CandidateAnswer {
                record: MdnsRecord::Cname {
                    owner: "alias.local".into(),
                    target: "example.local".into(),
                    ttl: 60,
                },
                contributing_rule: &rule,
                delivery: DeliveryMode::QuOnly,
            },
        ];

        let suppressed = HashSet::new();
        // If rate limited on QM, the Both item falls back to QU
        let (qm, qu) = partition_native_answers(&candidates, &suppressed, |_| true);
        assert!(qm.is_empty());
        assert_eq!(qu.len(), 2);

        // If not rate limited, Both stays in QM
        let (qm2, qu2) = partition_native_answers(&candidates, &suppressed, |_| false);
        assert_eq!(qm2.len(), 1);
        assert_eq!(qu2.len(), 1);

        let legacy_candidates = vec![CandidateAnswer {
            record: MdnsRecord::A {
                owner: "example.local".into(),
                address: Ipv4Addr::new(192, 0, 2, 1),
                ttl: 60,
            },
            contributing_rule: &rule,
            delivery: DeliveryMode::Legacy,
        }];
        let legacy = filter_legacy_answers(&legacy_candidates, &suppressed);
        assert_eq!(legacy.len(), 1);
    }
}
