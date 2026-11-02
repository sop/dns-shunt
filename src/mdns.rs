use crate::{
    admin::RuntimeState,
    backend::{FlowContext, InterceptionBackend},
    config::{CompiledRules, Rule, RuleType},
    packet::{FlowTuple, build_udp},
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

pub const MDNS_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_IPV6_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

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
    Aaaa {
        owner: String,
        address: Ipv6Addr,
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
            Self::A { owner, .. }
            | Self::Aaaa { owner, .. }
            | Self::Cname { owner, .. }
            | Self::Raw { owner, .. } => owner,
        }
    }

    pub fn rr_type(&self) -> u16 {
        match self {
            Self::A { .. } => 1,
            Self::Cname { .. } => 5,
            Self::Aaaa { .. } => 28,
            Self::Raw { rr_type, .. } => *rr_type,
        }
    }

    pub fn class(&self) -> u16 {
        match self {
            Self::A { .. } | Self::Aaaa { .. } | Self::Cname { .. } => 1,
            Self::Raw { class, .. } => *class,
        }
    }

    pub fn ttl(&self) -> u32 {
        match self {
            Self::A { ttl, .. }
            | Self::Aaaa { ttl, .. }
            | Self::Cname { ttl, .. }
            | Self::Raw { ttl, .. } => *ttl,
        }
    }

    pub fn key(&self) -> MdnsRrKey {
        let mut rdata = Vec::new();
        match self {
            Self::A { address, .. } => {
                rdata.extend_from_slice(&address.octets());
            }
            Self::Aaaa { address, .. } => {
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
#[cfg(test)]
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

#[cfg(test)]
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
        28 if rdlength == 16 => {
            let octets: [u8; 16] = message[rdata_start..rdata_end]
                .try_into()
                .map_err(|_| MdnsError::Malformed)?;
            MdnsRecord::Aaaa {
                owner,
                address: Ipv6Addr::from(octets),
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

        let matching_rules = rules.lookup_for_mdns(&q.name, q.qtype);
        for rule in matching_rules {
            match rule.record_type {
                RuleType::A => {
                    if (q.qtype == 1 || q.qtype == 255)
                        && let Some(IpAddr::V4(address)) = rule.address
                    {
                        let record = MdnsRecord::A {
                            owner: q.name.clone(),
                            address,
                            ttl: rule.ttl,
                        };
                        add_or_combine(&mut candidates, &mut seen_keys, record, rule, mode, query);
                    }
                }
                RuleType::Aaaa => {
                    if (q.qtype == 28 || q.qtype == 255)
                        && let Some(IpAddr::V6(address)) = rule.address
                    {
                        let record = MdnsRecord::Aaaa {
                            owner: q.name.clone(),
                            address,
                            ttl: rule.ttl,
                        };
                        add_or_combine(&mut candidates, &mut seen_keys, record, rule, mode, query);
                    }
                }
                RuleType::Cname => {
                    let target = rule.target.as_deref().expect("validated CNAME target");
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

                    if (q.qtype == 1 || q.qtype == 255)
                        && let Some(target_rule) = rules.lookup_exact_for_qtype(target, 1)
                        && target_rule.record_type == RuleType::A
                        && let Some(IpAddr::V4(address)) = target_rule.address
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

                    if (q.qtype == 28 || q.qtype == 255)
                        && let Some(target_rule) = rules.lookup_exact_for_qtype(target, 28)
                        && target_rule.record_type == RuleType::Aaaa
                        && let Some(IpAddr::V6(address)) = target_rule.address
                    {
                        let aaaa_record = MdnsRecord::Aaaa {
                            owner: target.to_owned(),
                            address,
                            ttl: target_rule.ttl,
                        };
                        add_or_combine(
                            &mut candidates,
                            &mut seen_keys,
                            aaaa_record,
                            target_rule,
                            mode,
                            query,
                        );
                    }
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

/// Partitions candidate native answers into QM (multicast) and QU (unicast)
/// buckets.
///
/// Under the host-only inbound injection model, synthesized responses are
/// routed back up the local host stack and never touch the physical network.
/// Per RFC 6762 §5.4, queriers requesting QU answers must also accept
/// multicast responses. Therefore, candidates with `DeliveryMode::Both` are
/// satisfied by multicast delivery alone (`qm_answers`) without generating
/// redundant duplicate unicast packets.
pub fn partition_native_answers<'a>(
    candidates: &'a [CandidateAnswer<'a>],
) -> (Vec<&'a CandidateAnswer<'a>>, Vec<&'a CandidateAnswer<'a>>) {
    let mut qm_answers = Vec::new();
    let mut qu_answers = Vec::new();

    for candidate in candidates {
        match candidate.delivery {
            DeliveryMode::QmOnly | DeliveryMode::Both => {
                qm_answers.push(candidate);
            }
            DeliveryMode::QuOnly => {
                qu_answers.push(candidate);
            }
            DeliveryMode::Legacy => {}
        }
    }

    (qm_answers, qu_answers)
}

pub fn dispatch_native_response(
    backend: &dyn InterceptionBackend,
    runtime: &RuntimeState,
    context: &FlowContext,
    tuple: FlowTuple,
    candidates: &[CandidateAnswer<'_>],
) {
    let (qm_items, qu_items) = partition_native_answers(candidates);

    if !qm_items.is_empty() {
        let records: Vec<&MdnsRecord> = qm_items.iter().map(|i| &i.record).collect();
        if let Ok(payload) = build_native_response(&records) {
            let multicast_dst = match tuple.source {
                IpAddr::V4(_) => IpAddr::V4(MDNS_IPV4_ADDR),
                IpAddr::V6(_) => IpAddr::V6(MDNS_IPV6_ADDR),
            };
            let resp_tuple = FlowTuple {
                source: tuple.source,
                source_port: 5353,
                destination: multicast_dst,
                destination_port: 5353,
            };
            if let Ok(packet) = build_udp(resp_tuple, &payload, 255)
                && backend.inject_raw_packet(context, &packet, false).is_ok()
            {
                let rules: Vec<&Rule> = qm_items
                    .iter()
                    .map(|i| i.contributing_rule)
                    .filter(|r| !r.is_builtin)
                    .collect();
                let has_builtin = qm_items.iter().any(|i| i.contributing_rule.is_builtin);
                runtime.record_synthesized(&rules, has_builtin);
                let response_names: Vec<&str> = qm_items.iter().map(|i| i.record.owner()).collect();
                tracing::debug!(
                    names = ?response_names,
                    "injected synchronous mDNS QM response packet"
                );
            }
        }
    }

    if !qu_items.is_empty() {
        let records: Vec<&MdnsRecord> = qu_items.iter().map(|i| &i.record).collect();
        if let Ok(payload) = build_native_response(&records) {
            let resp_tuple = FlowTuple {
                source: tuple.source,
                source_port: 5353,
                destination: tuple.source,
                destination_port: tuple.source_port,
            };
            if let Ok(packet) = build_udp(resp_tuple, &payload, 255)
                && backend.inject_raw_packet(context, &packet, false).is_ok()
            {
                let rules: Vec<&Rule> = qu_items
                    .iter()
                    .map(|i| i.contributing_rule)
                    .filter(|r| !r.is_builtin)
                    .collect();
                let has_builtin = qu_items.iter().any(|i| i.contributing_rule.is_builtin);
                runtime.record_synthesized(&rules, has_builtin);
                let response_names: Vec<&str> = qu_items.iter().map(|i| i.record.owner()).collect();
                tracing::debug!(
                    names = ?response_names,
                    "injected synchronous mDNS QU response packet"
                );
            }
        }
    }
}

pub fn dispatch_legacy_response(
    backend: &dyn InterceptionBackend,
    runtime: &RuntimeState,
    context: &FlowContext,
    tuple: FlowTuple,
    query: &MdnsQuery,
    candidates: &[CandidateAnswer<'_>],
) {
    if candidates.is_empty() {
        return;
    }
    let records: Vec<&MdnsRecord> = candidates.iter().map(|c| &c.record).collect();
    if let Ok(payload) = build_legacy_response(
        query.id,
        &query.raw_questions_section,
        query.questions.len() as u16,
        &records,
    ) {
        let resp_tuple = FlowTuple {
            source: tuple.source,
            source_port: 5353,
            destination: tuple.source,
            destination_port: tuple.source_port,
        };
        if let Ok(packet) = build_udp(resp_tuple, &payload, 255)
            && backend.inject_raw_packet(context, &packet, false).is_ok()
        {
            let rules: Vec<&Rule> = candidates
                .iter()
                .map(|c| c.contributing_rule)
                .filter(|r| !r.is_builtin)
                .collect();
            let has_builtin = candidates.iter().any(|c| c.contributing_rule.is_builtin);
            runtime.record_synthesized(&rules, has_builtin);
            let response_names: Vec<&str> = candidates.iter().map(|c| c.record.owner()).collect();
            tracing::debug!(
                names = ?response_names,
                "injected synchronous legacy mDNS response packet"
            );
        }
    }
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
        MdnsRecord::Aaaa { address, .. } => {
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
                record_type: Some(RuleType::A),
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
                    record_type: Some(RuleType::A),
                    address: Some("192.0.2.80".into()),
                    target: None,
                    ttl: Some(80),
                },
                RuleInput {
                    name: "*.example.local".into(),
                    record_type: Some(RuleType::Cname),
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
                    record_type: Some(RuleType::A),
                    address: Some("192.0.2.80".into()),
                    target: None,
                    ttl: Some(80),
                },
                RuleInput {
                    name: "*.example.local".into(),
                    record_type: Some(RuleType::Cname),
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
                record_type: Some(RuleType::A),
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
    fn answers_gui_name_and_loopback_per_rfc() {
        let rules_vec = crate::config::validate_rules(
            vec![
                RuleInput {
                    name: "dashboard.local".into(),
                    record_type: Some(RuleType::Cname),
                    address: None,
                    target: Some("dns-shunt.local".into()),
                    ttl: Some(30),
                },
                RuleInput {
                    name: "loopback.local".into(),
                    record_type: Some(RuleType::A),
                    address: Some("127.0.0.99".into()),
                    target: None,
                    ttl: Some(30),
                },
                RuleInput {
                    name: "lan.local".into(),
                    record_type: Some(RuleType::A),
                    address: Some("192.168.1.50".into()),
                    target: None,
                    ttl: Some(30),
                },
            ],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::with_builtin(rules_vec, "dns-shunt.local", 60);

        // QM query for gui_name (DeliveryMode::QmOnly)
        let wire_gui_qm = build_wire_query(0, &[("dns-shunt.local", 1, 1)], &[]);
        let query_gui_qm = parse_mdns_query(&wire_gui_qm, false).unwrap();
        let answers_gui_qm = resolve_mdns_query(&rules, &query_gui_qm);
        assert_eq!(answers_gui_qm.len(), 1);
        assert_eq!(answers_gui_qm[0].record.owner(), "dns-shunt.local");
        assert!(answers_gui_qm[0].contributing_rule.is_builtin);
        assert_eq!(answers_gui_qm[0].delivery, DeliveryMode::QmOnly);
        match &answers_gui_qm[0].record {
            MdnsRecord::A { address, ttl, .. } => {
                assert_eq!(*address, Ipv4Addr::LOCALHOST);
                assert_eq!(*ttl, 60);
            }
            _ => panic!("expected A record"),
        }

        // QU query for gui_name (DeliveryMode::QuOnly)
        let wire_gui_qu = build_wire_query(0, &[("dns-shunt.local", 1, 0x8001)], &[]);
        let query_gui_qu = parse_mdns_query(&wire_gui_qu, false).unwrap();
        let answers_gui_qu = resolve_mdns_query(&rules, &query_gui_qu);
        assert_eq!(answers_gui_qu.len(), 1);
        assert_eq!(answers_gui_qu[0].record.owner(), "dns-shunt.local");
        assert_eq!(answers_gui_qu[0].delivery, DeliveryMode::QuOnly);

        // QM query for user loopback rule (DeliveryMode::QmOnly)
        let wire_loopback_qm = build_wire_query(0, &[("loopback.local", 1, 1)], &[]);
        let query_loopback_qm = parse_mdns_query(&wire_loopback_qm, false).unwrap();
        let answers_loopback_qm = resolve_mdns_query(&rules, &query_loopback_qm);
        assert_eq!(answers_loopback_qm.len(), 1);
        assert_eq!(answers_loopback_qm[0].delivery, DeliveryMode::QmOnly);

        // QU query for user loopback rule (DeliveryMode::QuOnly)
        let wire_loopback_qu = build_wire_query(0, &[("loopback.local", 1, 0x8001)], &[]);
        let query_loopback_qu = parse_mdns_query(&wire_loopback_qu, false).unwrap();
        let answers_loopback_qu = resolve_mdns_query(&rules, &query_loopback_qu);
        assert_eq!(answers_loopback_qu.len(), 1);
        assert_eq!(answers_loopback_qu[0].delivery, DeliveryMode::QuOnly);

        // QM query for LAN rule (must be QmOnly for QM query)
        let wire_lan = build_wire_query(0, &[("lan.local", 1, 1)], &[]);
        let query_lan = parse_mdns_query(&wire_lan, false).unwrap();
        let answers_lan = resolve_mdns_query(&rules, &query_lan);
        assert_eq!(answers_lan.len(), 1);
        assert_eq!(answers_lan[0].delivery, DeliveryMode::QmOnly);

        // QM query for CNAME pointing to gui_name: both CNAME and target A are QmOnly
        let wire_cname_qm = build_wire_query(0, &[("dashboard.local", 1, 1)], &[]);
        let query_cname_qm = parse_mdns_query(&wire_cname_qm, false).unwrap();
        let answers_cname_qm = resolve_mdns_query(&rules, &query_cname_qm);
        assert_eq!(answers_cname_qm.len(), 2);
        assert_eq!(answers_cname_qm[0].record.owner(), "dashboard.local");
        assert_eq!(answers_cname_qm[0].delivery, DeliveryMode::QmOnly);
        assert!(!answers_cname_qm[0].contributing_rule.is_builtin);

        assert_eq!(answers_cname_qm[1].record.owner(), "dns-shunt.local");
        assert_eq!(answers_cname_qm[1].delivery, DeliveryMode::QmOnly);
        assert!(answers_cname_qm[1].contributing_rule.is_builtin);

        // QU query for CNAME pointing to gui_name: both CNAME and target A are QuOnly
        let wire_cname_qu = build_wire_query(0, &[("dashboard.local", 1, 0x8001)], &[]);
        let query_cname_qu = parse_mdns_query(&wire_cname_qu, false).unwrap();
        let answers_cname_qu = resolve_mdns_query(&rules, &query_cname_qu);
        assert_eq!(answers_cname_qu.len(), 2);
        assert_eq!(answers_cname_qu[0].record.owner(), "dashboard.local");
        assert_eq!(answers_cname_qu[0].delivery, DeliveryMode::QuOnly);
        assert!(!answers_cname_qu[0].contributing_rule.is_builtin);

        assert_eq!(answers_cname_qu[1].record.owner(), "dns-shunt.local");
        assert_eq!(answers_cname_qu[1].delivery, DeliveryMode::QuOnly);
        assert!(answers_cname_qu[1].contributing_rule.is_builtin);
    }

    #[test]
    fn partitions_native_answers_cleanly() {
        let rule = Rule {
            name: "example.local".into(),
            wildcard: false,
            record_type: RuleType::A,
            address: Some(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            target: None,
            ttl: 60,
            is_builtin: false,
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

        let (qm, qu) = partition_native_answers(&candidates);
        assert_eq!(qm.len(), 1);
        assert_eq!(qm[0].record.owner(), "example.local");
        assert_eq!(qm[0].delivery, DeliveryMode::Both);
        assert_eq!(qu.len(), 1);
        assert_eq!(qu[0].record.owner(), "alias.local");
    }

    #[test]
    fn encodes_and_parses_mdns_aaaa_record() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let record = MdnsRecord::Aaaa {
            owner: "ipv6.local".into(),
            address: addr,
            ttl: 120,
        };
        let records = vec![&record];
        let response_bytes = build_native_response(&records).unwrap();
        let parsed = parse_mdns_response(&response_bytes).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        match &parsed.answers[0] {
            MdnsRecord::Aaaa {
                owner,
                address,
                ttl,
            } => {
                assert_eq!(owner, "ipv6.local");
                assert_eq!(*address, addr);
                assert_eq!(*ttl, 120);
            }
            _ => panic!("expected AAAA record"),
        }
    }

    #[test]
    fn resolves_mdns_query_for_aaaa_rule() {
        let rules_vec = crate::config::validate_rules(
            vec![RuleInput {
                name: "host.local".into(),
                record_type: Some(RuleType::Aaaa),
                address: Some("2001:db8::1".into()),
                target: None,
                ttl: Some(60),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        let wire = build_wire_query(0, &[("host.local", 28, 1)], &[]);
        let query = parse_mdns_query(&wire, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].record.owner(), "host.local");
        match &answers[0].record {
            MdnsRecord::Aaaa { address, ttl, .. } => {
                assert_eq!(*address, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(*ttl, 60);
            }
            _ => panic!("expected AAAA record"),
        }

        // QTYPE 1 (A) query for AAAA-only rule produces no answers
        let wire_a = build_wire_query(0, &[("host.local", 1, 1)], &[]);
        let query_a = parse_mdns_query(&wire_a, false).unwrap();
        let answers_a = resolve_mdns_query(&rules, &query_a);
        assert!(answers_a.is_empty());
    }

    #[test]
    fn resolves_mdns_query_for_dual_stack_rule() {
        let rules_vec = crate::config::validate_rules(
            vec![
                RuleInput {
                    name: "dual.local".into(),
                    record_type: Some(RuleType::A),
                    address: Some("192.0.2.1".into()),
                    target: None,
                    ttl: Some(60),
                },
                RuleInput {
                    name: "dual.local".into(),
                    record_type: Some(RuleType::Aaaa),
                    address: Some("2001:db8::1".into()),
                    target: None,
                    ttl: Some(60),
                },
            ],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        // QTYPE 1 -> only A
        let wire_a = build_wire_query(0, &[("dual.local", 1, 1)], &[]);
        let query_a = parse_mdns_query(&wire_a, false).unwrap();
        let answers_a = resolve_mdns_query(&rules, &query_a);
        assert_eq!(answers_a.len(), 1);
        assert!(matches!(answers_a[0].record, MdnsRecord::A { .. }));

        // QTYPE 28 -> only AAAA
        let wire_aaaa = build_wire_query(0, &[("dual.local", 28, 1)], &[]);
        let query_aaaa = parse_mdns_query(&wire_aaaa, false).unwrap();
        let answers_aaaa = resolve_mdns_query(&rules, &query_aaaa);
        assert_eq!(answers_aaaa.len(), 1);
        assert!(matches!(answers_aaaa[0].record, MdnsRecord::Aaaa { .. }));

        // QTYPE 255 (ANY) -> both A and AAAA
        let wire_any = build_wire_query(0, &[("dual.local", 255, 1)], &[]);
        let query_any = parse_mdns_query(&wire_any, false).unwrap();
        let answers_any = resolve_mdns_query(&rules, &query_any);
        assert_eq!(answers_any.len(), 2);
        assert!(
            answers_any
                .iter()
                .any(|a| matches!(a.record, MdnsRecord::A { .. }))
        );
        assert!(
            answers_any
                .iter()
                .any(|a| matches!(a.record, MdnsRecord::Aaaa { .. }))
        );
    }

    #[test]
    fn resolves_mdns_gui_name_for_aaaa_and_any() {
        let rules = CompiledRules::with_builtin(vec![], "dns-shunt.local", 60);

        // QTYPE 28 (AAAA) for dns-shunt.local returns ::1
        let wire_aaaa = build_wire_query(0, &[("dns-shunt.local", 28, 1)], &[]);
        let query_aaaa = parse_mdns_query(&wire_aaaa, false).unwrap();
        let answers_aaaa = resolve_mdns_query(&rules, &query_aaaa);
        assert_eq!(answers_aaaa.len(), 1);
        assert_eq!(answers_aaaa[0].record.owner(), "dns-shunt.local");
        assert!(answers_aaaa[0].contributing_rule.is_builtin);
        match &answers_aaaa[0].record {
            MdnsRecord::Aaaa { address, ttl, .. } => {
                assert_eq!(*address, Ipv6Addr::LOCALHOST);
                assert_eq!(*ttl, 60);
            }
            _ => panic!("expected AAAA record"),
        }

        // QTYPE 255 (ANY) for dns-shunt.local returns both 127.0.0.1 and ::1
        let wire_any = build_wire_query(0, &[("dns-shunt.local", 255, 1)], &[]);
        let query_any = parse_mdns_query(&wire_any, false).unwrap();
        let answers_any = resolve_mdns_query(&rules, &query_any);
        assert_eq!(answers_any.len(), 2);
        assert!(answers_any.iter().all(|a| a.contributing_rule.is_builtin));
        assert!(
            answers_any
                .iter()
                .any(|a| matches!(a.record, MdnsRecord::A { .. }))
        );
        assert!(
            answers_any
                .iter()
                .any(|a| matches!(a.record, MdnsRecord::Aaaa { .. }))
        );
    }

    #[test]
    fn resolves_mdns_cname_to_aaaa_target() {
        let rules_vec = crate::config::validate_rules(
            vec![
                RuleInput {
                    name: "target.local".into(),
                    record_type: Some(RuleType::Aaaa),
                    address: Some("2001:db8::cafe".into()),
                    target: None,
                    ttl: Some(70),
                },
                RuleInput {
                    name: "alias.local".into(),
                    record_type: Some(RuleType::Cname),
                    address: None,
                    target: Some("target.local".into()),
                    ttl: Some(50),
                },
            ],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        // QTYPE 28 on alias.local emits CNAME and target AAAA
        let wire = build_wire_query(0, &[("alias.local", 28, 1)], &[]);
        let query = parse_mdns_query(&wire, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query);
        assert_eq!(answers.len(), 2);
        match &answers[0].record {
            MdnsRecord::Cname { owner, target, ttl } => {
                assert_eq!(owner, "alias.local");
                assert_eq!(target, "target.local");
                assert_eq!(*ttl, 50);
            }
            _ => panic!("expected CNAME record"),
        }
        match &answers[1].record {
            MdnsRecord::Aaaa {
                owner,
                address,
                ttl,
            } => {
                assert_eq!(owner, "target.local");
                assert_eq!(*address, "2001:db8::cafe".parse::<Ipv6Addr>().unwrap());
                assert_eq!(*ttl, 70);
            }
            _ => panic!("expected AAAA record"),
        }

        // QTYPE 255 on alias.local also emits CNAME and target AAAA
        let wire_any = build_wire_query(0, &[("alias.local", 255, 1)], &[]);
        let query_any = parse_mdns_query(&wire_any, false).unwrap();
        let answers_any = resolve_mdns_query(&rules, &query_any);
        assert_eq!(answers_any.len(), 2);
        assert!(matches!(answers_any[0].record, MdnsRecord::Cname { .. }));
        assert!(matches!(answers_any[1].record, MdnsRecord::Aaaa { .. }));
    }

    #[test]
    fn suppresses_mdns_aaaa_known_answer() {
        let rules_vec = crate::config::validate_rules(
            vec![RuleInput {
                name: "host.local".into(),
                record_type: Some(RuleType::Aaaa),
                address: Some("2001:db8::1".into()),
                target: None,
                ttl: Some(120),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules_vec);

        let addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let octets = addr.octets();

        // Known answer with TTL 60 (>= half emitted 120) suppresses answer
        let wire_suppressed = build_wire_query(
            0,
            &[("host.local", 28, 1)],
            &[("host.local", 28, 60, &octets)],
        );
        let query_suppressed = parse_mdns_query(&wire_suppressed, false).unwrap();
        let answers = resolve_mdns_query(&rules, &query_suppressed);
        assert!(answers.is_empty());

        // Known answer with TTL 59 (< half emitted 120) does NOT suppress
        let wire_emitted = build_wire_query(
            0,
            &[("host.local", 28, 1)],
            &[("host.local", 28, 59, &octets)],
        );
        let query_emitted = parse_mdns_query(&wire_emitted, false).unwrap();
        let answers_emitted = resolve_mdns_query(&rules, &query_emitted);
        assert_eq!(answers_emitted.len(), 1);
    }
}
