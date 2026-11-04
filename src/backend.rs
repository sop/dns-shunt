use crate::{
    admin::RuntimeState,
    config::{CompiledRules, Rule},
    dns,
    interfaces::InterfaceProvider,
    mdns,
    packet::FlowTuple,
};
use std::{any::Any, ops::Range, sync::Arc};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    UnicastDns,
    OutboundMdnsQuery,
    Other,
}

pub struct FlowContext {
    pub tuple: Option<FlowTuple>,
    pub original_packet: Vec<u8>,
    pub interface_index: u32,
    #[allow(dead_code)]
    pub outbound: bool,
    pub backend_context: Box<dyn Any + Send + Sync>,
}

pub struct CapturedPacket {
    pub context: FlowContext,
    pub dns_payload: Option<Range<usize>>,
    pub kind: PacketKind,
    pub ip_ttl: u8,
}

#[derive(Debug, Error)]
#[error("interception backend failed: {0}")]
pub struct BackendError(pub String);

pub trait InterceptionBackend: Send + Sync + 'static {
    fn capture(&self) -> Result<CapturedPacket, BackendError>;
    fn inject_response(
        &self,
        context: &FlowContext,
        dns_payload: &[u8],
    ) -> Result<(), BackendError>;
    fn reinject_original(&self, context: FlowContext) -> Result<(), BackendError>;
    fn forward_query(&self, _context: &FlowContext) -> Result<(), BackendError> {
        Err(BackendError("forward_query is not supported".into()))
    }
    fn inject_raw_packet(
        &self,
        _context: &FlowContext,
        _packet: &[u8],
        _outbound: bool,
    ) -> Result<(), BackendError> {
        Err(BackendError("inject_raw_packet is not supported".into()))
    }
    fn request_shutdown(&self) -> Result<(), BackendError> {
        Ok(())
    }
}

pub fn run_proxy(
    backend: Arc<dyn InterceptionBackend>,
    runtime: Arc<RuntimeState>,
    interfaces: Arc<dyn InterfaceProvider>,
    install_console_handler: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let weak_backend = Arc::downgrade(&backend);
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.set_stop_callback(Arc::new(move || {
        if let Some(backend) = weak_backend.upgrade()
            && let Err(error) = backend.request_shutdown()
            && let Some(runtime) = weak_runtime.upgrade()
        {
            runtime.record_error(error.to_string());
        }
    }));
    if runtime.is_stopping() {
        runtime.stop();
    }

    #[cfg(target_os = "windows")]
    if install_console_handler {
        let signal_runtime = Arc::clone(&runtime);
        ctrlc::set_handler(move || {
            signal_runtime.stop();
        })?;
    }

    if !runtime.is_stopping() {
        runtime.mark_ready();
    }

    while !runtime.is_stopping() {
        let captured = match backend.capture() {
            Ok(captured) => captured,
            Err(error) => {
                if runtime.is_stopping() {
                    break;
                }
                runtime.record_error(error.to_string());
                runtime.stop();
                return Err(Box::new(error));
            }
        };
        process_captured_packet(&*backend, &runtime, &*interfaces, captured);
    }

    Ok(())
}

fn process_captured_packet(
    backend: &dyn InterceptionBackend,
    runtime: &RuntimeState,
    interfaces: &dyn InterfaceProvider,
    captured: CapturedPacket,
) {
    match captured.kind {
        PacketKind::UnicastDns => {
            process_unicast_dns_packet(backend, runtime, captured);
        }
        PacketKind::OutboundMdnsQuery => {
            process_mdns_query_packet(backend, runtime, interfaces, captured);
        }
        PacketKind::Other => {
            reinject_or_log(backend, captured.context, runtime);
        }
    }
}

fn process_mdns_query_packet(
    backend: &dyn InterceptionBackend,
    runtime: &RuntimeState,
    interfaces: &dyn InterfaceProvider,
    captured: CapturedPacket,
) {
    let context = captured.context;
    let Some(payload_range) = captured.dns_payload else {
        fail_mdns_open(backend, &context, runtime, "invalid mDNS payload range");
        return;
    };
    let Some(payload) = context.original_packet.get(payload_range) else {
        fail_mdns_open(
            backend,
            &context,
            runtime,
            "mDNS payload range out of bounds",
        );
        return;
    };
    let Some(tuple) = context.tuple else {
        fail_mdns_open(backend, &context, runtime, "missing flow tuple");
        return;
    };

    if captured.ip_ttl == 0 {
        tracing::debug!(
            ip_ttl = captured.ip_ttl,
            "mDNS query passed through (zero TTL)"
        );
        forward_mdns_query(backend, &context, runtime);
        return;
    }

    if captured.ip_ttl != 255 {
        tracing::debug!(
            ip_ttl = captured.ip_ttl,
            "mDNS query has non-standard TTL"
        );
    }

    if !interfaces.has_unicast_source(context.interface_index, tuple.source) {
        tracing::debug!(
            if_index = context.interface_index,
            source = %tuple.source,
            "mDNS query passed through (non-local or non-unicast source)"
        );
        forward_mdns_query(backend, &context, runtime);
        return;
    }

    let is_legacy = tuple.source_port != 5353;
    if !is_legacy && (payload.len() < 2 || u16::from_be_bytes([payload[0], payload[1]]) != 0) {
        let id = if payload.len() >= 2 {
            u16::from_be_bytes([payload[0], payload[1]])
        } else {
            0
        };
        tracing::debug!(id, "mDNS query passed through (non-zero ID)");
        forward_mdns_query(backend, &context, runtime);
        return;
    }

    let parsed = match mdns::parse_mdns_questions(payload, is_legacy) {
        Ok(parsed) => parsed,
        Err(
            err @ (mdns::MdnsError::Truncated
            | mdns::MdnsError::Probe
            | mdns::MdnsError::Unsupported),
        ) => {
            tracing::debug!(reason = ?err, "mDNS query passed through (forwarded)");
            forward_mdns_query(backend, &context, runtime);
            return;
        }
        Err(error @ (mdns::MdnsError::Malformed | mdns::MdnsError::MalformedAt { .. })) => {
            fail_mdns_open(
                backend,
                &context,
                runtime,
                mdns_malformed_error(payload, "question section", &error),
            );
            return;
        }
    };

    let snapshot = runtime.rules.packet_snapshot();
    let may_match = parsed.questions.iter().any(|question| {
        question.qclass == 1
            && !snapshot
                .lookup_for_mdns(&question.name, question.qtype)
                .is_empty()
    });
    if !may_match {
        tracing::debug!(
            questions = ?parsed.questions,
            "mDNS query passed through (no matching local rules)"
        );
        forward_mdns_query(backend, &context, runtime);
        return;
    }

    let query = match mdns::parse_mdns_records(payload, parsed) {
        Ok(query) => query,
        Err(error @ (mdns::MdnsError::Malformed | mdns::MdnsError::MalformedAt { .. })) => {
            fail_mdns_open(
                backend,
                &context,
                runtime,
                mdns_malformed_error(payload, "answer/additional section", &error),
            );
            return;
        }
        Err(error) => {
            tracing::debug!(reason = ?error, "mDNS query passed through (forwarded)");
            forward_mdns_query(backend, &context, runtime);
            return;
        }
    };
    let candidates = mdns::resolve_mdns_query(&snapshot, &query);

    let all_matched = !query.questions.is_empty()
        && query.questions.iter().all(|q| {
            q.qclass == 1
                && candidates.iter().any(|c| {
                    c.record
                        .owner()
                        .eq_ignore_ascii_case(q.name.trim_end_matches('.'))
                        && match q.qtype {
                            1 => matches!(
                                c.record,
                                mdns::MdnsRecord::A { .. } | mdns::MdnsRecord::Cname { .. }
                            ),
                            28 => matches!(
                                c.record,
                                mdns::MdnsRecord::Aaaa { .. } | mdns::MdnsRecord::Cname { .. }
                            ),
                            5 => matches!(c.record, mdns::MdnsRecord::Cname { .. }),
                            255 => true,
                            _ => false,
                        }
                })
        });
    let none_matched = candidates.is_empty();

    if (!all_matched || none_matched) && !forward_mdns_query(backend, &context, runtime) {
        return;
    }

    if none_matched {
        tracing::debug!(
            questions = ?query.questions,
            "mDNS query passed through (no matching local rules)"
        );
        return;
    }

    tracing::debug!(
        questions = ?query.questions,
        candidates = candidates.len(),
        "mDNS query handled (immediate local response)"
    );

    if is_legacy {
        mdns::dispatch_legacy_response(backend, runtime, &context, tuple, &query, &candidates);
    } else {
        mdns::dispatch_native_response(backend, runtime, &context, tuple, &candidates);
    }
}

fn forward_mdns_query(
    backend: &dyn InterceptionBackend,
    context: &FlowContext,
    runtime: &RuntimeState,
) -> bool {
    match backend.forward_query(context) {
        Ok(()) => true,
        Err(first_error) => match backend.forward_query(context) {
            Ok(()) => {
                tracing::warn!(%first_error, "mDNS forwarding succeeded on retry");
                true
            }
            Err(retry_error) => {
                let error =
                    format!("mDNS forwarding failed: {first_error}; retry failed: {retry_error}");
                tracing::error!(%error, "mDNS packet could not be forwarded");
                runtime.record_error(error);
                runtime.record_fail_open();
                false
            }
        },
    }
}

fn fail_mdns_open(
    backend: &dyn InterceptionBackend,
    context: &FlowContext,
    runtime: &RuntimeState,
    error: impl Into<String>,
) {
    let error = error.into();
    tracing::warn!(%error, "mDNS fail-open triggered");
    runtime.record_error(error);
    runtime.record_fail_open();
    forward_mdns_query(backend, context, runtime);
}

fn mdns_malformed_error(payload: &[u8], section: &str, error: &mdns::MdnsError) -> String {
    let header = if payload.len() >= 12 {
        format!(
            ", id=0x{:04x}, qd={}, an={}, ns={}, ar={}",
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[4], payload[5]]),
            u16::from_be_bytes([payload[6], payload[7]]),
            u16::from_be_bytes([payload[8], payload[9]]),
            u16::from_be_bytes([payload[10], payload[11]])
        )
    } else {
        String::new()
    };

    format!(
        "mDNS query malformed in {section}: {error} (payload_len={} bytes{header})",
        payload.len()
    )
}

fn process_unicast_dns_packet(
    backend: &dyn InterceptionBackend,
    runtime: &RuntimeState,
    captured: CapturedPacket,
) {
    let context = captured.context;
    let Some(payload_range) = captured.dns_payload else {
        fail_open(
            backend,
            context,
            runtime,
            "captured packet is not a valid IPv4 UDP DNS query",
        );
        return;
    };
    let Some(payload) = context.original_packet.get(payload_range) else {
        fail_open(
            backend,
            context,
            runtime,
            "captured DNS payload range is outside the original packet",
        );
        return;
    };
    let question = match dns::classify_query(payload) {
        Ok(dns::QueryClassification::Eligible(question)) => question,
        Ok(dns::QueryClassification::UnsupportedQuestion) => {
            tracing::debug!("DNS query passed through (unsupported query type or class)");
            reinject_or_log(backend, context, runtime);
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "DNS query parsing failed, passed through");
            fail_open(
                backend,
                context,
                runtime,
                format!("DNS query parsing failed: {error}"),
            );
            return;
        }
    };
    let snapshot = runtime.rules.packet_snapshot();
    let Some(rule) = snapshot.lookup_for_qtype(&question.name, question.qtype) else {
        tracing::debug!(
            qname = %question.name,
            qtype = question.qtype,
            "DNS query passed through (no matching rule)"
        );
        reinject_or_log(backend, context, runtime);
        return;
    };
    if let Err(error) = dns::validate_query_sections(payload, &question) {
        tracing::warn!(%error, "matched DNS query sections are malformed");
        fail_open(
            backend,
            context,
            runtime,
            format!("DNS query section validation failed: {error}"),
        );
        return;
    }
    let (answers, contributing_rules, builtin_hit) = match rule.record_type {
        crate::config::RuleType::A => {
            if question.qtype != 1 {
                tracing::debug!(
                    qname = %question.name,
                    qtype = question.qtype,
                    "DNS query passed through (record type mismatch)"
                );
                reinject_or_log(backend, context, runtime);
                return;
            }
            let contributing_rules = if rule.is_builtin {
                Vec::new()
            } else {
                vec![rule]
            };
            let address = match rule.address {
                Some(std::net::IpAddr::V4(ipv4)) => ipv4,
                _ => {
                    fail_open(backend, context, runtime, "invalid A rule address");
                    return;
                }
            };
            (
                vec![dns::AnswerRecord::A {
                    owner: question.name.clone(),
                    address,
                    ttl: rule.ttl,
                }],
                contributing_rules,
                rule.is_builtin,
            )
        }
        crate::config::RuleType::Aaaa => {
            if question.qtype != 28 {
                tracing::debug!(
                    qname = %question.name,
                    qtype = question.qtype,
                    "DNS query passed through (record type mismatch)"
                );
                reinject_or_log(backend, context, runtime);
                return;
            }
            let contributing_rules = if rule.is_builtin {
                Vec::new()
            } else {
                vec![rule]
            };
            let address = match rule.address {
                Some(std::net::IpAddr::V6(ipv6)) => ipv6,
                _ => {
                    fail_open(backend, context, runtime, "invalid AAAA rule address");
                    return;
                }
            };
            (
                vec![dns::AnswerRecord::Aaaa {
                    owner: question.name.clone(),
                    address,
                    ttl: rule.ttl,
                }],
                contributing_rules,
                rule.is_builtin,
            )
        }
        crate::config::RuleType::Cname => {
            let resolution = if question.qtype == 5 {
                let contributing_rules = if rule.is_builtin {
                    Vec::new()
                } else {
                    vec![rule]
                };
                Ok((
                    vec![dns::AnswerRecord::Cname {
                        owner: question.name.clone(),
                        target: rule.target.clone().expect("validated CNAME target"),
                        ttl: rule.ttl,
                    }],
                    contributing_rules,
                    rule.is_builtin,
                ))
            } else {
                resolve_cname_chain(&snapshot, &question.name, question.qtype)
            };
            match resolution {
                Ok(resolution) => resolution,
                Err(()) => {
                    fail_open(
                        backend,
                        context,
                        runtime,
                        "local CNAME chain contains a loop",
                    );
                    return;
                }
            }
        }
    };
    let (response, answer_count) =
        match dns::build_response_with_count(payload, &question, &answers) {
            Ok(response) => response,
            Err(error) => {
                fail_open(
                    backend,
                    context,
                    runtime,
                    format!("DNS override response build failed: {error}"),
                );
                return;
            }
        };
    if let Err(error) = backend.inject_response(&context, &response) {
        fail_open(
            backend,
            context,
            runtime,
            format!("DNS override response injection failed: {error}"),
        );
        return;
    }
    tracing::debug!(
        qname = %question.name,
        qtype = question.qtype,
        answers = answer_count,
        "DNS query handled (injected override response)"
    );
    let retained_rules = &contributing_rules[..answer_count.min(contributing_rules.len())];
    runtime.record_synthesized(
        retained_rules,
        builtin_hit && answer_count > contributing_rules.len(),
    );
}

fn resolve_cname_chain<'a>(
    rules: &'a CompiledRules,
    query_name: &str,
    qtype: u16,
) -> Result<(Vec<dns::AnswerRecord>, Vec<&'a Rule>, bool), ()> {
    let mut answers = Vec::new();
    let mut contributing_rules = Vec::new();
    // `visited` is only needed once a CNAME hop is followed, so the common
    // single-answer path does not allocate it.
    let mut visited: Option<std::collections::HashSet<String>> = None;
    let mut current = query_name.to_owned();
    let mut cname_count = 0;
    let mut builtin_hit = false;

    while let Some(rule) = rules.lookup_for_qtype(&current, qtype) {
        match rule.record_type {
            crate::config::RuleType::A => {
                if qtype == 1
                    && let Some(std::net::IpAddr::V4(address)) = rule.address
                {
                    answers.push(dns::AnswerRecord::A {
                        owner: current,
                        address,
                        ttl: rule.ttl,
                    });
                    if rule.is_builtin {
                        builtin_hit = true;
                    } else {
                        contributing_rules.push(rule);
                    }
                }
                break;
            }
            crate::config::RuleType::Aaaa => {
                if qtype == 28
                    && let Some(std::net::IpAddr::V6(address)) = rule.address
                {
                    answers.push(dns::AnswerRecord::Aaaa {
                        owner: current,
                        address,
                        ttl: rule.ttl,
                    });
                    if rule.is_builtin {
                        builtin_hit = true;
                    } else {
                        contributing_rules.push(rule);
                    }
                }
                break;
            }
            crate::config::RuleType::Cname => {
                if cname_count == 16 {
                    break;
                }
                let target = rule.target.as_deref().expect("validated CNAME target");
                let seen = visited.get_or_insert_with(|| {
                    let mut set = std::collections::HashSet::new();
                    set.insert(query_name.to_owned());
                    set
                });
                if !seen.insert(target.to_owned()) {
                    return Err(());
                }
                answers.push(dns::AnswerRecord::Cname {
                    owner: current,
                    target: target.to_owned(),
                    ttl: rule.ttl,
                });
                if rule.is_builtin {
                    builtin_hit = true;
                } else {
                    contributing_rules.push(rule);
                }
                current = target.to_owned();
                cname_count += 1;
            }
        }
    }
    if answers.is_empty() {
        Err(())
    } else {
        Ok((answers, contributing_rules, builtin_hit))
    }
}

fn fail_open(
    backend: &dyn InterceptionBackend,
    context: FlowContext,
    runtime: &RuntimeState,
    error: impl Into<String>,
) {
    let error = error.into();
    tracing::warn!(%error, "fail-open triggered");
    runtime.record_error(error);
    runtime.record_fail_open();
    reinject_or_log(backend, context, runtime);
}

fn reinject_or_log(
    backend: &dyn InterceptionBackend,
    context: FlowContext,
    runtime: &RuntimeState,
) {
    if let Err(error) = backend.reinject_original(context) {
        tracing::error!(%error, "failed to reinject original packet");
        runtime.record_error(error.to_string());
        runtime.record_fail_open();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, RuleInput},
        packet::FlowTuple,
        rules::RuleManager,
    };
    use std::{
        env,
        net::{IpAddr, Ipv4Addr},
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct MockBackend {
        response_attempts: AtomicUsize,
        responses: Mutex<Vec<Vec<u8>>>,
        reinjections: Mutex<Vec<Option<Vec<u8>>>>,
        forwarded: Mutex<Vec<Vec<u8>>>,
        raw_injected: Mutex<Vec<(Vec<u8>, bool)>>,
        fail_response: AtomicBool,
        fail_forward: AtomicBool,
        fail_forward_once: AtomicBool,
        forward_attempts: AtomicUsize,
    }

    impl InterceptionBackend for MockBackend {
        fn capture(&self) -> Result<CapturedPacket, BackendError> {
            Err(BackendError("mock capture is unused".into()))
        }

        fn inject_response(
            &self,
            _context: &FlowContext,
            dns_payload: &[u8],
        ) -> Result<(), BackendError> {
            self.response_attempts.fetch_add(1, Ordering::Relaxed);
            if self.fail_response.load(Ordering::Relaxed) {
                return Err(BackendError("mock response injection failure".into()));
            }
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(dns_payload.to_vec());
            Ok(())
        }

        fn reinject_original(&self, context: FlowContext) -> Result<(), BackendError> {
            self.reinjections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(Some(context.original_packet));
            Ok(())
        }

        fn forward_query(&self, context: &FlowContext) -> Result<(), BackendError> {
            self.forward_attempts.fetch_add(1, Ordering::Relaxed);
            if self.fail_forward.load(Ordering::Relaxed)
                || self.fail_forward_once.swap(false, Ordering::Relaxed)
            {
                return Err(BackendError("mock forward failure".into()));
            }
            self.forwarded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(context.original_packet.clone());
            Ok(())
        }

        fn inject_raw_packet(
            &self,
            _context: &FlowContext,
            packet: &[u8],
            outbound: bool,
        ) -> Result<(), BackendError> {
            self.raw_injected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((packet.to_vec(), outbound));
            Ok(())
        }
    }

    fn process_captured_packet(
        backend: &dyn InterceptionBackend,
        _config: &Config,
        runtime: &RuntimeState,
        captured: CapturedPacket,
    ) {
        let interfaces = crate::interfaces::MockInterfaceProvider::new();
        super::process_captured_packet(backend, runtime, &interfaces, captured);
    }

    fn query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut payload = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        payload[..2].copy_from_slice(&id.to_be_bytes());
        for label in name.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&qclass.to_be_bytes());
        payload
    }

    fn query_with_edns(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut payload = query(id, name, qtype, 1);
        payload[11] = 1;
        payload.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        payload
    }

    fn test_tuple() -> FlowTuple {
        FlowTuple {
            source: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 53000,
            destination: std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
            destination_port: 53,
        }
    }

    fn wire_packet(payload: &[u8]) -> Vec<u8> {
        crate::packet::build_ipv4_udp(test_tuple(), payload).unwrap()
    }

    fn test_ipv6_tuple() -> FlowTuple {
        FlowTuple {
            source: std::net::IpAddr::V6("2001:db8::10".parse().unwrap()),
            source_port: 53000,
            destination: std::net::IpAddr::V6("2001:db8::53".parse().unwrap()),
            destination_port: 53,
        }
    }

    fn wire_ipv6_packet(payload: &[u8]) -> Vec<u8> {
        crate::packet::build_ipv6_udp(test_ipv6_tuple(), payload, 64).unwrap()
    }

    fn ipv6_packet(payload: Option<Vec<u8>>) -> CapturedPacket {
        let tuple = test_ipv6_tuple();
        let (original_packet, dns_payload) = match payload {
            Some(payload) => {
                let original_packet = wire_ipv6_packet(&payload);
                let parsed = crate::packet::parse_packet_range(&original_packet).unwrap();
                (original_packet, Some(parsed.payload_range))
            }
            None => (Vec::new(), None),
        };
        CapturedPacket {
            context: FlowContext {
                tuple: Some(tuple),
                original_packet,
                interface_index: 1,
                outbound: true,
                backend_context: Box::new(()),
            },
            dns_payload,
            kind: PacketKind::UnicastDns,
            ip_ttl: 64,
        }
    }

    fn packet(payload: Option<Vec<u8>>) -> CapturedPacket {
        let tuple = test_tuple();
        let (original_packet, dns_payload) = match payload {
            Some(payload) => {
                let original_packet = wire_packet(&payload);
                let (_, payload_range) =
                    crate::packet::parse_ipv4_udp_range(&original_packet).unwrap();
                (original_packet, Some(payload_range))
            }
            None => (Vec::new(), None),
        };
        CapturedPacket {
            context: FlowContext {
                tuple: Some(tuple),
                original_packet,
                interface_index: 1,
                outbound: true,
                backend_context: Box::new(()),
            },
            dns_payload,
            kind: PacketKind::UnicastDns,
            ip_ttl: 64,
        }
    }

    fn runtime() -> (Config, Arc<RuntimeState>) {
        let config = Config::parse("upstream = \"not-an-address\"\nsource_port = 53\n").unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir()
            .join(format!(
                "dns-shunt-backend-{nonce}-{}",
                TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ))
            .join("rules.json");
        let rules = RuleManager::load(path, config.gui_name.clone(), config.ttl).unwrap();
        rules
            .transact(|_| {
                Ok(vec![RuleInput {
                    name: "match.example".into(),
                    record_type: Some(crate::config::RuleType::A),
                    address: Some("192.0.2.44".into()),
                    target: None,
                    ttl: Some(90),
                }])
            })
            .unwrap();
        (
            config.clone(),
            RuntimeState::new(config, rules, "test").unwrap(),
        )
    }

    fn a_rule(name: &str, address: &str) -> RuleInput {
        RuleInput {
            name: name.into(),
            record_type: Some(crate::config::RuleType::A),
            address: Some(address.into()),
            target: None,
            ttl: Some(60),
        }
    }

    fn aaaa_rule(name: &str, address: &str) -> RuleInput {
        RuleInput {
            name: name.into(),
            record_type: Some(crate::config::RuleType::Aaaa),
            address: Some(address.into()),
            target: None,
            ttl: Some(60),
        }
    }

    fn cname_rule(name: &str, target: &str) -> RuleInput {
        RuleInput {
            name: name.into(),
            record_type: Some(crate::config::RuleType::Cname),
            address: None,
            target: Some(target.into()),
            ttl: Some(30),
        }
    }

    fn replace_rules(runtime: &RuntimeState, rules: Vec<RuleInput>) {
        runtime.rules.transact(|_| Ok(rules)).unwrap();
    }

    fn decode_name(message: &[u8], mut offset: usize) -> (String, usize) {
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

    fn answer_types(message: &[u8]) -> Vec<(String, u16, u32, Vec<u8>)> {
        let mut question_end = 12;
        loop {
            let length = message[question_end] as usize;
            question_end += 1;
            if length == 0 {
                break;
            }
            question_end += length;
        }
        question_end += 4;
        let count = u16::from_be_bytes([message[6], message[7]]) as usize;
        let mut offset = question_end;
        let mut records = Vec::new();
        for _ in 0..count {
            let (owner, next) = decode_name(message, offset);
            offset = next;
            let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
            let ttl = u32::from_be_bytes(message[offset + 4..offset + 8].try_into().unwrap());
            let data_len = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
            records.push((
                owner,
                rr_type,
                ttl,
                message[offset + 10..offset + 10 + data_len].to_vec(),
            ));
            offset += 10 + data_len;
        }
        records
    }

    #[test]
    fn matching_a_in_query_gets_override_and_only_override_metrics() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let original = query(0x1234, "match.example", 1, 1);
        process_captured_packet(&backend, &config, &runtime, packet(Some(original.clone())));

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0][..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([responses[0][6], responses[0][7]]), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records[0].0, "match.example");
        assert_eq!(records[0].3, [192, 0, 2, 44]);
        assert!(backend.reinjections.lock().unwrap().is_empty());
        let status = runtime.status();
        assert_eq!(status["overrides"], 1);
        assert_eq!(status["fail_open"], 0);
        assert!(status.get("forwarded").is_none());
    }

    #[test]
    fn nonmatches_and_unsupported_questions_are_reinjected_unchanged() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let packets = [
            query(1, "other.example", 1, 1),
            query(2, "match.example", 28, 1),
            query(3, "match.example", 1, 3),
        ];
        for original in &packets {
            process_captured_packet(&backend, &config, &runtime, packet(Some(original.clone())));
        }
        let reinjections = backend.reinjections.lock().unwrap();
        assert_eq!(
            *reinjections,
            packets
                .iter()
                .map(|payload| Some(wire_packet(payload)))
                .collect::<Vec<_>>()
        );
        assert!(backend.responses.lock().unwrap().is_empty());
        let status = runtime.status();
        assert_eq!(status["overrides"], 0);
        assert_eq!(status["fail_open"], 0);
        assert!(status.get("forwarded").is_none());
    }

    #[test]
    fn unmatched_supported_queries_skip_malformed_records_and_keep_packet_bytes() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let mut malformed = query(20, "other.example", 1, 1);
        malformed[11] = 1;
        malformed.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8]);
        let large_packet_payload = {
            let mut payload = query(21, "other.example", 1, 1);
            payload[10..12].copy_from_slice(&1u16.to_be_bytes());
            payload.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 2, 4, 0, 12, 2, 0]);
            payload.resize(payload.len() + 512, 0);
            payload
        };

        for payload in [&malformed, &large_packet_payload] {
            process_captured_packet(&backend, &config, &runtime, packet(Some(payload.clone())));
        }

        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![
                Some(wire_packet(&malformed)),
                Some(wire_packet(&large_packet_payload)),
            ]
        );
        assert!(backend.responses.lock().unwrap().is_empty());
        assert_eq!(runtime.status()["fail_open"], 0);
        assert_eq!(runtime.status()["errors"], 0);
    }

    #[test]
    fn malformed_dns_is_reinjected_unchanged_and_counted_as_fail_open() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let malformed = vec![1, 2, 3];
        process_captured_packet(&backend, &config, &runtime, packet(Some(malformed.clone())));
        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![Some(wire_packet(&malformed))]
        );
        assert_eq!(runtime.status()["overrides"], 0);
        assert_eq!(runtime.status()["fail_open"], 1);
    }

    #[test]
    fn unsupported_header_and_malformed_question_keep_fail_open_diagnostics() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let mut unsupported_header = query(8, "match.example", 1, 1);
        unsupported_header[2] |= 0x80;
        let mut malformed_question = query(9, "match.example", 28, 1);
        malformed_question[13] = b'!';

        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(unsupported_header.clone())),
        );
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(malformed_question.clone())),
        );

        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![
                Some(wire_packet(&unsupported_header)),
                Some(wire_packet(&malformed_question)),
            ]
        );
        assert_eq!(runtime.status()["fail_open"], 2);
        assert_eq!(runtime.status()["errors"], 2);
    }

    #[test]
    fn unsupported_question_bypasses_malformed_trailing_sections_without_metrics() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let mut unsupported = query(5, "match.example", 15, 1);
        unsupported[11] = 1;
        unsupported.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8]);

        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(unsupported.clone())),
        );

        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![Some(wire_packet(&unsupported))]
        );
        assert_eq!(runtime.status()["fail_open"], 0);
        assert_eq!(runtime.status()["errors"], 0);
        assert_eq!(runtime.status()["overrides"], 0);
    }

    #[test]
    fn malformed_trailing_sections_on_a_in_query_remain_fail_open() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let mut malformed = query(6, "match.example", 1, 1);
        malformed[11] = 1;
        malformed.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 8]);

        process_captured_packet(&backend, &config, &runtime, packet(Some(malformed.clone())));

        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![Some(wire_packet(&malformed))]
        );
        assert_eq!(runtime.status()["fail_open"], 1);
        assert_eq!(runtime.status()["errors"], 1);
        assert_eq!(runtime.status()["overrides"], 0);
    }

    #[test]
    fn invalid_dns_payload_range_fails_open_without_slicing_packet() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let mut captured = packet(Some(query(7, "match.example", 1, 1)));
        captured.dns_payload = Some(0..captured.context.original_packet.len() + 1);
        let original = captured.context.original_packet.clone();

        process_captured_packet(&backend, &config, &runtime, captured);

        assert_eq!(*backend.reinjections.lock().unwrap(), vec![Some(original)]);
        assert_eq!(runtime.status()["fail_open"], 1);
        assert_eq!(runtime.status()["errors"], 1);
    }

    #[test]
    fn response_injection_failure_reinjects_the_original_once() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        backend.fail_response.store(true, Ordering::Relaxed);
        let original = query(4, "match.example", 1, 1);
        process_captured_packet(&backend, &config, &runtime, packet(Some(original.clone())));
        assert_eq!(backend.response_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![Some(wire_packet(&original))]
        );
        assert_eq!(runtime.status()["overrides"], 0);
        assert_eq!(runtime.status()["fail_open"], 1);
        assert_eq!(runtime.status()["errors"], 1);
    }

    #[test]
    fn built_in_gui_name_precedes_user_rules_and_user_wildcards() {
        let rules = crate::config::validate_rules(
            vec![RuleInput {
                name: "*.dns-shunt.local".into(),
                record_type: Some(crate::config::RuleType::A),
                address: Some("192.0.2.9".into()),
                target: None,
                ttl: Some(60),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::with_builtin(rules, "dns-shunt.local", 60);
        let rule = rules.lookup_normalized("dns-shunt.local").unwrap();
        assert!(rule.is_builtin);
        let wildcard_match = rules.lookup_normalized("host.dns-shunt.local").unwrap();
        assert!(!wildcard_match.is_builtin);
        assert_eq!(
            wildcard_match.address,
            Some("192.0.2.9".parse::<std::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn wildcard_cname_and_terminal_a_are_returned_in_one_a_response() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                cname_rule("*.example.local", "example.local"),
                a_rule("example.local", "192.0.2.80"),
            ],
        );
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(1, "api.example.local", 1, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, "api.example.local");
        assert_eq!(records[0].1, 5);
        assert_eq!(records[0].2, 30);
        assert_eq!(decode_name(&records[0].3, 0).0, "example.local");
        assert_eq!(records[1].0, "example.local");
        assert_eq!(records[1].1, 1);
        assert_eq!(records[1].2, 60);
        assert_eq!(records[1].3, [192, 0, 2, 80]);
        let status = runtime.status();
        assert_eq!(status["overrides"], 1);
        assert_eq!(
            runtime.statistics_snapshot()["rule_hits"]["*.example.local"],
            1
        );
        assert_eq!(
            runtime.statistics_snapshot()["rule_hits"]["example.local"],
            1
        );
        assert!(backend.reinjections.lock().unwrap().is_empty());
    }

    #[test]
    fn cname_answers_support_aaaa_and_explicit_cname_queries() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                cname_rule("alias.example", "middle.example"),
                cname_rule("middle.example", "missing.example"),
            ],
        );
        let backend = MockBackend::default();
        for (id, qtype) in [(10, 28), (11, 5)] {
            process_captured_packet(
                &backend,
                &config,
                &runtime,
                packet(Some(query(id, "alias.example", qtype, 1))),
            );
        }
        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 2);
        let aaaa_records = answer_types(&responses[0]);
        assert_eq!(aaaa_records.len(), 2);
        assert_eq!(aaaa_records[0].0, "alias.example");
        assert_eq!(aaaa_records[0].1, 5);
        assert_eq!(decode_name(&aaaa_records[0].3, 0).0, "middle.example");
        assert_eq!(aaaa_records[1].0, "middle.example");
        assert_eq!(decode_name(&aaaa_records[1].3, 0).0, "missing.example");
        let cname_records = answer_types(&responses[1]);
        assert_eq!(cname_records.len(), 1);
        assert_eq!(cname_records[0].0, "alias.example");
        assert_eq!(cname_records[0].1, 5);
        assert_eq!(decode_name(&cname_records[0].3, 0).0, "middle.example");
        assert_eq!(runtime.status()["overrides"], 2);
        assert_eq!(
            runtime.statistics_snapshot()["rule_hits"]["alias.example"],
            2
        );
        assert_eq!(
            runtime.statistics_snapshot()["rule_hits"]["middle.example"],
            1
        );
    }

    #[test]
    fn a_query_to_unruled_cname_target_returns_only_the_local_chain() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![cname_rule("alias.example", "unruled.example")],
        );
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(19, "alias.example", 1, 1))),
        );
        let records = answer_types(&backend.responses.lock().unwrap()[0]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, 5);
        assert_eq!(decode_name(&records[0].3, 0).0, "unruled.example");
        assert_eq!(runtime.status()["overrides"], 1);
        assert!(backend.reinjections.lock().unwrap().is_empty());
    }

    #[test]
    fn exact_a_rule_shadows_wildcard_cname_even_for_aaaa() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                cname_rule("*.example.local", "outside.example.net"),
                a_rule("api.example.local", "192.0.2.81"),
            ],
        );
        let backend = MockBackend::default();
        let original = query(12, "api.example.local", 28, 1);
        process_captured_packet(&backend, &config, &runtime, packet(Some(original.clone())));
        assert!(backend.responses.lock().unwrap().is_empty());
        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            vec![Some(wire_packet(&original))]
        );
        assert_eq!(runtime.status()["overrides"], 0);
    }

    #[test]
    fn cname_chain_uses_builtin_gui_a_and_counts_each_contributor_once() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![cname_rule("alias.example", "dns-shunt.local")],
        );
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(13, "alias.example", 1, 1))),
        );
        let records = answer_types(&backend.responses.lock().unwrap()[0]);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].0, "dns-shunt.local");
        assert_eq!(records[1].3, [127, 0, 0, 1]);
        assert_eq!(runtime.status()["overrides"], 1);
        assert_eq!(runtime.status()["builtin_hits"], 1);
        assert_eq!(
            runtime.statistics_snapshot()["rule_hits"]["alias.example"],
            1
        );
    }

    #[test]
    fn a_rules_only_answer_a_and_unmatched_cname_queries_fail_open() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        let packets = [
            query(14, "match.example", 28, 1),
            query(15, "missing.example", 5, 1),
            query(16, "match.example", 15, 1),
        ];
        for original in &packets {
            process_captured_packet(&backend, &config, &runtime, packet(Some(original.clone())));
        }
        assert!(backend.responses.lock().unwrap().is_empty());
        assert_eq!(
            *backend.reinjections.lock().unwrap(),
            packets
                .iter()
                .map(|payload| Some(wire_packet(payload)))
                .collect::<Vec<_>>()
        );
        assert_eq!(runtime.status()["overrides"], 0);
    }

    #[test]
    fn cname_chain_stops_at_sixteen_records_and_keeps_terminal_a() {
        let (config, runtime) = runtime();
        let mut rules = (0..16)
            .map(|index| {
                cname_rule(
                    &format!("host{index}.chain.example"),
                    &format!("host{}.chain.example", index + 1),
                )
            })
            .collect::<Vec<_>>();
        rules.push(a_rule("host16.chain.example", "192.0.2.82"));
        replace_rules(&runtime, rules);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query_with_edns(17, "host0.chain.example", 1))),
        );
        let records = answer_types(&backend.responses.lock().unwrap()[0]);
        assert_eq!(records.len(), 17);
        assert!(records[..16].iter().all(|record| record.1 == 5));
        assert_eq!(records[16].1, 1);
    }

    #[test]
    fn seventeenth_cname_is_omitted_as_a_valid_prefix() {
        let (config, runtime) = runtime();
        let rules = (0..17)
            .map(|index| {
                cname_rule(
                    &format!("node{index}.chain.example"),
                    &format!("node{}.chain.example", index + 1),
                )
            })
            .collect();
        replace_rules(&runtime, rules);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query_with_edns(18, "node0.chain.example", 28))),
        );
        let records = answer_types(&backend.responses.lock().unwrap()[0]);
        assert_eq!(records.len(), 16);
        assert!(records.iter().all(|record| record.1 == 5));
    }

    fn mdns_packet(
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        payload: Vec<u8>,
        ip_ttl: u8,
        outbound: bool,
    ) -> CapturedPacket {
        let tuple = FlowTuple {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port,
            destination: destination_ip,
            destination_port,
        };
        let original_packet =
            crate::packet::build_ipv4_udp_with_ttl(tuple, &payload, ip_ttl).unwrap();
        let payload_range = 28..original_packet.len();
        let kind = if outbound {
            if destination_port == 5353 {
                PacketKind::OutboundMdnsQuery
            } else {
                PacketKind::UnicastDns
            }
        } else {
            PacketKind::Other
        };
        CapturedPacket {
            context: FlowContext {
                tuple: Some(tuple),
                original_packet,
                interface_index: 1,
                outbound,
                backend_context: Box::new(()),
            },
            dns_payload: Some(payload_range),
            kind,
            ip_ttl,
        }
    }

    fn mdns_ipv6_packet(
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        payload: Vec<u8>,
        ip_ttl: u8,
        outbound: bool,
    ) -> CapturedPacket {
        let tuple = FlowTuple {
            source: IpAddr::V6("2001:db8::10".parse().unwrap()),
            source_port,
            destination: destination_ip,
            destination_port,
        };
        let original_packet = crate::packet::build_ipv6_udp(tuple, &payload, ip_ttl).unwrap();
        let payload_range = 48..original_packet.len();
        let kind = if outbound {
            if destination_port == 5353 {
                PacketKind::OutboundMdnsQuery
            } else {
                PacketKind::UnicastDns
            }
        } else {
            PacketKind::Other
        };
        CapturedPacket {
            context: FlowContext {
                tuple: Some(tuple),
                original_packet,
                interface_index: 1,
                outbound,
                backend_context: Box::new(()),
            },
            dns_payload: Some(payload_range),
            kind,
            ip_ttl,
        }
    }

    fn multi_query(id: u16, questions: &[(&str, u16, u16)]) -> Vec<u8> {
        let mut payload = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        payload[..2].copy_from_slice(&id.to_be_bytes());
        payload[4..6].copy_from_slice(&(questions.len() as u16).to_be_bytes());
        for (name, qtype, qclass) in questions {
            for label in name.split('.') {
                payload.push(label.len() as u8);
                payload.extend_from_slice(label.as_bytes());
            }
            payload.push(0);
            payload.extend_from_slice(&qtype.to_be_bytes());
            payload.extend_from_slice(&qclass.to_be_bytes());
        }
        payload
    }

    fn run_mdns_test<F>(test_fn: F)
    where
        F: FnOnce(&dyn InterfaceProvider),
    {
        let interfaces = crate::interfaces::MockInterfaceProvider::new();
        let mut if_data = crate::interfaces::InterfaceData::default();
        if_data
            .unicast_addresses
            .push(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        if_data
            .unicast_addresses
            .push(IpAddr::V6("2001:db8::10".parse().unwrap()));
        interfaces.add_interface(1, if_data);

        test_fn(&interfaces);
    }

    #[test]
    fn mdns_query_forwarded_and_answered_with_cname_and_target_a() {
        let (_config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                cname_rule("*.example.local", "example.local"),
                a_rule("example.local", "192.0.2.80"),
            ],
        );
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "test.example.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);

            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(!raw[0].1); // inbound QM
            let (tuple, resp_payload) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.destination, IpAddr::V4(mdns::MDNS_IPV4_ADDR));
            assert_eq!(tuple.destination_port, 5353);

            let info = mdns::parse_mdns_response(resp_payload).unwrap();
            assert_eq!(info.id, 0);
            assert_eq!(info.answers.len(), 2);
            assert_eq!(info.answers[0].owner(), "test.example.local");
            assert_eq!(info.answers[1].owner(), "example.local");

            assert_eq!(runtime.status()["overrides"], 1);
            let hits = runtime.statistics_snapshot()["rule_hits"].clone();
            assert_eq!(hits["*.example.local"], 1);
            assert_eq!(hits["example.local"], 1);
        });
    }

    #[test]
    fn mdns_gui_name_is_answered() {
        let (_config, runtime) = runtime();
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "dns-shunt.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            let (tuple, _) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.destination, IpAddr::V4(mdns::MDNS_IPV4_ADDR));
            assert_eq!(tuple.destination_port, 5353);
            assert!(!raw[0].1); // Inbound QM multicast
            assert_eq!(runtime.status()["overrides"], 1);
            assert_eq!(runtime.status()["builtin_hits"], 1);
        });
    }

    #[test]
    fn mdns_cname_to_gui_name_is_answered_via_multicast_for_qm_query() {
        let (_config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![cname_rule("dashboard.local", "dns-shunt.local")],
        );
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "dashboard.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            let (tuple, resp_payload) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.destination, IpAddr::V4(mdns::MDNS_IPV4_ADDR));
            assert_eq!(tuple.destination_port, 5353);
            assert!(!raw[0].1); // Inbound QM multicast

            let info = mdns::parse_mdns_response(resp_payload).unwrap();
            assert_eq!(info.answers.len(), 2);
            assert_eq!(info.answers[0].owner(), "dashboard.local");
            assert_eq!(info.answers[1].owner(), "dns-shunt.local");

            assert_eq!(runtime.status()["overrides"], 1);
            assert_eq!(runtime.status()["builtin_hits"], 1);
            let hits = runtime.statistics_snapshot()["rule_hits"].clone();
            assert_eq!(hits["dashboard.local"], 1);
        });
    }

    #[test]
    fn mdns_gui_name_is_answered_via_unicast_when_qu_requested() {
        let (_config, runtime) = runtime();
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "dns-shunt.local", 1, 0x8001);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            let (tuple, _) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
            assert_eq!(tuple.destination_port, 5353);
            assert!(!raw[0].1); // Inbound QU unicast
            assert_eq!(runtime.status()["overrides"], 1);
            assert_eq!(runtime.status()["builtin_hits"], 1);
        });
    }

    #[test]
    fn mdns_multi_question_different_delivery_modes() {
        let (_config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                a_rule("matched1.local", "192.0.2.101"),
                a_rule("matched2.local", "192.0.2.102"),
            ],
        );
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let q_bytes = multi_query(
                0,
                &[
                    ("matched1.local", 1, 1),      // QM
                    ("matched2.local", 1, 0x8001), // QU
                ],
            );
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 2);

            // First packet: QM response to multicast address
            let (tuple_qm, payload_qm) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple_qm.destination, IpAddr::V4(mdns::MDNS_IPV4_ADDR));
            assert_eq!(tuple_qm.destination_port, 5353);
            assert!(!raw[0].1);
            let info_qm = mdns::parse_mdns_response(payload_qm).unwrap();
            assert_eq!(info_qm.answers.len(), 1);
            assert_eq!(info_qm.answers[0].owner(), "matched1.local");

            // Second packet: QU response to unicast address
            let (tuple_qu, payload_qu) = crate::packet::parse_ipv4_udp(&raw[1].0).unwrap();
            assert_eq!(
                tuple_qu.destination,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
            );
            assert_eq!(tuple_qu.destination_port, 5353);
            assert!(!raw[1].1);
            let info_qu = mdns::parse_mdns_response(payload_qu).unwrap();
            assert_eq!(info_qu.answers.len(), 1);
            assert_eq!(info_qu.answers[0].owner(), "matched2.local");

            // Statistics check: 2 overrides (1 QM + 1 QU), each rule hit once
            assert_eq!(runtime.status()["overrides"], 2);
            assert_eq!(runtime.status()["builtin_hits"], 0);
            let hits = runtime.statistics_snapshot()["rule_hits"].clone();
            assert_eq!(hits["matched1.local"], 1);
            assert_eq!(hits["matched2.local"], 1);
        });
    }

    #[test]
    fn mdns_zero_ttl_is_only_forwarded() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("example.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "example.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            // TTL is 0
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                0,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 1);
            assert_eq!(backend.raw_injected.lock().unwrap().len(), 0);
        });
    }

    #[test]
    fn mdns_non_255_ttl_is_accepted_leniently() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("example.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "example.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            // TTL is 64 (non-standard but non-zero, accepted leniently)
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                64,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            assert_eq!(backend.raw_injected.lock().unwrap().len(), 1);
            assert!(!backend.raw_injected.lock().unwrap()[0].1);
            assert_eq!(runtime.status()["overrides"], 1);
        });
    }

    #[test]
    fn mdns_legacy_query_echoes_id_and_questions() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("example.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0x4321, "example.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                54321,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);

            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(!raw[0].1); // inbound unicast
            let (tuple, resp_payload) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
            assert_eq!(tuple.destination_port, 54321);

            let info = mdns::parse_mdns_response(resp_payload).unwrap();
            assert_eq!(info.id, 0x4321);
            assert_eq!(info.answers.len(), 1);
            assert!(info.answers[0].ttl() <= 10);
            assert_eq!(runtime.status()["overrides"], 1);
        });
    }

    #[test]
    fn mdns_matched_query_is_not_forwarded() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("matched.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "matched.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(!raw[0].1); // outbound == false
            assert_eq!(runtime.status()["overrides"], 1);
        });
    }

    #[test]
    fn mdns_unmatched_query_is_forwarded() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("other.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "unmatched.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 1);
            assert_eq!(backend.raw_injected.lock().unwrap().len(), 0);
            assert_eq!(runtime.status()["overrides"], 0);
        });
    }

    #[test]
    fn mdns_unmatched_malformed_records_are_forwarded_without_fail_open_metrics() {
        let (_config, runtime) = runtime();
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut payload = multi_query(0, &[("unmatched.local", 1, 1)]);
            payload[6..8].copy_from_slice(&1u16.to_be_bytes());
            payload.push(0xc0);
            let captured = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                payload,
                255,
                true,
            );
            let original = captured.context.original_packet.clone();
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, captured);

            assert_eq!(*backend.forwarded.lock().unwrap(), vec![original]);
            assert!(backend.reinjections.lock().unwrap().is_empty());
            assert_eq!(runtime.status()["fail_open"], 0);
            assert_eq!(runtime.status()["errors"], 0);
        });
    }

    #[test]
    fn mdns_early_forwarding_branches_retry_without_unicast_reinjection() {
        let nonzero_id = multi_query(1, &[("unmatched.local", 1, 1)]);
        let mut truncated = multi_query(0, &[("unmatched.local", 1, 1)]);
        truncated[2] |= 0x02;
        let mut malformed_records = multi_query(0, &[("unmatched.local", 1, 1)]);
        malformed_records[6..8].copy_from_slice(&1u16.to_be_bytes());
        malformed_records.push(0xc0);

        let packets = vec![
            mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                multi_query(0, &[("matched.local", 1, 1)]),
                0,
                true,
            ),
            mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                nonzero_id,
                255,
                true,
            ),
            mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                truncated,
                255,
                true,
            ),
            mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                malformed_records,
                255,
                true,
            ),
        ];

        run_mdns_test(|interfaces| {
            for captured in packets {
                let (_config, runtime) = runtime();
                let backend = MockBackend::default();
                backend.fail_forward_once.store(true, Ordering::Relaxed);
                let original = captured.context.original_packet.clone();
                super::process_captured_packet(&backend, &runtime, interfaces, captured);

                assert_eq!(backend.forward_attempts.load(Ordering::Relaxed), 2);
                assert_eq!(*backend.forwarded.lock().unwrap(), vec![original]);
                assert!(backend.reinjections.lock().unwrap().is_empty());
                assert_eq!(runtime.status()["fail_open"], 0);
                assert_eq!(runtime.status()["errors"], 0);
            }
        });

        let (_config, runtime) = runtime();
        let backend = MockBackend::default();
        backend.fail_forward_once.store(true, Ordering::Relaxed);
        let interfaces = crate::interfaces::MockInterfaceProvider::new();
        let captured = mdns_packet(
            5353,
            IpAddr::V4(mdns::MDNS_IPV4_ADDR),
            5353,
            multi_query(0, &[("unmatched.local", 1, 1)]),
            255,
            true,
        );
        let original = captured.context.original_packet.clone();
        super::process_captured_packet(&backend, &runtime, &interfaces, captured);
        assert_eq!(backend.forward_attempts.load(Ordering::Relaxed), 2);
        assert_eq!(*backend.forwarded.lock().unwrap(), vec![original]);
        assert!(backend.reinjections.lock().unwrap().is_empty());
        assert_eq!(runtime.status()["errors"], 0);
    }

    #[test]
    fn terminal_mdns_forwarding_failure_is_reported_without_reinjection() {
        let (_config, runtime) = runtime();
        let backend = MockBackend::default();
        backend.fail_forward.store(true, Ordering::Relaxed);
        run_mdns_test(|interfaces| {
            let captured = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                multi_query(0, &[("unmatched.local", 1, 1)]),
                0,
                true,
            );
            super::process_captured_packet(&backend, &runtime, interfaces, captured);
        });

        assert_eq!(backend.forward_attempts.load(Ordering::Relaxed), 2);
        assert!(backend.forwarded.lock().unwrap().is_empty());
        assert!(backend.reinjections.lock().unwrap().is_empty());
        assert_eq!(runtime.status()["fail_open"], 1);
        assert_eq!(runtime.status()["errors"], 1);
    }

    #[test]
    fn mdns_mixed_multi_question_query_is_forwarded_and_answered() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("matched.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let q_bytes = multi_query(0, &[("matched.local", 1, 1), ("unmatched.local", 1, 1)]);
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 1);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(!raw[0].1); // outbound == false

            let (_, resp_payload) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            let info = mdns::parse_mdns_response(resp_payload).unwrap();
            assert_eq!(info.answers.len(), 1);
            assert_eq!(info.answers[0].owner(), "matched.local");
            assert_eq!(runtime.status()["overrides"], 1);
        });
    }

    #[test]
    fn mdns_response_timing_immediate() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("fast.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "fast.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            // No sleep needed - response is immediate
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
        });
    }

    #[test]
    fn mdns_non_loopback_multicast_injected_inbound() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("lan.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "lan.local", 1, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(!raw[0].1); // outbound must be false!
            let (tuple, _) = crate::packet::parse_ipv4_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.destination, IpAddr::V4(mdns::MDNS_IPV4_ADDR));
            assert_eq!(tuple.destination_port, 5353);
        });
    }

    #[test]
    fn mdns_ipv6_query_packet_handled_and_injected() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![aaaa_rule("matched.local", "2001:db8::80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "matched.local", 28, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_ipv6_packet(
                5353,
                IpAddr::V6(mdns::MDNS_IPV6_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 0);
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(!raw[0].1); // outbound == false

            // Verify injected packet has IPv6 flow tuple and valid UDP checksum
            let (tuple, resp_payload) = crate::packet::parse_ipv6_udp(&raw[0].0).unwrap();
            assert_eq!(tuple.source, "2001:db8::10".parse::<IpAddr>().unwrap());
            assert_eq!(tuple.destination, IpAddr::V6(mdns::MDNS_IPV6_ADDR));
            assert_eq!(tuple.source_port, 5353);
            assert_eq!(tuple.destination_port, 5353);

            let resp_info = mdns::parse_mdns_response(resp_payload).unwrap();
            assert_eq!(resp_info.answers.len(), 1);
            assert_eq!(resp_info.answers[0].owner(), "matched.local");
            assert!(matches!(
                resp_info.answers[0],
                mdns::MdnsRecord::Aaaa { .. }
            ));
        });
    }

    #[test]
    fn mdns_query_with_unanswered_aaaa_is_forwarded() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("foo.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            // Multi-question query: foo.local A (answered) and bar.local AAAA (unanswered)
            let q_bytes = multi_query(0, &[("foo.local", 1, 1), ("bar.local", 28, 1)]);
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            // Because bar.local AAAA was not answered, the query packet must be forwarded
            assert_eq!(backend.forwarded.lock().unwrap().len(), 1);

            // Because foo.local A was answered, local answer is also injected
            let raw = backend.raw_injected.lock().unwrap();
            assert_eq!(raw.len(), 1);
            assert_eq!(runtime.status()["overrides"], 1);
        });
    }

    #[test]
    fn mdns_query_for_aaaa_on_a_only_domain_is_forwarded_without_injection() {
        let (_config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("foo.local", "192.0.2.80")]);
        let backend = Arc::new(MockBackend::default());
        run_mdns_test(|interfaces| {
            let mut q_bytes = query(0, "foo.local", 28, 1);
            q_bytes[2] = 0;
            q_bytes[3] = 0;
            let pkt = mdns_packet(
                5353,
                IpAddr::V4(mdns::MDNS_IPV4_ADDR),
                5353,
                q_bytes,
                255,
                true,
            );
            super::process_captured_packet(backend.as_ref(), &runtime, interfaces, pkt);

            assert_eq!(backend.forwarded.lock().unwrap().len(), 1);
            assert_eq!(backend.raw_injected.lock().unwrap().len(), 0);
        });
    }

    #[test]
    fn size_limited_prefix_counts_only_rules_in_retained_records() {
        let (config, runtime) = runtime();
        let long_target = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(55)
        );
        replace_rules(
            &runtime,
            vec![
                cname_rule("alias.example", &long_target),
                a_rule(&long_target, "192.0.2.83"),
            ],
        );
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(20, "alias.example", 1, 1))),
        );
        let response = backend.responses.lock().unwrap()[0].clone();
        let records = answer_types(&response);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, 5);
        assert!(response.len() <= 512);
        let hits = runtime.statistics_snapshot()["rule_hits"].clone();
        assert_eq!(hits["alias.example"], 1);
        assert!(hits.get(&long_target).is_none());
        assert_eq!(runtime.status()["overrides"], 1);
    }

    #[test]
    fn aaaa_query_over_ipv4_transport_matching_aaaa_rule() {
        let (config, runtime) = runtime();
        replace_rules(&runtime, vec![aaaa_rule("test.example", "2001:db8::1234")]);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(1, "test.example", 28, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "test.example");
        assert_eq!(records[0].1, 28);
        assert_eq!(records[0].2, 60);
        let expected_addr: std::net::Ipv6Addr = "2001:db8::1234".parse().unwrap();
        assert_eq!(records[0].3, expected_addr.octets());
    }

    #[test]
    fn a_query_over_ipv6_transport_matching_a_rule() {
        let (config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("test.example", "192.0.2.1")]);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            ipv6_packet(Some(query(2, "test.example", 1, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "test.example");
        assert_eq!(records[0].1, 1);
        assert_eq!(records[0].2, 60);
        assert_eq!(records[0].3, [192, 0, 2, 1]);
    }

    #[test]
    fn aaaa_query_over_ipv6_transport_matching_aaaa_rule() {
        let (config, runtime) = runtime();
        replace_rules(&runtime, vec![aaaa_rule("test.example", "2001:db8::abcd")]);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            ipv6_packet(Some(query(3, "test.example", 28, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "test.example");
        assert_eq!(records[0].1, 28);
        let expected_addr: std::net::Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        assert_eq!(records[0].3, expected_addr.octets());
    }

    #[test]
    fn aaaa_query_to_domain_with_only_a_rule_fails_open() {
        let (config, runtime) = runtime();
        replace_rules(&runtime, vec![a_rule("v4only.example", "192.0.2.1")]);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(4, "v4only.example", 28, 1))),
        );

        assert!(backend.responses.lock().unwrap().is_empty());
        assert_eq!(backend.reinjections.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_query_to_domain_with_only_aaaa_rule_fails_open() {
        let (config, runtime) = runtime();
        replace_rules(&runtime, vec![aaaa_rule("v6only.example", "2001:db8::1")]);
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(5, "v6only.example", 1, 1))),
        );

        assert!(backend.responses.lock().unwrap().is_empty());
        assert_eq!(backend.reinjections.lock().unwrap().len(), 1);
    }

    #[test]
    fn domain_with_both_a_and_aaaa_rules_answers_respective_records() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                a_rule("dual.example", "192.0.2.1"),
                aaaa_rule("dual.example", "2001:db8::1"),
            ],
        );
        let backend = MockBackend::default();

        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(6, "dual.example", 1, 1))),
        );
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(7, "dual.example", 28, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 2);

        let a_records = answer_types(&responses[0]);
        assert_eq!(a_records[0].1, 1);
        assert_eq!(a_records[0].3, [192, 0, 2, 1]);

        let aaaa_records = answer_types(&responses[1]);
        assert_eq!(aaaa_records[0].1, 28);
        let expected_addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(aaaa_records[0].3, expected_addr.octets());
    }

    #[test]
    fn cname_chain_resolving_to_terminal_aaaa_for_aaaa_query() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                cname_rule("alias.example", "target.example"),
                aaaa_rule("target.example", "2001:db8::99"),
            ],
        );
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(8, "alias.example", 28, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, "alias.example");
        assert_eq!(records[0].1, 5);
        assert_eq!(records[1].0, "target.example");
        assert_eq!(records[1].1, 28);
        let expected_addr: std::net::Ipv6Addr = "2001:db8::99".parse().unwrap();
        assert_eq!(records[1].3, expected_addr.octets());
    }

    #[test]
    fn cname_chain_returns_cname_only_when_terminal_record_family_does_not_match() {
        let (config, runtime) = runtime();
        replace_rules(
            &runtime,
            vec![
                cname_rule("alias.example", "target.example"),
                a_rule("target.example", "192.0.2.88"),
            ],
        );
        let backend = MockBackend::default();
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(9, "alias.example", 28, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 1);
        let records = answer_types(&responses[0]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "alias.example");
        assert_eq!(records[0].1, 5);
    }

    #[test]
    fn gui_name_answers_both_a_and_aaaa() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();

        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(10, "dns-shunt.local", 1, 1))),
        );
        process_captured_packet(
            &backend,
            &config,
            &runtime,
            packet(Some(query(11, "dns-shunt.local", 28, 1))),
        );

        let responses = backend.responses.lock().unwrap();
        assert_eq!(responses.len(), 2);

        let a_records = answer_types(&responses[0]);
        assert_eq!(a_records.len(), 1);
        assert_eq!(a_records[0].1, 1);
        assert_eq!(a_records[0].3, [127, 0, 0, 1]);

        let aaaa_records = answer_types(&responses[1]);
        assert_eq!(aaaa_records.len(), 1);
        assert_eq!(aaaa_records[0].1, 28);
        assert_eq!(aaaa_records[0].3, std::net::Ipv6Addr::LOCALHOST.octets());
    }
}
