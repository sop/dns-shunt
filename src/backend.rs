use crate::{
    admin::RuntimeState,
    config::{CompiledRules, Config, Rule},
    dns,
    packet::FlowTuple,
};
use std::{any::Any, ops::Range, sync::Arc};
use thiserror::Error;

pub struct FlowContext {
    pub tuple: Option<FlowTuple>,
    pub original_packet: Vec<u8>,
    pub backend_context: Box<dyn Any + Send + Sync>,
}

pub struct CapturedPacket {
    pub context: FlowContext,
    pub dns_payload: Option<Range<usize>>,
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
    fn request_shutdown(&self) -> Result<(), BackendError> {
        Ok(())
    }
}

pub fn run_proxy(
    backend: Arc<dyn InterceptionBackend>,
    config: Config,
    runtime: Arc<RuntimeState>,
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
        process_captured_packet(&*backend, &config, &runtime, captured);
    }

    Ok(())
}

fn process_captured_packet(
    backend: &dyn InterceptionBackend,
    config: &Config,
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
            reinject_or_log(backend, context, runtime);
            return;
        }
        Err(error) => {
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
    let Some(matched_override) = lookup_override(&snapshot, &config.gui_name, &question.name)
    else {
        reinject_or_log(backend, context, runtime);
        return;
    };
    let (answers, contributing_rules, builtin_hit) = match matched_override {
        OverrideMatch::Builtin if question.qtype == 1 => (
            vec![dns::AnswerRecord::A {
                owner: question.name.clone(),
                address: std::net::Ipv4Addr::LOCALHOST,
                ttl: config.ttl,
            }],
            Vec::new(),
            true,
        ),
        OverrideMatch::Builtin => {
            reinject_or_log(backend, context, runtime);
            return;
        }
        OverrideMatch::Rule(rule) if rule.record_type == crate::config::RuleType::A => {
            if question.qtype != 1 {
                reinject_or_log(backend, context, runtime);
                return;
            }
            (
                vec![dns::AnswerRecord::A {
                    owner: question.name.clone(),
                    address: rule.address.expect("validated A address"),
                    ttl: rule.ttl,
                }],
                vec![rule],
                false,
            )
        }
        OverrideMatch::Rule(rule) => {
            let resolution = if question.qtype == 5 {
                Ok((
                    vec![dns::AnswerRecord::Cname {
                        owner: question.name.clone(),
                        target: rule.target.clone().expect("validated CNAME target"),
                        ttl: rule.ttl,
                    }],
                    vec![rule],
                    false,
                ))
            } else {
                resolve_cname_chain(
                    &snapshot,
                    &config.gui_name,
                    &question.name,
                    question.qtype,
                    config.ttl,
                )
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
    let retained_rules = &contributing_rules[..answer_count.min(contributing_rules.len())];
    runtime.record_synthesized(
        retained_rules,
        builtin_hit && answer_count > contributing_rules.len(),
    );
}

enum OverrideMatch<'a> {
    Builtin,
    Rule(&'a Rule),
}

fn lookup_override<'a>(
    rules: &'a CompiledRules,
    gui_name: &str,
    query_name: &str,
) -> Option<OverrideMatch<'a>> {
    if query_name.eq_ignore_ascii_case(gui_name) {
        Some(OverrideMatch::Builtin)
    } else {
        rules.lookup_normalized(query_name).map(OverrideMatch::Rule)
    }
}

fn resolve_cname_chain<'a>(
    rules: &'a CompiledRules,
    gui_name: &str,
    query_name: &str,
    qtype: u16,
    gui_ttl: u32,
) -> Result<(Vec<dns::AnswerRecord>, Vec<&'a Rule>, bool), ()> {
    let mut answers = Vec::new();
    let mut contributing_rules = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut current = query_name.to_owned();
    let mut cname_count = 0;
    visited.insert(current.clone());

    loop {
        if current.eq_ignore_ascii_case(gui_name) {
            if qtype == 1 {
                answers.push(dns::AnswerRecord::A {
                    owner: current,
                    address: std::net::Ipv4Addr::LOCALHOST,
                    ttl: gui_ttl,
                });
                return Ok((answers, contributing_rules, true));
            }
            break;
        }
        let Some(rule) = rules.lookup_normalized(&current) else {
            break;
        };
        match rule.record_type {
            crate::config::RuleType::A => {
                if qtype == 1 {
                    answers.push(dns::AnswerRecord::A {
                        owner: current,
                        address: rule.address.expect("validated A address"),
                        ttl: rule.ttl,
                    });
                    contributing_rules.push(rule);
                }
                break;
            }
            crate::config::RuleType::Cname => {
                if cname_count == 16 {
                    break;
                }
                let target = rule.target.as_deref().expect("validated CNAME target");
                if !visited.insert(target.to_owned()) {
                    return Err(());
                }
                answers.push(dns::AnswerRecord::Cname {
                    owner: current,
                    target: target.to_owned(),
                    ttl: rule.ttl,
                });
                contributing_rules.push(rule);
                current = target.to_owned();
                cname_count += 1;
            }
        }
    }
    if answers.is_empty() {
        Err(())
    } else {
        Ok((answers, contributing_rules, false))
    }
}

fn fail_open(
    backend: &dyn InterceptionBackend,
    context: FlowContext,
    runtime: &RuntimeState,
    error: impl Into<String>,
) {
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
        runtime.record_error(error.to_string());
        runtime.record_fail_open();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::RuleInput, packet::FlowTuple, rules::RuleManager};
    use std::{
        env,
        net::Ipv4Addr,
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
        fail_response: AtomicBool,
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
            source: Ipv4Addr::new(192, 0, 2, 10),
            source_port: 53000,
            destination: Ipv4Addr::new(198, 51, 100, 53),
            destination_port: 53,
        }
    }

    fn wire_packet(payload: &[u8]) -> Vec<u8> {
        crate::packet::build_ipv4_udp(test_tuple(), payload).unwrap()
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
                backend_context: Box::new(()),
            },
            dns_payload,
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
                    record_type: crate::config::RuleType::A,
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
            record_type: crate::config::RuleType::A,
            address: Some(address.into()),
            target: None,
            ttl: Some(60),
        }
    }

    fn cname_rule(name: &str, target: &str) -> RuleInput {
        RuleInput {
            name: name.into(),
            record_type: crate::config::RuleType::Cname,
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
                record_type: crate::config::RuleType::A,
                address: Some("192.0.2.9".into()),
                target: None,
                ttl: Some(60),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        let rules = CompiledRules::new(rules);
        assert!(matches!(
            lookup_override(&rules, "dns-shunt.local", "DNS-SHUNT.LOCAL"),
            Some(OverrideMatch::Builtin)
        ));
        assert!(matches!(
            lookup_override(&rules, "dns-shunt.local", "host.dns-shunt.local"),
            Some(OverrideMatch::Rule(_))
        ));
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
}
