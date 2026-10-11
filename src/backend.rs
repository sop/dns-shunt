use crate::{
    admin::RuntimeState,
    config::{Config, Rule},
    dns,
    packet::FlowTuple,
};
use std::{any::Any, sync::Arc};
use thiserror::Error;

pub struct FlowContext {
    pub tuple: Option<FlowTuple>,
    pub backend_context: Arc<dyn Any + Send + Sync>,
}

pub struct CapturedPacket {
    pub context: FlowContext,
    pub dns_payload: Option<Vec<u8>>,
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
    fn reinject_original(&self, context: &FlowContext) -> Result<(), BackendError>;
    fn request_shutdown(&self) {}
}

pub fn run_proxy(
    backend: Arc<dyn InterceptionBackend>,
    config: Config,
    runtime: Arc<RuntimeState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let weak_backend = Arc::downgrade(&backend);
    runtime.set_stop_callback(Arc::new(move || {
        if let Some(backend) = weak_backend.upgrade() {
            backend.request_shutdown();
        }
    }));
    if runtime.is_stopping() {
        runtime.stop();
    }

    #[cfg(target_os = "windows")]
    {
        let signal_runtime = Arc::clone(&runtime);
        ctrlc::set_handler(move || {
            signal_runtime.stop();
        })?;
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

    eprintln!("DNS interception stopped");
    Ok(())
}

fn process_captured_packet(
    backend: &dyn InterceptionBackend,
    config: &Config,
    runtime: &RuntimeState,
    captured: CapturedPacket,
) {
    let context = captured.context;
    let Some(payload) = captured.dns_payload.as_deref() else {
        fail_open(
            backend,
            &context,
            runtime,
            "captured packet is not a valid IPv4 UDP DNS query",
        );
        return;
    };
    let question = match dns::parse_query(payload) {
        Ok(question) => question,
        Err(error) => {
            fail_open(
                backend,
                &context,
                runtime,
                format!("DNS query parsing failed: {error}"),
            );
            return;
        }
    };

    if question.qtype != 1 || question.qclass != 1 {
        reinject_or_log(backend, &context, runtime);
        return;
    }
    let snapshot = runtime.rules.snapshot();
    let Some(matched_override) = lookup_override(&snapshot, &config.gui_name, &question.name)
    else {
        reinject_or_log(backend, &context, runtime);
        return;
    };
    let (address, ttl) = match &matched_override {
        OverrideMatch::Builtin => (std::net::Ipv4Addr::LOCALHOST, config.ttl),
        OverrideMatch::Rule(rule) => (rule.address, rule.ttl),
    };
    let response = match dns::build_a_response(payload, &question, address, ttl) {
        Ok(response) => response,
        Err(error) => {
            fail_open(
                backend,
                &context,
                runtime,
                format!("DNS override response build failed: {error}"),
            );
            return;
        }
    };
    if let Err(error) = backend.inject_response(&context, &response) {
        fail_open(
            backend,
            &context,
            runtime,
            format!("DNS override response injection failed: {error}"),
        );
        return;
    }
    match &matched_override {
        OverrideMatch::Rule(rule) => runtime.record_override(rule),
        OverrideMatch::Builtin => runtime.record_builtin_override(),
    }
}

enum OverrideMatch {
    Builtin,
    Rule(Rule),
}

fn lookup_override(rules: &[Rule], gui_name: &str, query_name: &str) -> Option<OverrideMatch> {
    if query_name.eq_ignore_ascii_case(gui_name) {
        Some(OverrideMatch::Builtin)
    } else {
        crate::config::lookup_rule(rules, query_name)
            .cloned()
            .map(OverrideMatch::Rule)
    }
}

fn fail_open(
    backend: &dyn InterceptionBackend,
    context: &FlowContext,
    runtime: &RuntimeState,
    error: impl Into<String>,
) {
    runtime.record_error(error);
    runtime.record_fail_open();
    reinject_or_log(backend, context, runtime);
}

fn reinject_or_log(
    backend: &dyn InterceptionBackend,
    context: &FlowContext,
    runtime: &RuntimeState,
) {
    if let Err(error) = backend.reinject_original(context) {
        eprintln!("failed to reinject original DNS packet: {error}");
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
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    struct OriginalPayload(Option<Vec<u8>>);

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

        fn reinject_original(&self, context: &FlowContext) -> Result<(), BackendError> {
            let original = context
                .backend_context
                .downcast_ref::<OriginalPayload>()
                .ok_or_else(|| BackendError("invalid mock packet context".into()))?;
            self.reinjections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(original.0.clone());
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

    fn packet(payload: Option<Vec<u8>>) -> CapturedPacket {
        let tuple = FlowTuple {
            source: Ipv4Addr::new(192, 0, 2, 10),
            source_port: 53000,
            destination: Ipv4Addr::new(198, 51, 100, 53),
            destination_port: 53,
        };
        CapturedPacket {
            context: FlowContext {
                tuple: Some(tuple),
                backend_context: Arc::new(OriginalPayload(payload.clone())),
            },
            dns_payload: payload,
        }
    }

    fn runtime() -> (Config, Arc<RuntimeState>) {
        let config = Config::parse("upstream = \"not-an-address\"\nsource_port = 53\n").unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir()
            .join(format!("dns-shunt-backend-{nonce}"))
            .join("rules.json");
        let rules = RuleManager::load(path, config.gui_name.clone(), config.ttl).unwrap();
        rules
            .transact(|_| {
                Ok(vec![RuleInput {
                    name: "match.example".into(),
                    address: "192.0.2.44".into(),
                    ttl: Some(90),
                }])
            })
            .unwrap();
        (config.clone(), RuntimeState::new(config, rules, "test"))
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
        assert_eq!(&responses[0][original.len() + 12..], &[192, 0, 2, 44]);
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
            packets.iter().cloned().map(Some).collect::<Vec<_>>()
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
        assert_eq!(*backend.reinjections.lock().unwrap(), vec![Some(malformed)]);
        assert_eq!(runtime.status()["overrides"], 0);
        assert_eq!(runtime.status()["fail_open"], 1);
    }

    #[test]
    fn response_injection_failure_reinjects_the_original_once() {
        let (config, runtime) = runtime();
        let backend = MockBackend::default();
        backend.fail_response.store(true, Ordering::Relaxed);
        let original = query(4, "match.example", 1, 1);
        process_captured_packet(&backend, &config, &runtime, packet(Some(original.clone())));
        assert_eq!(backend.response_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(*backend.reinjections.lock().unwrap(), vec![Some(original)]);
        assert_eq!(runtime.status()["overrides"], 0);
        assert_eq!(runtime.status()["fail_open"], 1);
        assert_eq!(runtime.status()["errors"], 1);
    }

    #[test]
    fn built_in_gui_name_precedes_user_rules_and_user_wildcards() {
        let rules = crate::config::validate_rules(
            vec![RuleInput {
                name: "*.dns-shunt.local".into(),
                address: "192.0.2.9".into(),
                ttl: Some(60),
            }],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        assert!(matches!(
            lookup_override(&rules, "dns-shunt.local", "DNS-SHUNT.LOCAL"),
            Some(OverrideMatch::Builtin)
        ));
        assert!(matches!(
            lookup_override(&rules, "dns-shunt.local", "host.dns-shunt.local"),
            Some(OverrideMatch::Rule(_))
        ));
    }
}
