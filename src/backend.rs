use crate::{
    admin::RuntimeState,
    config::{Config, Rule},
    dns::{self, Question},
    packet::FlowTuple,
};
use std::{
    any::Any,
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const MAX_IN_FLIGHT: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIVE_TIMEOUT: Duration = Duration::from_millis(100);

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

struct PendingRequest {
    context: FlowContext,
    original_id: u16,
    question: Question,
    expires: Instant,
}

#[derive(Default)]
struct RequestTable {
    next_id: u16,
    pending: HashMap<u16, PendingRequest>,
}

impl RequestTable {
    fn insert(
        &mut self,
        context: FlowContext,
        payload: &[u8],
        now: Instant,
    ) -> Result<(u16, Vec<u8>), FlowContext> {
        let question = match dns::parse_query(payload) {
            Ok(question) => question,
            Err(_) => return Err(context),
        };
        if self.pending.len() >= MAX_IN_FLIGHT {
            return Err(context);
        }
        // DNS replies do not carry the original client tuple, so isolate every in-flight ID.
        let upstream_id = (0..=u16::MAX)
            .map(|step| self.next_id.wrapping_add(step))
            .find(|id| !self.pending.contains_key(id));
        let Some(upstream_id) = upstream_id else {
            return Err(context);
        };
        self.next_id = upstream_id.wrapping_add(1);
        let rewritten = match dns::rewrite_id(payload, upstream_id) {
            Ok(payload) => payload,
            Err(_) => return Err(context),
        };
        self.pending.insert(
            upstream_id,
            PendingRequest {
                context,
                original_id: question.id,
                question,
                expires: now + REQUEST_TIMEOUT,
            },
        );
        Ok((upstream_id, rewritten))
    }

    fn complete(&mut self, payload: &[u8]) -> Option<(FlowContext, Vec<u8>)> {
        let response_question = dns::parse_response_question(payload).ok()?;
        let pending = self.pending.get(&response_question.id)?;
        if pending.question.name != response_question.name
            || pending.question.qtype != response_question.qtype
            || pending.question.qclass != response_question.qclass
        {
            return None;
        }
        let pending = self.pending.remove(&response_question.id)?;
        let response = dns::rewrite_id(payload, pending.original_id).ok()?;
        Some((pending.context, response))
    }

    fn remove(&mut self, id: u16) -> Option<FlowContext> {
        self.pending.remove(&id).map(|pending| pending.context)
    }

    fn expire(&mut self, now: Instant) -> Vec<FlowContext> {
        let expired: Vec<u16> = self
            .pending
            .iter()
            .filter_map(|(id, pending)| (pending.expires <= now).then_some(*id))
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.remove(id))
            .collect()
    }

    fn drain(&mut self) -> Vec<FlowContext> {
        self.pending
            .drain()
            .map(|(_, pending)| pending.context)
            .collect()
    }
}

pub fn run_proxy(
    backend: Arc<dyn InterceptionBackend>,
    config: Config,
    upstream_socket: UdpSocket,
    runtime: Arc<RuntimeState>,
) -> Result<(), Box<dyn std::error::Error>> {
    upstream_socket.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
    let upstream = SocketAddr::from((config.upstream, 53));
    let pending = Arc::new(Mutex::new(RequestTable::default()));
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

    let response_backend = Arc::clone(&backend);
    let response_pending = Arc::clone(&pending);
    let response_runtime = Arc::clone(&runtime);
    let response_socket = upstream_socket.try_clone()?;
    let response_worker = thread::Builder::new()
        .name("dns-shunt-upstream".into())
        .spawn(move || {
            let mut buffer = vec![0u8; 65_535];
            while !response_runtime.is_stopping() {
                let received = response_socket.recv_from(&mut buffer);
                let expired = response_pending
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .expire(Instant::now());
                for context in expired {
                    reinject_or_log(&response_backend, &context, &response_runtime);
                    response_runtime.record_fail_open();
                }
                match received {
                    Ok((length, source)) if source == upstream => {
                        let completion = response_pending
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .complete(&buffer[..length]);
                        if let Some((context, payload)) = completion
                            && response_backend
                                .inject_response(&context, &payload)
                                .is_err()
                        {
                            response_runtime.record_error("upstream response injection failed");
                            reinject_or_log(&response_backend, &context, &response_runtime);
                            response_runtime.record_fail_open();
                        }
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => {
                        response_runtime
                            .record_error(format!("upstream socket receive failed: {error}"));
                        response_runtime.stop();
                        break;
                    }
                }
            }
        })?;

    while !runtime.is_stopping() {
        let captured = match backend.capture() {
            Ok(captured) => captured,
            Err(error) => {
                if runtime.is_stopping() {
                    break;
                }
                runtime.record_error(error.to_string());
                runtime.stop();
                drain_pending(&backend, &pending, &runtime);
                let _ = response_worker.join();
                return Err(Box::new(error));
            }
        };
        let Some(payload) = captured.dns_payload.as_deref() else {
            reinject_or_log(&backend, &captured.context, &runtime);
            runtime.record_fail_open();
            continue;
        };
        let question = match dns::parse_query(payload) {
            Ok(question) => question,
            Err(_) => {
                reinject_or_log(&backend, &captured.context, &runtime);
                runtime.record_fail_open();
                continue;
            }
        };

        let snapshot = runtime.rules.snapshot();
        let matched_override = lookup_override(&snapshot, &config.gui_name, &question.name);
        if question.qtype == 1
            && question.qclass == 1
            && let Some(matched_override) = matched_override.as_ref()
        {
            let (address, ttl) = match matched_override {
                OverrideMatch::Builtin => (std::net::Ipv4Addr::LOCALHOST, config.ttl),
                OverrideMatch::Rule(rule) => (rule.address, rule.ttl),
            };
            match dns::build_a_response(payload, &question, address, ttl) {
                Ok(response)
                    if backend
                        .inject_response(&captured.context, &response)
                        .is_ok() =>
                {
                    match matched_override {
                        OverrideMatch::Rule(rule) => runtime.record_override(rule),
                        OverrideMatch::Builtin => runtime.record_builtin_override(),
                    }
                    continue;
                }
                _ => {
                    reinject_or_log(&backend, &captured.context, &runtime);
                    runtime.record_fail_open();
                    continue;
                }
            }
        }

        let inserted = pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(captured.context, payload, Instant::now());
        let (upstream_id, forwarded_query) = match inserted {
            Ok(request) => request,
            Err(context) => {
                reinject_or_log(&backend, &context, &runtime);
                runtime.record_fail_open();
                continue;
            }
        };
        if upstream_socket.send_to(&forwarded_query, upstream).is_err() {
            let context = pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(upstream_id);
            if let Some(context) = context {
                reinject_or_log(&backend, &context, &runtime);
            }
            runtime.record_error("sending DNS query to upstream failed");
            runtime.record_fail_open();
        } else {
            runtime.record_forward();
        }
    }

    drain_pending(&backend, &pending, &runtime);
    if response_worker.join().is_err() {
        eprintln!("upstream response worker terminated unexpectedly");
    }
    eprintln!("DNS interception stopped");
    Ok(())
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

fn drain_pending(
    backend: &Arc<dyn InterceptionBackend>,
    pending: &Arc<Mutex<RequestTable>>,
    runtime: &RuntimeState,
) {
    let queued = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain();
    for context in queued {
        reinject_or_log(backend, &context, runtime);
        runtime.record_fail_open();
    }
}

fn reinject_or_log(
    backend: &Arc<dyn InterceptionBackend>,
    context: &FlowContext,
    runtime: &RuntimeState,
) {
    if let Err(error) = backend.reinject_original(context) {
        eprintln!("failed to reinject original DNS packet: {error}");
        runtime.record_error(error.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::FlowTuple;
    use std::net::Ipv4Addr;

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut payload = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        payload[..2].copy_from_slice(&id.to_be_bytes());
        for label in name.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.extend_from_slice(&[0, 0, 28, 0, 1]);
        payload
    }

    fn context(source_port: u16) -> FlowContext {
        FlowContext {
            tuple: Some(FlowTuple {
                source: Ipv4Addr::new(192, 0, 2, 10),
                source_port,
                destination: Ipv4Addr::new(198, 51, 100, 53),
                destination_port: 53,
            }),
            backend_context: Arc::new(()),
        }
    }

    #[test]
    fn translates_repeated_transaction_ids_and_correlates_parallel_flows() {
        let mut table = RequestTable::default();
        let (first_id, first_query) = table
            .insert(context(1001), &query(7, "one.example"), Instant::now())
            .unwrap_or_else(|_| panic!("first request should be inserted"));
        let (second_id, second_query) = table
            .insert(context(1002), &query(7, "two.example"), Instant::now())
            .unwrap_or_else(|_| panic!("second request should be inserted"));
        assert_ne!(first_id, second_id);

        let mut first_response = first_query;
        first_response[2] |= 0x80;
        assert_eq!(
            table
                .complete(&first_response)
                .unwrap()
                .0
                .tuple
                .unwrap()
                .source_port,
            1001
        );
        let mut second_response = second_query;
        second_response[2] |= 0x80;
        let (second_context, restored) = table.complete(&second_response).unwrap();
        assert_eq!(second_context.tuple.unwrap().source_port, 1002);
        assert_eq!(&restored[..2], &7u16.to_be_bytes());
    }

    #[test]
    fn rejects_mismatched_response_questions_and_expires_contexts() {
        let mut table = RequestTable::default();
        let now = Instant::now();
        let (id, mut request) = table
            .insert(context(2000), &query(9, "right.example"), now)
            .unwrap_or_else(|_| panic!("request should be inserted"));
        request[2] |= 0x80;
        let wrong = query(id, "wrong.example");
        let mut wrong = wrong;
        wrong[2] |= 0x80;
        assert!(table.complete(&wrong).is_none());
        assert_eq!(table.expire(now + REQUEST_TIMEOUT).len(), 1);
    }

    #[test]
    fn returns_context_for_fail_open_when_request_table_is_full() {
        let mut table = RequestTable::default();
        let now = Instant::now();
        for port in 0..MAX_IN_FLIGHT {
            table
                .insert(context(port as u16), &query(1, "bounded.example"), now)
                .unwrap_or_else(|_| panic!("request {port} should fit in the table"));
        }
        let rejected = table
            .insert(context(60000), &query(1, "overflow.example"), now)
            .expect_err("capacity overflow must return its original flow context");
        assert_eq!(rejected.tuple.unwrap().source_port, 60000);
        assert_eq!(table.pending.len(), MAX_IN_FLIGHT);
    }

    #[test]
    fn built_in_gui_name_precedes_user_rules_and_user_wildcards() {
        let rules = crate::config::validate_rules(
            vec![crate::config::RuleInput {
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
