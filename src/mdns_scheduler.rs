use crate::{
    admin::RuntimeState,
    backend::{FlowContext, InterceptionBackend},
    config::Rule,
    mdns::{
        CandidateAnswer, DeliveryMode, MdnsQuery, MdnsRecord, MdnsRrKey, build_legacy_response,
        build_native_response,
    },
    packet::{FlowTuple, build_udp},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_PENDING_TASKS: usize = 1024;
const MULTICAST_RATE_LIMIT: Duration = Duration::from_secs(1);

pub trait JitterProvider: Send + Sync {
    fn delay_ms(&self) -> u64;
}

pub struct RandomJitter;

impl JitterProvider for RandomJitter {
    fn delay_ms(&self) -> u64 {
        let mut buf = [0u8; 4];
        let _ = getrandom::fill(&mut buf);
        let val = u32::from_ne_bytes(buf);
        20 + (val % 101) as u64
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct FixedJitter(pub u64);

impl JitterProvider for FixedJitter {
    fn delay_ms(&self) -> u64 {
        self.0
    }
}

pub struct MulticastThrottle {
    recent: HashMap<(u32, MdnsRrKey), Instant>,
}

impl Default for MulticastThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticastThrottle {
    pub fn new() -> Self {
        Self {
            recent: HashMap::new(),
        }
    }

    pub fn is_rate_limited(&self, if_index: u32, key: &MdnsRrKey, now: Instant) -> bool {
        if let Some(&last) = self.recent.get(&(if_index, key.clone())) {
            now.duration_since(last) < MULTICAST_RATE_LIMIT
        } else {
            false
        }
    }

    pub fn record_multicast(&mut self, if_index: u32, key: MdnsRrKey, now: Instant) {
        self.recent.insert((if_index, key), now);
        if self.recent.len() > 2048 {
            self.recent
                .retain(|_, &mut time| now.duration_since(time) < MULTICAST_RATE_LIMIT * 2);
        }
    }
}

#[derive(Clone)]
pub struct ScheduledAnswerItem {
    pub record: MdnsRecord,
    pub rule: Rule,
    pub delivery: DeliveryMode,
    pub planned_ttl: u32,
}

pub struct PendingTask {
    #[allow(dead_code)]
    pub id: u64,
    pub deadline: Instant,
    pub if_index: u32,
    pub context: FlowContext,
    pub tuple: FlowTuple,
    pub is_legacy: bool,
    pub query_id: u16,
    pub raw_questions_section: Vec<u8>,
    pub question_count: u16,
    pub answers: Vec<ScheduledAnswerItem>,
    pub suppressed_keys: HashSet<MdnsRrKey>,
}

struct SchedulerState {
    stopped: bool,
    tasks: Vec<PendingTask>,
    next_id: u64,
}

pub struct MdnsScheduler {
    backend: Arc<dyn InterceptionBackend>,
    runtime: Arc<RuntimeState>,
    jitter: Arc<dyn JitterProvider>,
    state: Arc<Mutex<SchedulerState>>,
    condvar: Arc<Condvar>,
    throttle: Arc<Mutex<MulticastThrottle>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
}

impl MdnsScheduler {
    pub fn new(
        backend: Arc<dyn InterceptionBackend>,
        runtime: Arc<RuntimeState>,
        jitter: Arc<dyn JitterProvider>,
    ) -> Arc<Self> {
        let state = Arc::new(Mutex::new(SchedulerState {
            stopped: false,
            tasks: Vec::new(),
            next_id: 1,
        }));
        let condvar = Arc::new(Condvar::new());
        let throttle = Arc::new(Mutex::new(MulticastThrottle::new()));

        let scheduler = Arc::new(Self {
            backend,
            runtime,
            jitter,
            state: Arc::clone(&state),
            condvar: Arc::clone(&condvar),
            throttle: Arc::clone(&throttle),
            worker: Mutex::new(None),
            stopped: AtomicBool::new(false),
        });

        let worker_scheduler = Arc::clone(&scheduler);
        let handle = thread::spawn(move || {
            worker_scheduler.worker_loop();
        });

        *scheduler.worker.lock().unwrap() = Some(handle);
        scheduler
    }

    pub fn schedule(
        &self,
        context: FlowContext,
        query: MdnsQuery,
        candidates: Vec<CandidateAnswer<'_>>,
    ) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }

        let Some(tuple) = context.tuple else {
            return false;
        };

        let delay_ms = self.jitter.delay_ms();
        let deadline = Instant::now() + Duration::from_millis(delay_ms);
        let if_index = context.interface_index;
        let is_legacy = query.is_legacy;
        let max_ttl = if is_legacy { 10 } else { 120 };

        let scheduled_answers: Vec<ScheduledAnswerItem> = candidates
            .into_iter()
            .map(|c| {
                let planned_ttl = c.record.ttl().min(max_ttl);
                ScheduledAnswerItem {
                    record: c.record,
                    rule: c.contributing_rule.clone(),
                    delivery: c.delivery,
                    planned_ttl,
                }
            })
            .collect();

        let mut state = self.state.lock().unwrap();
        if state.stopped || state.tasks.len() >= MAX_PENDING_TASKS {
            return false;
        }

        let task_id = state.next_id;
        state.next_id += 1;

        state.tasks.push(PendingTask {
            id: task_id,
            deadline,
            if_index,
            context,
            tuple,
            is_legacy,
            query_id: query.id,
            raw_questions_section: query.raw_questions_section,
            question_count: query.questions.len() as u16,
            answers: scheduled_answers,
            suppressed_keys: HashSet::new(),
        });

        self.condvar.notify_all();
        true
    }

    pub fn observe_peer_response(&self, if_index: u32, response_id: u16, answers: &[MdnsRecord]) {
        let mut state = self.state.lock().unwrap();
        for answer in answers {
            let key = answer.key();
            let peer_ttl = answer.ttl();
            for task in &mut state.tasks {
                if task.if_index == if_index && (!task.is_legacy || task.query_id == response_id) {
                    for item in &task.answers {
                        if item.record.key() == key && peer_ttl >= item.planned_ttl {
                            task.suppressed_keys.insert(key.clone());
                        }
                    }
                }
            }
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        {
            let mut state = self.state.lock().unwrap();
            state.stopped = true;
            state.tasks.clear();
        }
        self.condvar.notify_all();
    }

    pub fn join(&self) {
        self.stop();
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    fn worker_loop(&self) {
        loop {
            let task = {
                let mut state = self.state.lock().unwrap();
                loop {
                    if state.stopped {
                        return;
                    }
                    let now = Instant::now();
                    let mut earliest_due = None;
                    let mut due_index = None;

                    for (index, t) in state.tasks.iter().enumerate() {
                        if now >= t.deadline {
                            due_index = Some(index);
                            break;
                        }
                        match earliest_due {
                            None => earliest_due = Some(t.deadline),
                            Some(d) if t.deadline < d => earliest_due = Some(t.deadline),
                            _ => {}
                        }
                    }

                    if let Some(index) = due_index {
                        break state.tasks.remove(index);
                    }

                    match earliest_due {
                        Some(d) => {
                            let dur = d.saturating_duration_since(now);
                            let (guard, _) = self.condvar.wait_timeout(state, dur).unwrap();
                            state = guard;
                        }
                        None => {
                            state = self.condvar.wait(state).unwrap();
                        }
                    }
                }
            };

            self.dispatch_task(task);
        }
    }

    fn dispatch_task(&self, task: PendingTask) {
        let now = Instant::now();

        if task.is_legacy {
            self.dispatch_legacy_task(task);
        } else {
            self.dispatch_native_task(task, now);
        }
    }

    fn dispatch_native_task(&self, task: PendingTask, now: Instant) {
        let mut qm_items = Vec::new();
        let mut qu_items = Vec::new();

        {
            let throttle = self.throttle.lock().unwrap();
            for item in &task.answers {
                let key = item.record.key();
                if task.suppressed_keys.contains(&key) {
                    continue;
                }
                match item.delivery {
                    DeliveryMode::QmOnly => {
                        if !throttle.is_rate_limited(task.if_index, &key, now) {
                            qm_items.push(item);
                        }
                    }
                    DeliveryMode::QuOnly => {
                        qu_items.push(item);
                    }
                    DeliveryMode::Both => {
                        if !throttle.is_rate_limited(task.if_index, &key, now) {
                            qm_items.push(item);
                        } else {
                            qu_items.push(item);
                        }
                    }
                    DeliveryMode::Legacy => {}
                }
            }
        }

        if !qm_items.is_empty() {
            let records: Vec<&MdnsRecord> = qm_items.iter().map(|i| &i.record).collect();
            if let Ok(payload) = build_native_response(&records) {
                let multicast_dst = match task.tuple.source {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb)),
                };
                let tuple = FlowTuple {
                    source: task.tuple.source,
                    source_port: 5353,
                    destination: multicast_dst,
                    destination_port: 5353,
                };
                if let Ok(packet) = build_udp(tuple, &payload, 255)
                    && self
                        .backend
                        .inject_raw_packet(&task.context, &packet, true)
                        .is_ok()
                {
                    let mut throttle = self.throttle.lock().unwrap();
                    for item in &qm_items {
                        throttle.record_multicast(task.if_index, item.record.key(), now);
                    }
                    let rules: Vec<&Rule> = qm_items.iter().map(|i| &i.rule).collect();
                    self.runtime.record_synthesized(&rules, false);
                    let response_names: Vec<&str> =
                        qm_items.iter().map(|i| i.record.owner()).collect();
                    tracing::debug!(
                        names = ?response_names,
                        "injected scheduled mDNS response packet"
                    );
                }
            }
        }

        if !qu_items.is_empty() {
            let records: Vec<&MdnsRecord> = qu_items.iter().map(|i| &i.record).collect();
            if let Ok(payload) = build_native_response(&records) {
                let tuple = FlowTuple {
                    source: task.tuple.source,
                    source_port: 5353,
                    destination: task.tuple.source,
                    destination_port: task.tuple.source_port,
                };
                if let Ok(packet) = build_udp(tuple, &payload, 255)
                    && self
                        .backend
                        .inject_raw_packet(&task.context, &packet, false)
                        .is_ok()
                {
                    let rules: Vec<&Rule> = qu_items.iter().map(|i| &i.rule).collect();
                    self.runtime.record_synthesized(&rules, false);
                    let response_names: Vec<&str> =
                        qu_items.iter().map(|i| i.record.owner()).collect();
                    tracing::debug!(
                        names = ?response_names,
                        "injected scheduled mDNS response packet"
                    );
                }
            }
        }
    }

    fn dispatch_legacy_task(&self, task: PendingTask) {
        let mut legacy_items = Vec::new();
        for item in &task.answers {
            let key = item.record.key();
            if !task.suppressed_keys.contains(&key) {
                legacy_items.push(item);
            }
        }

        if legacy_items.is_empty() {
            return;
        }

        let records: Vec<&MdnsRecord> = legacy_items.iter().map(|i| &i.record).collect();
        if let Ok(payload) = build_legacy_response(
            task.query_id,
            &task.raw_questions_section,
            task.question_count,
            &records,
        ) {
            let tuple = FlowTuple {
                source: task.tuple.source,
                source_port: 5353,
                destination: task.tuple.source,
                destination_port: task.tuple.source_port,
            };
            if let Ok(packet) = build_udp(tuple, &payload, 255)
                && self
                    .backend
                    .inject_raw_packet(&task.context, &packet, false)
                    .is_ok()
            {
                let rules: Vec<&Rule> = legacy_items.iter().map(|i| &i.rule).collect();
                self.runtime.record_synthesized(&rules, false);
                let response_names: Vec<&str> =
                    legacy_items.iter().map(|i| i.record.owner()).collect();
                tracing::debug!(
                    names = ?response_names,
                    "injected scheduled mDNS response packet"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_throttle_enforces_one_second_interval() {
        let mut throttle = MulticastThrottle::new();
        let key = MdnsRrKey {
            name: "test.local".into(),
            rr_type: 1,
            class: 1,
            rdata: vec![192, 0, 2, 1],
        };
        let t0 = Instant::now();
        assert!(!throttle.is_rate_limited(1, &key, t0));

        throttle.record_multicast(1, key.clone(), t0);
        assert!(throttle.is_rate_limited(1, &key, t0 + Duration::from_millis(500)));
        assert!(!throttle.is_rate_limited(1, &key, t0 + Duration::from_millis(1001)));
        // Different interface index is not rate limited
        assert!(!throttle.is_rate_limited(2, &key, t0 + Duration::from_millis(500)));
    }
}
