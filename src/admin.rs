use crate::{
    config::{self, Config, Rule},
    rules::{RuleManager, RuleStoreError},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 65_536;
type ErrorCallback = Arc<dyn Fn(&str) + Send + Sync>;

pub struct RuntimeState {
    pub config: Config,
    pub rules: RuleManager,
    pub backend: &'static str,
    started: Instant,
    stopping: AtomicBool,
    listener_failed: AtomicBool,
    stop_callback: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    ready_callback: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    error_callback: Mutex<Option<ErrorCallback>>,
    overrides: AtomicU64,
    fail_open: AtomicU64,
    errors: AtomicU64,
    rule_hits: Mutex<HashMap<String, u64>>,
    last_error: RwLock<Option<String>>,
    stats_lock: Mutex<()>,
    event_state: Mutex<EventState>,
    event_changed: Condvar,
}

#[derive(Default)]
struct EventState {
    stats_version: u64,
    rules_version: u64,
}

impl RuntimeState {
    pub fn new(config: Config, rules: RuleManager, backend: &'static str) -> Arc<Self> {
        Arc::new(Self {
            config,
            rules,
            backend,
            started: Instant::now(),
            stopping: AtomicBool::new(false),
            listener_failed: AtomicBool::new(false),
            stop_callback: Mutex::new(None),
            ready_callback: Mutex::new(None),
            error_callback: Mutex::new(None),
            overrides: AtomicU64::new(0),
            fail_open: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            rule_hits: Mutex::new(HashMap::new()),
            last_error: RwLock::new(None),
            stats_lock: Mutex::new(()),
            event_state: Mutex::new(EventState::default()),
            event_changed: Condvar::new(),
        })
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    pub fn set_stop_callback(&self, callback: Arc<dyn Fn() + Send + Sync>) {
        *self
            .stop_callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(callback);
    }

    pub fn set_ready_callback(&self, callback: Arc<dyn Fn() + Send + Sync>) {
        *self
            .ready_callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(callback);
    }

    pub fn mark_ready(&self) {
        let callback = self
            .ready_callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(callback) = callback {
            callback();
        }
    }

    pub fn set_error_callback(&self, callback: ErrorCallback) {
        *self
            .error_callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(callback);
    }

    pub fn stop(&self) {
        let _events = self
            .event_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.stopping.store(true, Ordering::Release);
        self.event_changed.notify_all();
        drop(_events);
        let callback = self
            .stop_callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(callback) = callback {
            callback();
        }
    }

    pub fn record_override(&self, rule: &Rule) {
        {
            let _stats = self
                .stats_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.overrides.fetch_add(1, Ordering::Relaxed);
            let key = if rule.wildcard {
                format!("*.{}", rule.name)
            } else {
                rule.name.clone()
            };
            *self
                .rule_hits
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(key)
                .or_default() += 1;
        }
        self.notify_stats_changed();
    }

    pub fn record_builtin_override(&self) {
        {
            let _stats = self
                .stats_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.overrides.fetch_add(1, Ordering::Relaxed);
        }
        self.notify_stats_changed();
    }

    pub fn record_fail_open(&self) {
        {
            let _stats = self
                .stats_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.fail_open.fetch_add(1, Ordering::Relaxed);
        }
        self.notify_stats_changed();
    }
    pub fn record_error(&self, error: impl Into<String>) {
        let error = error.into();
        {
            let _stats = self
                .stats_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.errors.fetch_add(1, Ordering::Relaxed);
            *self
                .last_error
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.clone());
        }
        self.notify_stats_changed();
        let callback = self
            .error_callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(callback) = callback {
            callback(&error);
        }
    }

    fn notify_stats_changed(&self) {
        let mut events = self
            .event_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        events.stats_version = events.stats_version.wrapping_add(1);
        self.event_changed.notify_all();
    }

    fn notify_rules_changed(&self) {
        let mut events = self
            .event_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        events.rules_version = events.rules_version.wrapping_add(1);
        self.event_changed.notify_all();
    }

    fn statistics_snapshot(&self) -> Value {
        let _stats = self
            .stats_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hits = self
            .rule_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        json!({
            "overrides": self.overrides.load(Ordering::Relaxed),
            "fail_open": self.fail_open.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "last_error": self
                .last_error
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            "rule_hits": hits.clone(),
        })
    }

    pub(crate) fn status(&self) -> Value {
        let _stats = self
            .stats_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        json!({
            "service": if self.is_stopping() { "stopping" } else { "running" },
            "uptime_seconds": self.started.elapsed().as_secs(),
            "backend": self.backend,
            "overrides": self.overrides.load(Ordering::Relaxed),
            "fail_open": self.fail_open.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "last_error": self
                .last_error
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            "settings": {
                "default_ttl": self.config.ttl,
                "gui_name": self.config.gui_name,
                "gui_port": self.config.gui_port,
                "rules_path": self.rules.store_path().display().to_string(),
            }
        })
    }

    fn rules_json(&self) -> Value {
        let hits = self
            .rule_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let rules = self
            .rules
            .snapshot()
            .into_iter()
            .map(|rule| {
                let key = if rule.wildcard {
                    format!("*.{}", rule.name)
                } else {
                    rule.name.clone()
                };
                json!({
                    "name": key,
                    "address": rule.address.to_string(),
                    "ttl": rule.ttl,
                    "hits": hits.get(&key).copied().unwrap_or(0),
                })
            })
            .collect::<Vec<_>>();
        json!(rules)
    }
}

pub struct AdminServer {
    runtime: Arc<RuntimeState>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("could not bind the loopback admin interface on port {0}: {1}")]
    Bind(u16, #[source] std::io::Error),
    #[error("could not start admin HTTP thread: {0}")]
    Thread(#[source] std::io::Error),
}

impl AdminServer {
    pub fn bind(runtime: &Arc<RuntimeState>) -> Result<Self, AdminError> {
        let listener = TcpListener::bind(("127.0.0.1", runtime.config.gui_port))
            .map_err(|error| AdminError::Bind(runtime.config.gui_port, error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| AdminError::Bind(runtime.config.gui_port, error))?;
        let runtime = Arc::clone(runtime);
        let worker_runtime = Arc::clone(&runtime);
        let worker = thread::Builder::new()
            .name("dns-shunt-admin".into())
            .spawn(move || {
                while !worker_runtime.is_stopping() {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let connection_runtime = Arc::clone(&worker_runtime);
                            if let Err(error) = thread::Builder::new()
                                .name("dns-shunt-admin-connection".into())
                                .spawn(move || {
                                    if let Err(error) =
                                        handle_connection(stream, &connection_runtime)
                                    {
                                        connection_runtime.record_error(error);
                                    }
                                })
                            {
                                worker_runtime.record_error(format!(
                                    concat!("could not start admin ", "connection thread: {}"),
                                    error
                                ));
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20))
                        }
                        Err(error) => {
                            worker_runtime.record_error(format!("admin listener failed: {error}"));
                            worker_runtime
                                .listener_failed
                                .store(true, Ordering::Release);
                            worker_runtime.stop();
                            break;
                        }
                    }
                }
            })
            .map_err(AdminError::Thread)?;
        Ok(Self {
            runtime,
            worker: Some(worker),
        })
    }

    pub fn join(mut self) -> Result<(), String> {
        self.runtime.stop();
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            return Err("admin HTTP thread terminated unexpectedly".into());
        }
        if self.runtime.listener_failed.load(Ordering::Acquire) {
            return Err("admin HTTP listener failed; DNS interception was stopped".into());
        }
        Ok(())
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn handle_connection(mut stream: TcpStream, runtime: &Arc<RuntimeState>) -> Result<(), String> {
    // On Windows, accepted sockets inherit the listener's nonblocking mode.
    // Request parsing uses read_exact, so each connection must be blocking.
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(message) => {
            return send_response(
                &mut stream,
                400,
                json!({"error": message}).to_string().as_bytes(),
                "application/json",
            );
        }
    };
    if let Err((status, error)) = authorize(&request, runtime) {
        return send_response(
            &mut stream,
            status,
            &json!({"error": error}).to_string().into_bytes(),
            "application/json",
        );
    }
    if request.method == "GET" && request.path == "/api/events" {
        serve_events(&mut stream, runtime);
        return Ok(());
    }
    let (status, content_type, body) = match route(&request, runtime) {
        Ok((status, value)) => (
            status,
            "application/json",
            serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec()),
        ),
        Err((status, error)) => (
            status,
            "application/json",
            serde_json::to_vec(&json!({"error": error})).unwrap_or_else(|_| b"{}".to_vec()),
        ),
    };
    if request.method == "HEAD" && request.path == "/" {
        return send_response(&mut stream, 200, b"", "text/html; charset=utf-8");
    }
    if request.method == "GET" && request.path == "/" {
        return send_response(
            &mut stream,
            200,
            DASHBOARD.as_bytes(),
            "text/html; charset=utf-8",
        );
    }
    send_response(&mut stream, status, &body, content_type)
}

fn serve_events(stream: &mut TcpStream, runtime: &RuntimeState) {
    if write!(
        stream,
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream; charset=utf-8\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: keep-alive\r\n",
            "X-Accel-Buffering: no\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "X-Frame-Options: DENY\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Content-Security-Policy: default-src 'self'; style-src ",
            "'unsafe-inline'; script-src 'unsafe-inline'\r\n\r\n"
        )
    )
    .and_then(|()| stream.flush())
    .is_err()
    {
        return;
    }

    let (mut stats_version, mut rules_version) = {
        let events = runtime
            .event_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (events.stats_version, events.rules_version)
    };
    if send_sse_event(stream, "stats", &runtime.statistics_snapshot()).is_err()
        || send_sse_event(stream, "rules-changed", &json!({})).is_err()
    {
        return;
    }

    while !runtime.is_stopping() {
        let events = runtime
            .event_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (events, _) = runtime
            .event_changed
            .wait_timeout_while(events, Duration::from_secs(2), |events| {
                events.stats_version == stats_version
                    && events.rules_version == rules_version
                    && !runtime.is_stopping()
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stats_changed = events.stats_version != stats_version;
        let rules_changed = events.rules_version != rules_version;
        stats_version = events.stats_version;
        rules_version = events.rules_version;
        drop(events);

        if runtime.is_stopping() {
            return;
        }
        if stats_changed && send_sse_event(stream, "stats", &runtime.statistics_snapshot()).is_err()
        {
            return;
        }
        if rules_changed && send_sse_event(stream, "rules-changed", &json!({})).is_err() {
            return;
        }
        if !stats_changed
            && !rules_changed
            && stream
                .write_all(b": heartbeat\n\n")
                .and_then(|()| stream.flush())
                .is_err()
        {
            return;
        }
    }
}

fn send_sse_event(stream: &mut TcpStream, name: &str, data: &Value) -> std::io::Result<()> {
    let data = serde_json::to_string(data).unwrap_or_else(|_| "{}".into());
    write!(stream, "event: {name}\ndata: {data}\n\n")?;
    stream.flush()
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut headers = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while headers.len() < 16_384 {
        stream
            .read_exact(&mut byte)
            .map_err(|error| format!("incomplete HTTP headers: {error}"))?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !headers.ends_with(b"\r\n\r\n") {
        return Err("HTTP headers exceed 16 KiB".into());
    }
    let header_text = std::str::from_utf8(&headers).map_err(|_| "HTTP headers are not UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or("missing HTTP request line")?
        .split_whitespace();
    let method = request_line.next().ok_or("missing HTTP method")?.to_owned();
    let path = request_line.next().ok_or("missing HTTP path")?.to_owned();
    if request_line.next() != Some("HTTP/1.1") {
        return Err("only HTTP/1.1 is supported".into());
    }
    let mut parsed_headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        parsed_headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = parsed_headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_owned())
        })
        .transpose()?
        .unwrap_or(0);
    if length > MAX_REQUEST_BYTES {
        return Err("request body exceeds 64 KiB".into());
    }
    let mut body = vec![0; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("incomplete request body: {error}"))?;
    Ok(HttpRequest {
        method,
        path,
        headers: parsed_headers,
        body,
    })
}

#[derive(Deserialize)]
struct IndexedInput {
    index: usize,
    name: String,
    address: String,
    ttl: Option<u32>,
}

#[derive(Deserialize)]
struct ReorderInput {
    from: usize,
    to: usize,
}

fn route(request: &HttpRequest, runtime: &RuntimeState) -> Result<(u16, Value), (u16, String)> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/status") => Ok((200, runtime.status())),
        ("GET", "/api/rules") => Ok((200, runtime.rules_json())),
        ("POST", "/api/rules") => {
            let input: config::RuleInput = parse_json(&request.body)?;
            let result = runtime
                .rules
                .transact(|current| {
                    let mut next = current.iter().map(config::rule_input).collect::<Vec<_>>();
                    next.push(input);
                    Ok(next)
                })
                .map_err(store_error)?;
            runtime.notify_rules_changed();
            Ok((201, json!({"rules": result.len()})))
        }
        ("POST", "/api/rules/reorder") => {
            let input: ReorderInput = parse_json(&request.body)?;
            let result = runtime
                .rules
                .transact(|current| {
                    if input.from >= current.len() || input.to >= current.len() {
                        return Err("rule index is out of range".into());
                    }
                    let mut next = current.iter().map(config::rule_input).collect::<Vec<_>>();
                    let rule = next.remove(input.from);
                    next.insert(input.to, rule);
                    Ok(next)
                })
                .map_err(store_error)?;
            runtime.notify_rules_changed();
            Ok((200, json!({"rules": result.len()})))
        }
        ("PUT", "/api/rules") => {
            let input: IndexedInput = parse_json(&request.body)?;
            let result = runtime
                .rules
                .transact(|current| {
                    if input.index >= current.len() {
                        return Err("rule index is out of range".into());
                    }
                    let mut next = current.iter().map(config::rule_input).collect::<Vec<_>>();
                    next[input.index] = config::RuleInput {
                        name: input.name,
                        address: input.address,
                        ttl: input.ttl,
                    };
                    Ok(next)
                })
                .map_err(store_error)?;
            runtime.notify_rules_changed();
            Ok((200, json!({"rules": result.len()})))
        }
        ("DELETE", path) if path.starts_with("/api/rules/") => {
            let index = path
                .trim_start_matches("/api/rules/")
                .parse::<usize>()
                .map_err(|_| (400, "invalid rule index".into()))?;
            let result = runtime
                .rules
                .transact(|current| {
                    if index >= current.len() {
                        return Err("rule index is out of range".into());
                    }
                    let mut next = current.iter().map(config::rule_input).collect::<Vec<_>>();
                    next.remove(index);
                    Ok(next)
                })
                .map_err(store_error)?;
            runtime.notify_rules_changed();
            Ok((200, json!({"rules": result.len()})))
        }
        _ => Err((404, "not found".into())),
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, (u16, String)> {
    serde_json::from_slice(body).map_err(|error| (400, format!("invalid JSON: {error}")))
}

fn store_error(error: RuleStoreError) -> (u16, String) {
    let status = match &error {
        RuleStoreError::Update(_) | RuleStoreError::Validation(_) => 400,
        RuleStoreError::Io(_) | RuleStoreError::Json(_) => 500,
    };
    (status, error.to_string())
}

fn allowed_hosts(runtime: &RuntimeState) -> Vec<String> {
    let hosts = ["127.0.0.1", "localhost", runtime.config.gui_name.as_str()];
    let mut allowed = Vec::with_capacity(hosts.len() * 2);
    for host in hosts {
        allowed.push(format!("{host}:{}", runtime.config.gui_port));
        if runtime.config.gui_port == 80 {
            allowed.push(host.to_owned());
        }
    }
    allowed
}

fn host_allowed(host: &str, runtime: &RuntimeState) -> bool {
    allowed_hosts(runtime)
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn origin_allowed(origin: &str, runtime: &RuntimeState) -> bool {
    allowed_hosts(runtime)
        .iter()
        .any(|host| origin.eq_ignore_ascii_case(&format!("http://{host}")))
}

fn authorize(request: &HttpRequest, runtime: &RuntimeState) -> Result<(), (u16, &'static str)> {
    if !host_allowed(
        request
            .headers
            .get("host")
            .map(String::as_str)
            .unwrap_or(""),
        runtime,
    ) {
        return Err((403, "invalid Host header"));
    }
    if matches!(request.method.as_str(), "POST" | "PUT" | "DELETE")
        && !origin_allowed(
            request
                .headers
                .get("origin")
                .map(String::as_str)
                .unwrap_or(""),
            runtime,
        )
    {
        return Err((403, "invalid or missing Origin"));
    }
    Ok(())
}

fn send_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error",
    };
    write!(
        stream,
        concat!(
            "HTTP/1.1 {} {}\r\n",
            "Content-Type: {}\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n",
            "Cache-Control: no-store\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "X-Frame-Options: DENY\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Content-Security-Policy: default-src 'self'; style-src ",
            "'unsafe-inline'; script-src 'unsafe-inline'\r\n\r\n"
        ),
        status,
        reason,
        content_type,
        body.len()
    )
    .map_err(|error| error.to_string())?;
    stream.write_all(body).map_err(|error| error.to_string())
}

const DASHBOARD: &str = include_str!("admin.html");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleManager;
    use std::{
        env,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn runtime() -> Arc<RuntimeState> {
        let config = Config::parse("upstream=\"1.1.1.1\"\nsource_port=53053\n").unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = env::temp_dir()
            .join(format!("dns-shunt-api-{nonce}"))
            .join("rules.json");
        RuntimeState::new(
            config.clone(),
            RuleManager::load(path, config.gui_name.clone(), config.ttl).unwrap(),
            "WinDivert",
        )
    }

    fn request(method: &str, path: &str, body: &str) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn stop_signaling_runs_the_backend_wakeup_callback() {
        let state = runtime();
        let callbacks = Arc::new(AtomicU64::new(0));
        let callback_count = Arc::clone(&callbacks);
        state.set_stop_callback(Arc::new(move || {
            callback_count.fetch_add(1, Ordering::Relaxed);
        }));

        state.stop();

        assert!(state.is_stopping());
        assert_eq!(callbacks.load(Ordering::Relaxed), 1);
    }

    fn connection_response(runtime: &Arc<RuntimeState>, request: &str) -> Vec<u8> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream, runtime).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        response
    }

    #[test]
    fn handles_headers_that_arrive_after_accept_on_a_nonblocking_stream() {
        let runtime = runtime();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        let port = runtime.config.gui_port;
        let client_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            write!(
                client,
                "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
            )
            .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            response
        });

        handle_connection(stream, &runtime).unwrap();
        let response = client_thread.join().unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn unauthenticated_connections_can_read_dashboard_data_and_mutate_rules() {
        let state = runtime();
        state
            .rules
            .transact(|_| {
                Ok(vec![config::RuleInput {
                    name: "secret.example".into(),
                    address: "192.0.2.55".into(),
                    ttl: None,
                }])
            })
            .unwrap();
        let port = state.config.gui_port;
        let dashboard = connection_response(
            &state,
            &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert!(dashboard.starts_with(b"HTTP/1.1 200 OK\r\n"));

        let status = connection_response(
            &state,
            &format!("GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert!(status.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            status
                .windows(b"\"service\":\"running\"".len())
                .any(|window| { window == b"\"service\":\"running\"" })
        );

        let rules = connection_response(
            &state,
            &format!("GET /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert!(rules.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            rules
                .windows(b"secret.example".len())
                .any(|window| { window == b"secret.example" })
        );

        let body = r#"{"name":"blocked.example","address":"192.0.2.9"}"#;
        let response = connection_response(
            &state,
            &format!(
                concat!(
                    "POST /api/rules HTTP/1.1\r\n",
                    "Host: 127.0.0.1:{}\r\n",
                    "Origin: http://127.0.0.1:{}\r\n",
                    "Content-Length: {}\r\n\r\n{}"
                ),
                port,
                port,
                body.len(),
                body
            ),
        );
        assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));
        assert!(state.rules.snapshot().iter().any(|rule| {
            rule.name == "blocked.example" && rule.address.to_string() == "192.0.2.9"
        }));
        assert!(
            !response
                .windows(b"WWW-Authenticate".len())
                .any(|window| { window == b"WWW-Authenticate" })
        );
    }

    #[test]
    fn enforces_host_origin_and_validates_rule_crud() {
        let runtime = runtime();
        let allowed_host = format!("127.0.0.1:{}", runtime.config.gui_port);
        let allowed_origin = format!("http://{allowed_host}");
        let denied_host = connection_response(
            &runtime,
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: evil.example:{}\r\n\r\n",
                runtime.config.gui_port
            ),
        );
        assert!(denied_host.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let missing_origin = connection_response(
            &runtime,
            &format!(
                concat!(
                    "POST /api/rules HTTP/1.1\r\n",
                    "Host: {}\r\n",
                    "Content-Length: 2\r\n\r\n{{}}"
                ),
                allowed_host
            ),
        );
        assert!(missing_origin.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let invalid_origin = connection_response(
            &runtime,
            &format!(
                concat!(
                    "POST /api/rules HTTP/1.1\r\n",
                    "Host: {}\r\n",
                    "Origin: https://{}\r\n",
                    "Content-Length: 2\r\n\r\n{{}}"
                ),
                allowed_host, allowed_host
            ),
        );
        assert!(invalid_origin.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let mut secured = request("POST", "/api/rules", "{}");
        secured.headers.insert("host".into(), allowed_host.clone());
        assert_eq!(
            authorize(&secured, &runtime),
            Err((403, "invalid or missing Origin"))
        );
        secured.headers.insert(
            "origin".into(),
            allowed_origin.replace("http://", "https://"),
        );
        assert_eq!(
            authorize(&secured, &runtime),
            Err((403, "invalid or missing Origin"))
        );
        secured.headers.insert("origin".into(), allowed_origin);
        assert_eq!(authorize(&secured, &runtime), Ok(()));
        secured.headers.insert(
            "host".into(),
            format!("evil.example:{}", runtime.config.gui_port),
        );
        assert_eq!(
            authorize(&secured, &runtime),
            Err((403, "invalid Host header"))
        );
        assert!(host_allowed(
            &format!("127.0.0.1:{}", runtime.config.gui_port),
            &runtime
        ));
        assert!(!host_allowed(
            &format!("evil.example:{}", runtime.config.gui_port),
            &runtime
        ));
        assert!(origin_allowed(
            &format!("http://localhost:{}", runtime.config.gui_port),
            &runtime
        ));
        assert!(!origin_allowed(
            &format!("https://localhost:{}", runtime.config.gui_port),
            &runtime
        ));
        assert_eq!(
            route(
                &request(
                    "POST",
                    "/api/rules",
                    r#"{"name":"app.example","address":"192.0.2.1","ttl":60}"#
                ),
                &runtime
            )
            .unwrap()
            .0,
            201
        );
        assert_eq!(
            route(
                &request(
                    "POST",
                    "/api/rules",
                    r#"{"name":"bad*name","address":"192.0.2.1"}"#
                ),
                &runtime
            )
            .unwrap_err()
            .0,
            400
        );
        assert_eq!(
            route(
                &request(
                    "PUT",
                    "/api/rules",
                    concat!(
                        r#"{"index":0,"name":"app.example","#,
                        r#""address":"192.0.2.2","ttl":30}"#
                    )
                ),
                &runtime
            )
            .unwrap()
            .0,
            200
        );
        assert_eq!(
            route(&request("DELETE", "/api/rules/0", ""), &runtime)
                .unwrap()
                .0,
            200
        );
        assert_eq!(
            route(&request("GET", "/api/rules", ""), &runtime)
                .unwrap()
                .1
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn records_only_aggregate_and_per_rule_statistics() {
        let state = runtime();
        let rule = config::validate_rules(
            vec![config::RuleInput {
                name: "hit.example".into(),
                address: "192.0.2.1".into(),
                ttl: None,
            }],
            &state.config.gui_name,
            state.config.ttl,
        )
        .unwrap()
        .remove(0);
        state
            .rules
            .transact(|_| Ok(vec![config::rule_input(&rule)]))
            .unwrap();
        state.record_override(&rule);
        let status = state.status();
        assert_eq!(status["overrides"], 1);
        assert!(status.get("forwarded").is_none());
        assert!(status["settings"].get("upstream").is_none());
        assert!(status["settings"].get("source_port").is_none());
        assert_eq!(state.rules_json()[0]["hits"], 1);
        assert_eq!(state.statistics_snapshot()["rule_hits"]["hit.example"], 1);
        let restarted = runtime();
        assert_eq!(restarted.status()["overrides"], 0);
        assert!(DASHBOARD.contains("/api/status"));
        assert!(!DASHBOARD.contains("Forwarded upstream"));
    }

    #[test]
    fn statistics_notifications_and_snapshots_include_all_counters() {
        let state = runtime();
        let rule = config::validate_rules(
            vec![config::RuleInput {
                name: "stats.example".into(),
                address: "192.0.2.1".into(),
                ttl: None,
            }],
            &state.config.gui_name,
            state.config.ttl,
        )
        .unwrap()
        .remove(0);

        state.record_override(&rule);
        state.record_builtin_override();
        state.record_fail_open();
        state.record_error("test error");

        let events = state.event_state.lock().unwrap();
        assert_eq!(events.stats_version, 4);
        let snapshot = state.statistics_snapshot();
        assert_eq!(snapshot["overrides"], 2);
        assert_eq!(snapshot["fail_open"], 1);
        assert_eq!(snapshot["errors"], 1);
        assert_eq!(snapshot["last_error"], "test error");
        assert_eq!(snapshot["rule_hits"]["stats.example"], 1);
    }

    #[test]
    fn only_successful_rule_mutations_publish_rule_changes() {
        let state = runtime();
        let version = || state.event_state.lock().unwrap().rules_version;
        assert_eq!(version(), 0);
        assert!(
            route(
                &request("POST", "/api/rules", r#"{"name":"bad*name"}"#),
                &state
            )
            .is_err()
        );
        assert_eq!(version(), 0);

        assert!(
            route(
                &request(
                    "POST",
                    "/api/rules",
                    r#"{"name":"app.example","address":"192.0.2.1"}"#
                ),
                &state
            )
            .is_ok()
        );
        assert_eq!(version(), 1);
        assert!(
            route(
                &request(
                    "PUT",
                    "/api/rules",
                    r#"{"index":5,"name":"x","address":"192.0.2.2"}"#
                ),
                &state
            )
            .is_err()
        );
        assert_eq!(version(), 1);
        assert!(
            route(
                &request(
                    "PUT",
                    "/api/rules",
                    r#"{"index":0,"name":"app.example","address":"192.0.2.2"}"#
                ),
                &state
            )
            .is_ok()
        );
        assert_eq!(version(), 2);
        assert!(route(&request("DELETE", "/api/rules/5", ""), &state).is_err());
        assert_eq!(version(), 2);
        assert!(route(&request("DELETE", "/api/rules/0", ""), &state).is_ok());
        assert_eq!(version(), 3);
    }

    #[test]
    fn reorders_rules_and_persists_the_new_order() {
        let state = runtime();
        for (name, address) in [
            ("first.example", "192.0.2.1"),
            ("second.example", "192.0.2.2"),
        ] {
            let body = format!(r#"{{"name":"{name}","address":"{address}"}}"#);
            assert!(route(&request("POST", "/api/rules", &body), &state).is_ok());
        }

        assert!(
            route(
                &request("POST", "/api/rules/reorder", r#"{"from":0,"to":1}"#),
                &state,
            )
            .is_ok()
        );
        assert_eq!(state.rules_json()[0]["name"], "second.example");
        assert_eq!(state.rules_json()[1]["name"], "first.example");
        assert!(
            route(
                &request("POST", "/api/rules/reorder", r#"{"from":2,"to":0}"#),
                &state,
            )
            .is_err()
        );

        let path = state.rules.store_path().to_path_buf();
        let persisted = RuleManager::load(
            path.clone(),
            state.config.gui_name.clone(),
            state.config.ttl,
        )
        .unwrap();
        assert_eq!(persisted.snapshot()[0].name, "second.example");
        assert_eq!(persisted.snapshot()[1].name, "first.example");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    fn read_until(stream: &mut TcpStream, delimiter: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut byte = [0u8; 1];
        while !result.ends_with(delimiter) {
            stream.read_exact(&mut byte).unwrap();
            result.push(byte[0]);
        }
        result
    }

    #[test]
    fn sse_stream_delivers_snapshots_rule_changes_and_stops_cleanly() {
        let state = runtime();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let port = state.config.gui_port;
        write!(
            client,
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .unwrap();
        let (stream, _) = listener.accept().unwrap();
        let connection_state = Arc::clone(&state);
        let worker = thread::spawn(move || handle_connection(stream, &connection_state));

        let headers = String::from_utf8(read_until(&mut client, b"\r\n\r\n")).unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains("Content-Type: text/event-stream; charset=utf-8\r\n"));
        assert!(headers.contains("Cache-Control: no-cache\r\n"));
        assert!(headers.contains("Connection: keep-alive\r\n"));
        assert!(!headers.to_ascii_lowercase().contains("content-length:"));
        assert!(!headers.to_ascii_lowercase().contains("www-authenticate:"));

        let initial_stats = String::from_utf8(read_until(&mut client, b"\n\n")).unwrap();
        assert!(initial_stats.starts_with("event: stats\n"));
        let data = initial_stats
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(data).unwrap()["overrides"], 0);
        let initial_rules = String::from_utf8(read_until(&mut client, b"\n\n")).unwrap();
        assert!(initial_rules.starts_with("event: rules-changed\n"));

        let rule = config::validate_rules(
            vec![config::RuleInput {
                name: "live.example".into(),
                address: "192.0.2.10".into(),
                ttl: None,
            }],
            &state.config.gui_name,
            state.config.ttl,
        )
        .unwrap()
        .remove(0);
        state.record_override(&rule);
        let stats = String::from_utf8(read_until(&mut client, b"\n\n")).unwrap();
        assert!(stats.starts_with("event: stats\n"));
        let data = stats
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let snapshot = serde_json::from_str::<Value>(data).unwrap();
        assert_eq!(snapshot["overrides"], 1);
        assert_eq!(snapshot["rule_hits"]["live.example"], 1);

        assert!(
            route(
                &request(
                    "POST",
                    "/api/rules",
                    r#"{"name":"changed.example","address":"192.0.2.20"}"#
                ),
                &state
            )
            .is_ok()
        );
        let changed = String::from_utf8(read_until(&mut client, b"\n\n")).unwrap();
        assert!(changed.starts_with("event: rules-changed\n"));

        state.stop();
        let mut remaining = Vec::new();
        client.read_to_end(&mut remaining).unwrap();
        worker.join().unwrap().unwrap();
    }
}
