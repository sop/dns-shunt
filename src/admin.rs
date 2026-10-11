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
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 65_536;

pub struct RuntimeState {
    pub config: Config,
    pub rules: RuleManager,
    pub backend: &'static str,
    started: Instant,
    stopping: AtomicBool,
    listener_failed: AtomicBool,
    stop_callback: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    overrides: AtomicU64,
    fail_open: AtomicU64,
    errors: AtomicU64,
    rule_hits: Mutex<HashMap<String, u64>>,
    last_error: RwLock<Option<String>>,
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
            overrides: AtomicU64::new(0),
            fail_open: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            rule_hits: Mutex::new(HashMap::new()),
            last_error: RwLock::new(None),
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

    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
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

    pub fn record_builtin_override(&self) {
        self.overrides.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fail_open(&self) {
        self.fail_open.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_error(&self, error: impl Into<String>) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        *self
            .last_error
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.into());
    }

    pub(crate) fn status(&self) -> Value {
        json!({
            "service": if self.is_stopping() { "stopping" } else { "running" },
            "uptime_seconds": self.started.elapsed().as_secs(),
            "backend": self.backend,
            "overrides": self.overrides.load(Ordering::Relaxed),
            "fail_open": self.fail_open.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "last_error": self.last_error.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone(),
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
                            if let Err(error) = handle_connection(stream, &worker_runtime) {
                                worker_runtime.record_error(error);
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
            Ok((201, json!({"rules": result.len()})))
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
    write!(stream, "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\r\n\r\n", body.len()).map_err(|error| error.to_string())?;
    stream.write_all(body).map_err(|error| error.to_string())
}

const DASHBOARD: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>dns-shunt / control room</title>
<style>
:root{color-scheme:dark;--bg:#101514;--panel:#191f1d;--line:#303a36;--muted:#a5b3aa;--ink:#edf4ec;--acid:#c7f36b;--orange:#e69b63}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% -10%,#324338 0,transparent 38%),var(--bg);color:var(--ink);font:15px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}main{max-width:1160px;margin:auto;padding:34px 24px 60px}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:22px}.brand{font-size:14px;color:var(--muted);letter-spacing:.14em;text-transform:uppercase}.brand b{color:var(--acid)}h1{font:500 clamp(34px,6vw,64px)/1.05 system-ui,sans-serif;letter-spacing:-.055em;margin:18px 0 8px}.lede{color:var(--muted);margin:0}.live{color:var(--acid);border:1px solid #607742;padding:7px 11px;border-radius:3px;font-size:12px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:30px 0}.card,.section{background:linear-gradient(145deg,#1c2420,#171c1a);border:1px solid var(--line);border-radius:5px}.card{padding:16px}.label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}.value{font:500 30px/1.25 system-ui,sans-serif;margin-top:10px}.unit{font-size:12px;color:var(--muted)}.layout{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(260px,.85fr);gap:14px}.section{padding:20px}.section h2{font:500 20px system-ui,sans-serif;margin:0 0 18px}.section-title{display:flex;align-items:center;justify-content:space-between}.count{font-size:12px;color:var(--muted)}form{display:grid;grid-template-columns:1.2fr 1fr 100px auto;gap:8px;margin-bottom:16px}input,button{font:inherit;border:1px solid var(--line);border-radius:3px;padding:10px;background:#0f1412;color:var(--ink);min-width:0}input:focus{outline:1px solid var(--acid)}button{cursor:pointer;background:var(--acid);border-color:var(--acid);color:#15200f;font-weight:700}button.delete{padding:5px 9px;background:transparent;color:#ff9b82;border-color:#714d41}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:10px;color:var(--muted);font-weight:400;text-transform:uppercase;letter-spacing:.1em}td,th{padding:11px 8px;border-bottom:1px solid var(--line)}td{font-size:13px}td.hit{text-align:right;color:var(--acid);font-variant-numeric:tabular-nums}.empty{color:var(--muted);text-align:center;padding:28px 8px}.settings{display:grid;grid-template-columns:1fr auto;gap:12px 8px;font-size:12px}.settings dt{color:var(--muted)}.settings dd{margin:0;text-align:right;overflow-wrap:anywhere}.notice{min-height:22px;color:var(--orange);font-size:12px}.foot{margin-top:14px;color:var(--muted);font-size:11px}@media(max-width:780px){main{padding:22px 14px}.grid{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}form{grid-template-columns:1fr 1fr}.settings dd{max-width:190px}}@media(max-width:420px){form{grid-template-columns:1fr}.section{padding:14px}td,th{padding:9px 4px;font-size:11px}}
</style></head><body><main><div class="top"><div class="brand"><b>dns-shunt</b> / local control room</div><div class="live" id="service">CONNECTING</div></div><h1>Route your names.</h1><p class="lede">Matched A/IN overrides only. Unmatched DNS passes through unchanged.</p>
<div class="grid"><div class="card"><div class="label">Override answers</div><div class="value" id="overrides">0</div></div><div class="card"><div class="label">Fail-open</div><div class="value" id="failopen">0</div></div><div class="card"><div class="label">Errors</div><div class="value" id="errors">0</div></div><div class="card"><div class="label">Uptime</div><div class="value" id="uptime">0<span class="unit">s</span></div></div></div>
<div class="layout"><section class="section"><div class="section-title"><h2>Override rules</h2><span class="count" id="rule-count">0 rules</span></div><form id="rule-form"><input name="index" type="hidden"><input name="name" placeholder="host.example or *.example" required><input name="address" placeholder="IPv4 address" required><input name="ttl" type="number" min="1" max="86400" placeholder="TTL"><button type="submit">Add rule +</button></form><div class="notice" id="notice"></div><div style="overflow-x:auto"><table><thead><tr><th>Pattern</th><th>IPv4 answer</th><th>TTL</th><th style="text-align:right">Hits</th><th></th></tr></thead><tbody id="rules"></tbody></table></div><p class="foot">Exact names win. Wildcards match subdomains, not the apex.</p></section><aside class="section"><h2>Service configuration</h2><dl class="settings" id="settings"></dl><p class="foot">Operational settings are read-only here and remain TOML-owned.</p></aside></div></main>
<script>
const $=id=>document.getElementById(id);let current=[];function esc(value){return String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function api(path,options={}){const response=await fetch(path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});const body=await response.json();if(!response.ok)throw Error(body.error||response.statusText);return body}function showError(error){$('notice').textContent=error.message}
 async function refresh(){try{const [status,rules]=await Promise.all([api('/api/status'),api('/api/rules')]);$('service').textContent=status.service.toUpperCase()+' · '+status.backend;$('overrides').textContent=status.overrides;$('failopen').textContent=status.fail_open;$('errors').textContent=status.errors;$('uptime').innerHTML=esc(status.uptime_seconds)+'<span class="unit">s</span>';const s=status.settings;$('settings').innerHTML=[['Default TTL',s.default_ttl+'s'],['GUI hostname',s.gui_name],['HTTP port',s.gui_port],['Rule store',s.rules_path]].map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+esc(v)+'</dd>').join('');current=rules;$('rule-count').textContent=rules.length+' rules';$('rules').innerHTML=rules.length?rules.map((rule,index)=>'<tr><td>'+esc(rule.name)+'</td><td>'+esc(rule.address)+'</td><td>'+rule.ttl+'s</td><td class="hit">'+rule.hits+'</td><td><button class="edit" data-index="'+index+'">Edit</button> <button class="delete" data-index="'+index+'" aria-label="Delete '+esc(rule.name)+'">×</button></td></tr>').join(''):'<tr><td class="empty" colspan="5">No overrides yet. Add one above.</td></tr>';document.querySelectorAll('.edit').forEach(button=>button.addEventListener('click',()=>{const index=Number(button.dataset.index),rule=current[index],form=$('rule-form');form.elements.index.value=index;form.elements.name.value=rule.name;form.elements.address.value=rule.address;form.elements.ttl.value=rule.ttl;form.querySelector('button[type=submit]').textContent='Save changes';form.elements.name.focus()}));document.querySelectorAll('.delete').forEach(button=>button.addEventListener('click',async()=>{try{await api('/api/rules/'+button.dataset.index,{method:'DELETE'});$('notice').textContent='Rule removed';await refresh()}catch(error){showError(error)}}));if(status.last_error)$('notice').textContent='Last error: '+status.last_error}catch(error){$('service').textContent='OFFLINE';showError(error)}}
$('rule-form').addEventListener('submit',async event=>{event.preventDefault();const form=new FormData(event.currentTarget),index=form.get('index'),body={name:form.get('name'),address:form.get('address'),ttl:form.get('ttl')?Number(form.get('ttl')):null};try{await api('/api/rules',{method:index===''?'POST':'PUT',body:JSON.stringify(index===''?body:{...body,index:Number(index)})});event.currentTarget.reset();event.currentTarget.querySelector('button[type=submit]').textContent='Add rule +';$('notice').textContent='Rule saved and active';await refresh()}catch(error){showError(error)}});refresh();setInterval(refresh,2000);
</script></body></html>"##;

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
    fn enforces_host_origin_and_validates_rule_crud() {
        let runtime = runtime();
        let mut secured = request("POST", "/api/rules", "{}");
        secured
            .headers
            .insert("host".into(), "127.0.0.1:8080".into());
        assert_eq!(
            authorize(&secured, &runtime),
            Err((403, "invalid or missing Origin"))
        );
        secured
            .headers
            .insert("origin".into(), "https://127.0.0.1:8080".into());
        assert_eq!(
            authorize(&secured, &runtime),
            Err((403, "invalid or missing Origin"))
        );
        secured
            .headers
            .insert("origin".into(), "http://127.0.0.1:8080".into());
        assert_eq!(authorize(&secured, &runtime), Ok(()));
        secured
            .headers
            .insert("host".into(), "evil.example:8080".into());
        assert_eq!(
            authorize(&secured, &runtime),
            Err((403, "invalid Host header"))
        );
        assert!(host_allowed("127.0.0.1:8080", &runtime));
        assert!(!host_allowed("evil.example:8080", &runtime));
        assert!(origin_allowed("http://localhost:8080", &runtime));
        assert!(!origin_allowed("https://localhost:8080", &runtime));
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
                    r#"{"index":0,"name":"app.example","address":"192.0.2.2","ttl":30}"#
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
        let restarted = runtime();
        assert_eq!(restarted.status()["overrides"], 0);
        assert!(DASHBOARD.contains("/api/status"));
        assert!(!DASHBOARD.contains("Forwarded upstream"));
    }
}
