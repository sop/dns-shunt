use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

const DEFAULT_TTL: u32 = 60;
pub const DEFAULT_GUI_NAME: &str = "dns-shunt.local";
pub const DEFAULT_GUI_PORT: u16 = 53080;
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_LOG_RETENTION_DAYS: u32 = 7;

#[derive(Debug, Clone)]
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub struct Config {
    pub ttl: u32,
    pub gui_name: String,
    #[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
    pub gui_port: u16,
    pub log_level: String,
    pub log_dir: Option<PathBuf>,
    pub log_retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub struct Rule {
    pub name: String,
    pub wildcard: bool,
    pub record_type: RuleType,
    pub address: Option<IpAddr>,
    pub target: Option<String>,
    pub ttl: u32,
    pub is_builtin: bool,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub enum RuleType {
    #[serde(rename = "A")]
    #[default]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "CNAME")]
    Cname,
}

#[derive(Debug)]
pub(crate) struct CompiledRules {
    rules: Vec<Rule>,
    exact_a: HashMap<String, usize>,
    exact_aaaa: HashMap<String, usize>,
    exact_cname: HashMap<String, usize>,
    wildcard_a: HashMap<String, usize>,
    wildcard_aaaa: HashMap<String, usize>,
    wildcard_cname: HashMap<String, usize>,
}

impl CompiledRules {
    pub(crate) fn new(rules: Vec<Rule>) -> Self {
        let mut exact_a = HashMap::new();
        let mut exact_aaaa = HashMap::new();
        let mut exact_cname = HashMap::new();
        let mut wildcard_a = HashMap::new();
        let mut wildcard_aaaa = HashMap::new();
        let mut wildcard_cname = HashMap::new();
        for (index, rule) in rules.iter().enumerate() {
            let map = match (rule.wildcard, rule.record_type) {
                (false, RuleType::A) => &mut exact_a,
                (false, RuleType::Aaaa) => &mut exact_aaaa,
                (false, RuleType::Cname) => &mut exact_cname,
                (true, RuleType::A) => &mut wildcard_a,
                (true, RuleType::Aaaa) => &mut wildcard_aaaa,
                (true, RuleType::Cname) => &mut wildcard_cname,
            };
            map.entry(rule.name.clone()).or_insert(index);
        }
        Self {
            rules,
            exact_a,
            exact_aaaa,
            exact_cname,
            wildcard_a,
            wildcard_aaaa,
            wildcard_cname,
        }
    }

    pub(crate) fn with_builtin(user_rules: Vec<Rule>, gui_name: &str, gui_ttl: u32) -> Self {
        let normalized = gui_name.trim_end_matches('.').to_ascii_lowercase();
        let mut all_rules = Vec::with_capacity(user_rules.len() + 2);
        all_rules.push(Rule {
            name: normalized.clone(),
            wildcard: false,
            record_type: RuleType::A,
            address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target: None,
            ttl: gui_ttl,
            is_builtin: true,
        });
        all_rules.push(Rule {
            name: normalized,
            wildcard: false,
            record_type: RuleType::Aaaa,
            address: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            target: None,
            ttl: gui_ttl,
            is_builtin: true,
        });
        all_rules.extend(user_rules);
        Self::new(all_rules)
    }

    pub(crate) fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub(crate) fn lookup_for_qtype(&self, query_name: &str, qtype: u16) -> Option<&Rule> {
        let has_exact = self.exact_cname.contains_key(query_name)
            || self.exact_a.contains_key(query_name)
            || self.exact_aaaa.contains_key(query_name);

        if has_exact {
            if let Some(&index) = self.exact_cname.get(query_name) {
                return self.rules.get(index);
            }
            return match qtype {
                1 => self
                    .exact_a
                    .get(query_name)
                    .and_then(|&i| self.rules.get(i)),
                28 => self
                    .exact_aaaa
                    .get(query_name)
                    .and_then(|&i| self.rules.get(i)),
                _ => None,
            };
        }

        for (dot, _) in query_name.match_indices('.') {
            let suffix = &query_name[dot + 1..];
            let has_wildcard = self.wildcard_cname.contains_key(suffix)
                || self.wildcard_a.contains_key(suffix)
                || self.wildcard_aaaa.contains_key(suffix);

            if has_wildcard {
                if let Some(&index) = self.wildcard_cname.get(suffix) {
                    return self.rules.get(index);
                }
                return match qtype {
                    1 => self.wildcard_a.get(suffix).and_then(|&i| self.rules.get(i)),
                    28 => self
                        .wildcard_aaaa
                        .get(suffix)
                        .and_then(|&i| self.rules.get(i)),
                    _ => None,
                };
            }
        }

        None
    }

    #[allow(dead_code)]
    pub(crate) fn lookup_exact_for_qtype(&self, query_name: &str, qtype: u16) -> Option<&Rule> {
        let has_exact = self.exact_cname.contains_key(query_name)
            || self.exact_a.contains_key(query_name)
            || self.exact_aaaa.contains_key(query_name);

        if !has_exact {
            return None;
        }

        if let Some(&index) = self.exact_cname.get(query_name) {
            return self.rules.get(index);
        }

        match qtype {
            1 => self
                .exact_a
                .get(query_name)
                .and_then(|&i| self.rules.get(i)),
            28 => self
                .exact_aaaa
                .get(query_name)
                .and_then(|&i| self.rules.get(i)),
            _ => None,
        }
    }

    pub(crate) fn lookup_cname(&self, query_name: &str) -> Option<&Rule> {
        let has_exact = self.exact_cname.contains_key(query_name)
            || self.exact_a.contains_key(query_name)
            || self.exact_aaaa.contains_key(query_name);

        if has_exact {
            return self
                .exact_cname
                .get(query_name)
                .and_then(|&i| self.rules.get(i));
        }

        for (dot, _) in query_name.match_indices('.') {
            let suffix = &query_name[dot + 1..];
            let has_wildcard = self.wildcard_cname.contains_key(suffix)
                || self.wildcard_a.contains_key(suffix)
                || self.wildcard_aaaa.contains_key(suffix);

            if has_wildcard {
                return self
                    .wildcard_cname
                    .get(suffix)
                    .and_then(|&i| self.rules.get(i));
            }
        }

        None
    }

    pub(crate) fn lookup_normalized(&self, query_name: &str) -> Option<&Rule> {
        if let Some(&index) = self.exact_cname.get(query_name) {
            return self.rules.get(index);
        }
        if let Some(&index) = self.exact_a.get(query_name) {
            return self.rules.get(index);
        }
        if let Some(&index) = self.exact_aaaa.get(query_name) {
            return self.rules.get(index);
        }
        for (dot, _) in query_name.match_indices('.') {
            let suffix = &query_name[dot + 1..];
            if let Some(&index) = self.wildcard_cname.get(suffix) {
                return self.rules.get(index);
            }
            if let Some(&index) = self.wildcard_a.get(suffix) {
                return self.rules.get(index);
            }
            if let Some(&index) = self.wildcard_aaaa.get(suffix) {
                return self.rules.get(index);
            }
        }
        None
    }

    pub(crate) fn lookup_exact(&self, query_name: &str) -> Option<&Rule> {
        let index = self
            .exact_cname
            .get(query_name)
            .or_else(|| self.exact_a.get(query_name))
            .or_else(|| self.exact_aaaa.get(query_name))?;
        self.rules.get(*index)
    }

    #[cfg(test)]
    fn lookup(&self, query_name: &str) -> Option<&Rule> {
        let name = query_name.trim_end_matches('.').to_ascii_lowercase();
        self.lookup_normalized(&name)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub struct RuleInput {
    pub name: String,
    #[serde(rename = "type", default)]
    pub record_type: Option<RuleType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default = "default_gui_name")]
    gui_name: String,
    #[serde(default = "default_gui_port")]
    gui_port: u16,
    #[serde(default = "default_log_level")]
    log_level: String,
    #[serde(default)]
    log_dir: Option<PathBuf>,
    #[serde(default = "default_log_retention_days")]
    log_retention_days: u32,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("default TTL must be between 1 and 86400 seconds")]
    DefaultTtl,
    #[error("invalid GUI DNS name: {0}")]
    GuiName(String),
    #[error("GUI HTTP port cannot be zero")]
    GuiPort,
    #[error("invalid log level: {0}")]
    InvalidLogLevel(String),
    #[error("invalid rule address for {0}")]
    RuleAddress(String),
    #[error("invalid CNAME target for {0}")]
    RuleTarget(String),
    #[error("invalid DNS name or wildcard syntax: {0}")]
    RuleName(String),
    #[error("rule TTL for {0} must be between 1 and 86400 seconds")]
    RuleTtl(String),
    #[error("duplicate, conflicting, or reserved rule: {0}")]
    Conflict(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text)?;
        validate_ttl(raw.ttl).map_err(|_| ConfigError::DefaultTtl)?;
        let (gui_name, wildcard) = canonical_rule_name(&raw.gui_name)
            .map_err(|_| ConfigError::GuiName(raw.gui_name.clone()))?;
        if wildcard {
            return Err(ConfigError::GuiName(raw.gui_name));
        }
        if raw.gui_port == 0 {
            return Err(ConfigError::GuiPort);
        }

        let log_level = raw.log_level.trim().to_ascii_lowercase();
        validate_log_level(&log_level).map_err(|_| ConfigError::InvalidLogLevel(raw.log_level))?;

        Ok(Self {
            ttl: raw.ttl,
            gui_name,
            gui_port: raw.gui_port,
            log_level,
            log_dir: raw.log_dir,
            log_retention_days: raw.log_retention_days,
        })
    }

    #[allow(dead_code)]
    pub fn gui_url(&self) -> String {
        format!("http://{}:{}", self.gui_name, self.gui_port)
    }
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn validate_rules(
    inputs: Vec<RuleInput>,
    reserved_name: &str,
    default_ttl: u32,
) -> Result<Vec<Rule>, ConfigError> {
    let mut rules = Vec::with_capacity(inputs.len());
    let mut seen: HashMap<(String, bool), HashSet<RuleType>> = HashMap::new();
    for input in inputs {
        let (name, wildcard) = canonical_rule_name(&input.name)?;
        if !wildcard && name == reserved_name {
            return Err(ConfigError::Conflict(input.name));
        }
        let record_type = match input.record_type {
            Some(record_type) => record_type,
            None => {
                if let Some(address_str) = &input.address {
                    if address_str.parse::<Ipv6Addr>().is_ok() {
                        RuleType::Aaaa
                    } else {
                        RuleType::A
                    }
                } else if input.target.is_some() {
                    RuleType::Cname
                } else {
                    RuleType::A
                }
            }
        };
        let key = (name.clone(), wildcard);
        if let Some(types) = seen.get(&key)
            && (types.contains(&RuleType::Cname)
                || record_type == RuleType::Cname
                || types.contains(&record_type))
        {
            return Err(ConfigError::Conflict(input.name));
        }
        seen.entry(key).or_default().insert(record_type);

        let (address, target) = match record_type {
            RuleType::A => {
                if input.target.is_some() {
                    return Err(ConfigError::Conflict(input.name));
                }
                let address = input
                    .address
                    .as_deref()
                    .ok_or_else(|| ConfigError::RuleAddress(input.name.clone()))?;
                (
                    Some(IpAddr::V4(
                        Ipv4Addr::from_str(address)
                            .map_err(|_| ConfigError::RuleAddress(input.name.clone()))?,
                    )),
                    None,
                )
            }
            RuleType::Aaaa => {
                if input.target.is_some() {
                    return Err(ConfigError::Conflict(input.name));
                }
                let address = input
                    .address
                    .as_deref()
                    .ok_or_else(|| ConfigError::RuleAddress(input.name.clone()))?;
                (
                    Some(IpAddr::V6(
                        Ipv6Addr::from_str(address)
                            .map_err(|_| ConfigError::RuleAddress(input.name.clone()))?,
                    )),
                    None,
                )
            }
            RuleType::Cname => {
                if input.address.is_some() {
                    return Err(ConfigError::Conflict(input.name));
                }
                let raw_target = input
                    .target
                    .as_deref()
                    .ok_or_else(|| ConfigError::RuleTarget(input.name.clone()))?;
                let (target, wildcard_target) = canonical_rule_name(raw_target)
                    .map_err(|_| ConfigError::RuleTarget(input.name.clone()))?;
                if wildcard_target {
                    return Err(ConfigError::RuleTarget(input.name));
                }
                (None, Some(target))
            }
        };
        let ttl = input.ttl.unwrap_or(default_ttl);
        validate_ttl(ttl).map_err(|_| ConfigError::RuleTtl(input.name.clone()))?;
        rules.push(Rule {
            name,
            wildcard,
            record_type,
            address,
            target,
            ttl,
            is_builtin: false,
        });
    }
    rules.sort_by(compare_rules);
    validate_cname_cycles(&rules, reserved_name)?;
    Ok(rules)
}

fn validate_cname_cycles(rules: &[Rule], reserved_name: &str) -> Result<(), ConfigError> {
    let compiled = CompiledRules::new(rules.to_vec());
    for rule in rules
        .iter()
        .filter(|rule| rule.record_type == RuleType::Cname)
    {
        let mut name = rule.target.as_deref().expect("validated CNAME target");
        let mut visited = HashSet::new();
        loop {
            if name == reserved_name {
                break;
            }
            if !visited.insert(name.to_owned()) {
                return Err(ConfigError::Conflict(rule.name.clone()));
            }
            let Some(next) = compiled.lookup_cname(name) else {
                break;
            };
            if next.record_type != RuleType::Cname {
                break;
            }
            name = next.target.as_deref().expect("validated CNAME target");
            if visited.contains(name) {
                return Err(ConfigError::Conflict(rule.name.clone()));
            }
        }
    }
    Ok(())
}

fn compare_rules(left: &Rule, right: &Rule) -> std::cmp::Ordering {
    left.name
        .split('.')
        .rev()
        .cmp(right.name.split('.').rev())
        .then_with(|| left.wildcard.cmp(&right.wildcard))
        .then_with(|| left.record_type.cmp(&right.record_type))
}

#[allow(dead_code)]
pub fn lookup_rule<'a>(rules: &'a [Rule], query_name: &str) -> Option<&'a Rule> {
    let name = query_name.trim_end_matches('.').to_ascii_lowercase();
    rules
        .iter()
        .find(|rule| !rule.wildcard && rule.name == name)
        .or_else(|| {
            rules
                .iter()
                .filter(|rule| rule.wildcard && name.len() > rule.name.len())
                .filter(|rule| {
                    name.ends_with(&rule.name)
                        && name.as_bytes().get(name.len() - rule.name.len() - 1) == Some(&b'.')
                })
                .max_by_key(|rule| rule.name.len())
        })
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn rule_input(rule: &Rule) -> RuleInput {
    RuleInput {
        name: if rule.wildcard {
            format!("*.{}", rule.name)
        } else {
            rule.name.clone()
        },
        record_type: Some(rule.record_type),
        address: rule.address.map(|address| address.to_string()),
        target: rule.target.clone(),
        ttl: Some(rule.ttl),
    }
}

fn canonical_rule_name(input: &str) -> Result<(String, bool), ConfigError> {
    if input.ends_with("..") {
        return Err(ConfigError::RuleName(input.to_owned()));
    }
    let (name, wildcard) = match input.strip_prefix("*.") {
        Some(name) => (name, true),
        None if input.contains('*') => {
            return Err(ConfigError::RuleName(input.to_owned()));
        }
        None => (input, false),
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ConfigError::RuleName(input.to_owned()));
    }
    Ok((name, wildcard))
}

fn validate_ttl(ttl: u32) -> Result<(), ()> {
    if (1..=86_400).contains(&ttl) {
        Ok(())
    } else {
        Err(())
    }
}

const fn default_ttl() -> u32 {
    DEFAULT_TTL
}
fn default_gui_name() -> String {
    DEFAULT_GUI_NAME.to_owned()
}
const fn default_gui_port() -> u16 {
    DEFAULT_GUI_PORT
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_owned()
}
const fn default_log_retention_days() -> u32 {
    DEFAULT_LOG_RETENTION_DAYS
}

fn validate_log_level(level: &str) -> Result<(), ()> {
    match level {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "ttl = 120\n";

    fn inputs() -> Vec<RuleInput> {
        vec![
            RuleInput {
                name: "example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "*.example.net".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.2".into()),
                target: None,
                ttl: Some(30),
            },
        ]
    }

    fn cname_input(name: &str, target: &str) -> RuleInput {
        RuleInput {
            name: name.into(),
            record_type: Some(RuleType::Cname),
            address: None,
            target: Some(target.into()),
            ttl: None,
        }
    }

    #[test]
    fn validates_override_settings_and_gui_defaults() {
        let config = Config::parse(BASE).unwrap();
        assert_eq!(config.ttl, 120);
        assert_eq!(config.gui_name, DEFAULT_GUI_NAME);
        assert_eq!(config.gui_port, DEFAULT_GUI_PORT);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_dir, None);
        assert_eq!(config.log_retention_days, 7);
        assert_eq!(
            Config::parse(&format!(
                "{BASE}\ngui_name = \"Admin.Example.\"\ngui_port = 9090\n"
            ))
            .unwrap()
            .gui_name,
            "admin.example"
        );
    }

    #[test]
    fn parses_custom_logging_configuration() {
        let text = r#"
ttl = 120
log_level = "DEBUG"
log_dir = "C:\\CustomLogs"
log_retention_days = 14
"#;
        let config = Config::parse(text).unwrap();
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_dir, Some(PathBuf::from(r"C:\CustomLogs")));
        assert_eq!(config.log_retention_days, 14);
    }

    #[test]
    fn rejects_invalid_log_level() {
        let text = "log_level = \"verbose\"\n";
        match Config::parse(text) {
            Err(ConfigError::InvalidLogLevel(lvl)) => assert_eq!(lvl, "verbose"),
            other => panic!("expected InvalidLogLevel, got {other:?}"),
        }
    }

    #[test]
    fn builds_gui_url_from_the_validated_hostname_and_port() {
        let config = Config::parse("gui_name = \"Admin.Example.\"\ngui_port = 9090\n").unwrap();
        assert_eq!(config.gui_url(), "http://admin.example:9090");
    }

    #[test]
    fn accepts_legacy_upstream_and_source_port_as_ignored_unknown_keys() {
        let config =
            Config::parse("upstream = \"not-an-ip\"\nsource_port = 53\nttl = 120\n").unwrap();
        assert_eq!(config.ttl, 120);
        assert_eq!(config.gui_name, DEFAULT_GUI_NAME);
    }

    #[test]
    fn ignores_legacy_toml_rules_without_activating_them() {
        let config = Config::parse(&format!(
            "{BASE}\n[[rules]]\nname=\"old.example\"\naddress=\"192.0.2.9\"\n"
        ))
        .unwrap();
        assert_eq!(config.gui_port, DEFAULT_GUI_PORT);
    }

    #[test]
    fn validates_names_wildcards_duplicates_and_reserved_host() {
        let rules = validate_rules(inputs(), "dns-shunt.local", 120).unwrap();
        assert_eq!(lookup_rule(&rules, "EXAMPLE.COM.").unwrap().ttl, 120);
        assert!(lookup_rule(&rules, "www.example.net").is_some());
        assert!(lookup_rule(&rules, "example.net").is_none());
        assert!(
            validate_rules(
                vec![RuleInput {
                    name: "DNS-SHUNT.LOCAL.".into(),
                    record_type: Some(RuleType::A),
                    address: Some("127.0.0.2".into()),
                    target: None,
                    ttl: None
                }],
                "dns-shunt.local",
                60
            )
            .is_err()
        );
        let duplicates = vec![
            inputs()[0].clone(),
            RuleInput {
                name: "EXAMPLE.COM.".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.3".into()),
                target: None,
                ttl: None,
            },
        ];
        assert!(validate_rules(duplicates, "dns-shunt.local", 60).is_err());
    }

    #[test]
    fn exact_rules_precede_wildcards_and_reject_invalid_values() {
        let entries = vec![
            RuleInput {
                name: "*.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "api.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.2".into()),
                target: None,
                ttl: None,
            },
        ];
        let rules = validate_rules(entries, "dns-shunt.local", 60).unwrap();
        assert_eq!(
            lookup_rule(&rules, "api.example.com").unwrap().address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
        );
        for input in [
            RuleInput {
                name: "bad..example".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "bad*.example".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "good.example".into(),
                record_type: Some(RuleType::A),
                address: Some("not-an-ip".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "good.example".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(0),
            },
        ] {
            assert!(validate_rules(vec![input], "dns-shunt.local", 60).is_err());
        }
        assert!(Config::parse(&format!("{BASE}\ngui_name=\"*.bad.example\"\n")).is_err());
        assert!(Config::parse(&format!("{BASE}\ngui_port=0\n")).is_err());
    }

    #[test]
    fn overlapping_wildcards_match_by_specificity_in_any_input_order() {
        let parent = RuleInput {
            name: "*.example.com".into(),
            record_type: Some(RuleType::A),
            address: Some("192.0.2.1".into()),
            target: None,
            ttl: None,
        };
        let nested = RuleInput {
            name: "*.sub.example.com".into(),
            record_type: Some(RuleType::A),
            address: Some("192.0.2.2".into()),
            target: None,
            ttl: None,
        };
        let exact = RuleInput {
            name: "api.sub.example.com".into(),
            record_type: Some(RuleType::A),
            address: Some("192.0.2.3".into()),
            target: None,
            ttl: None,
        };

        for entries in [
            vec![parent.clone(), nested.clone(), exact.clone()],
            vec![nested.clone(), parent.clone(), exact.clone()],
        ] {
            let rules = validate_rules(entries, "dns-shunt.local", 60).unwrap();
            let compiled = CompiledRules::new(rules.clone());

            for query in ["www.sub.example.com", "www.sub.example.com."] {
                assert_eq!(
                    lookup_rule(&rules, query).unwrap().address,
                    Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
                );
                assert_eq!(
                    compiled.lookup(query).unwrap().address,
                    Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
                );
            }
            assert_eq!(
                lookup_rule(&rules, "www.example.com").unwrap().address,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
            );
            assert_eq!(
                compiled.lookup("www.example.com").unwrap().address,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
            );
            assert_eq!(
                lookup_rule(&rules, "api.sub.example.com").unwrap().address,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))
            );
            assert_eq!(
                compiled.lookup("api.sub.example.com").unwrap().address,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))
            );
            assert!(lookup_rule(&rules, "example.com").is_none());
            assert!(compiled.lookup("example.com").is_none());
            assert_eq!(
                compiled.lookup("sub.example.com").unwrap().address,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
            );
        }

        assert!(
            validate_rules(
                vec![
                    RuleInput {
                        name: "*.Example.com.".into(),
                        record_type: Some(RuleType::A),
                        address: Some("192.0.2.1".into()),
                        target: None,
                        ttl: None,
                    },
                    RuleInput {
                        name: "*.example.com".into(),
                        record_type: Some(RuleType::A),
                        address: Some("192.0.2.2".into()),
                        target: None,
                        ttl: None,
                    },
                ],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );
    }

    #[test]
    fn sorts_rules_by_reversed_labels_parent_then_exact_rule() {
        let entries = vec![
            RuleInput {
                name: "*.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "z.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.2".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "example.net".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.3".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.4".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "a.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.5".into()),
                target: None,
                ttl: None,
            },
        ];

        let rules = validate_rules(entries, "dns-shunt.local", 60).unwrap();
        let names = rules
            .iter()
            .map(|rule| {
                if rule.wildcard {
                    format!("*.{}", rule.name)
                } else {
                    rule.name.clone()
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "example.com",
                "*.example.com",
                "a.example.com",
                "z.example.com",
                "example.net",
            ]
        );
    }

    #[test]
    fn compiled_rules_match_exact_and_wildcard_names_by_label() {
        let entries = vec![
            RuleInput {
                name: "*.example.net".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "api.example.net".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.2".into()),
                target: None,
                ttl: None,
            },
            RuleInput {
                name: "*.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.3".into()),
                target: None,
                ttl: None,
            },
        ];
        let rules = CompiledRules::new(validate_rules(entries, "dns-shunt.local", 60).unwrap());

        assert_eq!(
            rules.lookup_normalized("api.example.net").unwrap().address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
        );
        assert_eq!(
            rules.lookup_normalized("a.b.example.net").unwrap().address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert!(rules.lookup_normalized("example.net").is_none());
        assert!(rules.lookup_normalized("notexample.net").is_none());
        assert_eq!(
            rules.lookup("WWW.EXAMPLE.COM.").unwrap().address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))
        );
        assert!(lookup_rule(rules.rules(), "API.EXAMPLE.NET.").is_some());
    }

    #[test]
    fn accepts_legacy_a_rules_and_serializes_canonical_typed_rules() {
        let legacy: RuleInput =
            serde_json::from_str(r#"{"name":"legacy.example","address":"192.0.2.8","ttl":42}"#)
                .unwrap();
        let rules = validate_rules(vec![legacy], "dns-shunt.local", 60).unwrap();
        assert_eq!(rules[0].record_type, RuleType::A);
        assert_eq!(
            rules[0].address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)))
        );
        let stored = serde_json::to_value(rule_input(&rules[0])).unwrap();
        assert_eq!(stored["type"], "A");
        assert_eq!(stored["address"], "192.0.2.8");

        let cname = validate_rules(
            vec![cname_input("*.example.local", "example.local.")],
            "dns-shunt.local",
            60,
        )
        .unwrap();
        assert_eq!(cname[0].target.as_deref(), Some("example.local"));
        let stored = serde_json::to_value(rule_input(&cname[0])).unwrap();
        assert_eq!(stored["type"], "CNAME");
        assert_eq!(stored["target"], "example.local");
        assert!(stored.get("address").is_none());
    }

    #[test]
    fn validates_cname_targets_and_rejects_compiled_cycles() {
        for invalid in [
            cname_input("alias.example", "*.target.example"),
            RuleInput {
                name: "alias.example".into(),
                record_type: Some(RuleType::Cname),
                address: Some("192.0.2.1".into()),
                target: Some("target.example".into()),
                ttl: None,
            },
            RuleInput {
                name: "alias.example".into(),
                record_type: Some(RuleType::Cname),
                address: None,
                target: None,
                ttl: None,
            },
        ] {
            assert!(validate_rules(vec![invalid], "dns-shunt.local", 60).is_err());
        }

        for entries in [
            vec![cname_input("a.example", "a.example")],
            vec![
                cname_input("a.example", "b.example"),
                cname_input("b.example", "a.example"),
            ],
            vec![cname_input("*.example", "host.example")],
        ] {
            assert!(validate_rules(entries, "dns-shunt.local", 60).is_err());
        }
        let shadowed = validate_rules(
            vec![
                cname_input("*.example", "host.example"),
                RuleInput {
                    name: "host.example".into(),
                    record_type: Some(RuleType::A),
                    address: Some("192.0.2.10".into()),
                    target: None,
                    ttl: None,
                },
            ],
            "dns-shunt.local",
            60,
        );
        assert!(shadowed.is_ok());
    }

    #[test]
    fn compiled_rules_with_builtin_precedes_wildcards_and_normalizes() {
        let user_rules = validate_rules(
            vec![
                RuleInput {
                    name: "*.local".into(),
                    record_type: Some(RuleType::A),
                    address: Some("192.0.2.1".into()),
                    target: None,
                    ttl: Some(30),
                },
                RuleInput {
                    name: "*.dns-shunt.local".into(),
                    record_type: Some(RuleType::A),
                    address: Some("192.0.2.2".into()),
                    target: None,
                    ttl: Some(30),
                },
            ],
            "dns-shunt.local",
            60,
        )
        .unwrap();

        let compiled = CompiledRules::with_builtin(user_rules, "DNS-SHUNT.LOCAL.", 45);
        let rule_a = compiled.lookup_for_qtype("dns-shunt.local", 1).unwrap();
        assert!(rule_a.is_builtin);
        assert_eq!(rule_a.name, "dns-shunt.local");
        assert_eq!(rule_a.record_type, RuleType::A);
        assert_eq!(rule_a.address, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(rule_a.ttl, 45);

        let rule_aaaa = compiled.lookup_for_qtype("dns-shunt.local", 28).unwrap();
        assert!(rule_aaaa.is_builtin);
        assert_eq!(rule_aaaa.name, "dns-shunt.local");
        assert_eq!(rule_aaaa.record_type, RuleType::Aaaa);
        assert_eq!(rule_aaaa.address, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(rule_aaaa.ttl, 45);

        let other = compiled.lookup_normalized("other.local").unwrap();
        assert!(!other.is_builtin);
        assert_eq!(other.address, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn a_and_aaaa_coexist_on_same_name_and_wildcard() {
        let entries = vec![
            RuleInput {
                name: "dual.example.com".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "dual.example.com".into(),
                record_type: Some(RuleType::Aaaa),
                address: Some("2001:db8::1".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "*.dual.example.net".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.2".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "*.dual.example.net".into(),
                record_type: Some(RuleType::Aaaa),
                address: Some("2001:db8::2".into()),
                target: None,
                ttl: Some(60),
            },
        ];
        let rules = validate_rules(entries, "dns-shunt.local", 60).unwrap();
        assert_eq!(rules.len(), 4);
        let compiled = CompiledRules::new(rules);

        let a_match = compiled.lookup_for_qtype("dual.example.com", 1).unwrap();
        assert_eq!(a_match.record_type, RuleType::A);
        assert_eq!(
            a_match.address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );

        let aaaa_match = compiled.lookup_for_qtype("dual.example.com", 28).unwrap();
        assert_eq!(aaaa_match.record_type, RuleType::Aaaa);
        assert_eq!(
            aaaa_match.address,
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );

        let sub_a = compiled
            .lookup_for_qtype("sub.dual.example.net", 1)
            .unwrap();
        assert_eq!(sub_a.record_type, RuleType::A);
        assert_eq!(sub_a.address, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));

        let sub_aaaa = compiled
            .lookup_for_qtype("sub.dual.example.net", 28)
            .unwrap();
        assert_eq!(sub_aaaa.record_type, RuleType::Aaaa);
        assert_eq!(
            sub_aaaa.address,
            Some(IpAddr::V6("2001:db8::2".parse().unwrap()))
        );

        // lookup_exact_for_qtype matches exact domain, but not wildcards
        assert_eq!(
            compiled
                .lookup_exact_for_qtype("dual.example.com", 1)
                .unwrap()
                .record_type,
            RuleType::A
        );
        assert_eq!(
            compiled
                .lookup_exact_for_qtype("dual.example.com", 28)
                .unwrap()
                .record_type,
            RuleType::Aaaa
        );
        assert!(
            compiled
                .lookup_exact_for_qtype("sub.dual.example.net", 1)
                .is_none()
        );
        assert!(
            compiled
                .lookup_exact_for_qtype("sub.dual.example.net", 28)
                .is_none()
        );
    }

    #[test]
    fn rejects_conflicting_record_types_and_duplicates() {
        // Duplicate A
        assert!(
            validate_rules(
                vec![
                    RuleInput {
                        name: "dup.example".into(),
                        record_type: Some(RuleType::A),
                        address: Some("192.0.2.1".into()),
                        target: None,
                        ttl: None,
                    },
                    RuleInput {
                        name: "dup.example".into(),
                        record_type: Some(RuleType::A),
                        address: Some("192.0.2.2".into()),
                        target: None,
                        ttl: None,
                    },
                ],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );

        // Duplicate AAAA
        assert!(
            validate_rules(
                vec![
                    RuleInput {
                        name: "dup.example".into(),
                        record_type: Some(RuleType::Aaaa),
                        address: Some("2001:db8::1".into()),
                        target: None,
                        ttl: None,
                    },
                    RuleInput {
                        name: "dup.example".into(),
                        record_type: Some(RuleType::Aaaa),
                        address: Some("2001:db8::2".into()),
                        target: None,
                        ttl: None,
                    },
                ],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );

        // CNAME with A
        assert!(
            validate_rules(
                vec![
                    cname_input("cname.example", "target.example"),
                    RuleInput {
                        name: "cname.example".into(),
                        record_type: Some(RuleType::A),
                        address: Some("192.0.2.1".into()),
                        target: None,
                        ttl: None,
                    },
                ],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );

        // A with CNAME
        assert!(
            validate_rules(
                vec![
                    RuleInput {
                        name: "cname.example".into(),
                        record_type: Some(RuleType::A),
                        address: Some("192.0.2.1".into()),
                        target: None,
                        ttl: None,
                    },
                    cname_input("cname.example", "target.example"),
                ],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );

        // CNAME with AAAA
        assert!(
            validate_rules(
                vec![
                    cname_input("cname.example", "target.example"),
                    RuleInput {
                        name: "cname.example".into(),
                        record_type: Some(RuleType::Aaaa),
                        address: Some("2001:db8::1".into()),
                        target: None,
                        ttl: None,
                    },
                ],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );

        // AAAA with invalid address (IPv4 for AAAA)
        assert!(
            validate_rules(
                vec![RuleInput {
                    name: "invalid.example".into(),
                    record_type: Some(RuleType::Aaaa),
                    address: Some("192.0.2.1".into()),
                    target: None,
                    ttl: None,
                }],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );

        // A with invalid address (IPv6 for A)
        assert!(
            validate_rules(
                vec![RuleInput {
                    name: "invalid.example".into(),
                    record_type: Some(RuleType::A),
                    address: Some("2001:db8::1".into()),
                    target: None,
                    ttl: None,
                }],
                "dns-shunt.local",
                60,
            )
            .is_err()
        );
    }

    #[test]
    fn infers_aaaa_from_ipv6_address_when_type_omitted() {
        let json = r#"{"name":"ipv6.example","address":"2001:db8::99","ttl":30}"#;
        let input: RuleInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.record_type, None);
        let rules = validate_rules(vec![input], "dns-shunt.local", 60).unwrap();
        assert_eq!(rules[0].record_type, RuleType::Aaaa);
        assert_eq!(
            rules[0].address,
            Some(IpAddr::V6("2001:db8::99".parse().unwrap()))
        );
        let serialized = serde_json::to_value(rule_input(&rules[0])).unwrap();
        assert_eq!(serialized["type"], "AAAA");
        assert_eq!(serialized["address"], "2001:db8::99");
    }
}
