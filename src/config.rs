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

/// Per-name rule slots. Each slot holds the index of the first rule for that
/// (name, type), so duplicate names keep first-wins semantics.
#[derive(Debug, Default)]
struct RuleSlots {
    a: Option<usize>,
    aaaa: Option<usize>,
    cname: Option<usize>,
}

impl RuleSlots {
    fn slot_mut(&mut self, record_type: RuleType) -> &mut Option<usize> {
        match record_type {
            RuleType::A => &mut self.a,
            RuleType::Aaaa => &mut self.aaaa,
            RuleType::Cname => &mut self.cname,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CompiledRules {
    rules: Vec<Rule>,
    exact: HashMap<String, RuleSlots>,
    wildcard: HashMap<String, RuleSlots>,
    /// Largest label count of any wildcard base name (`*.example.com` -> 2).
    /// Suffixes with more labels than this can never match a wildcard.
    max_wildcard_base_labels: usize,
}

fn label_count(name: &str) -> usize {
    name.split('.').count()
}

impl CompiledRules {
    pub(crate) fn new(rules: Vec<Rule>) -> Self {
        let mut exact: HashMap<String, RuleSlots> = HashMap::new();
        let mut wildcard: HashMap<String, RuleSlots> = HashMap::new();
        let mut max_wildcard_base_labels = 0;
        for (index, rule) in rules.iter().enumerate() {
            let map = if rule.wildcard {
                max_wildcard_base_labels = max_wildcard_base_labels.max(label_count(&rule.name));
                &mut wildcard
            } else {
                &mut exact
            };
            let slot = map
                .entry(rule.name.clone())
                .or_default()
                .slot_mut(rule.record_type);
            slot.get_or_insert(index);
        }
        Self {
            rules,
            exact,
            wildcard,
            max_wildcard_base_labels,
        }
    }

    fn rule_at(&self, index: Option<usize>) -> Option<&Rule> {
        index.and_then(|index| self.rules.get(index))
    }

    /// Returns the closest wildcard entry for `query_name`, walking suffixes
    /// from longest to shortest. Only strict subdomains are considered.
    fn closest_wildcard(&self, query_name: &str) -> Option<&RuleSlots> {
        if self.wildcard.is_empty() {
            return None;
        }
        // A suffix with `k` labels is a wildcard candidate only when
        // `k <= max_wildcard_base_labels`. The candidate suffixes are the
        // ones starting after the rightmost `max_wildcard_base_labels` dots.
        // Find the leftmost of those dots by scanning from the right.
        let max = self.max_wildcard_base_labels;
        let mut from = query_name.len();
        let mut seen = 0;
        for (dot, _) in query_name.rmatch_indices('.') {
            from = dot;
            seen += 1;
            if seen == max {
                break;
            }
        }
        if seen < max {
            // Fewer dots than the bound: every suffix is a candidate, so
            // start at the first dot.
            from = query_name.find('.')?;
        }
        for (dot, _) in query_name[from..].match_indices('.') {
            let suffix = &query_name[from + dot + 1..];
            if let Some(entry) = self.wildcard.get(suffix) {
                return Some(entry);
            }
        }
        None
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

    /// Resolves a single-answer lookup. An exact entry for the name (of any
    /// type) shadows wildcards entirely; otherwise the closest wildcard entry
    /// applies. Within an entry, CNAME takes precedence over A/AAAA.
    pub(crate) fn lookup_for_qtype(&self, query_name: &str, qtype: u16) -> Option<&Rule> {
        if let Some(slots) = self.exact.get(query_name) {
            return self.typed_for_qtype(slots, qtype);
        }
        self.closest_wildcard(query_name)
            .and_then(|slots| self.typed_for_qtype(slots, qtype))
    }

    pub(crate) fn lookup_exact_for_qtype(&self, query_name: &str, qtype: u16) -> Option<&Rule> {
        self.exact
            .get(query_name)
            .and_then(|slots| self.typed_for_qtype(slots, qtype))
    }

    fn typed_for_qtype(&self, slots: &RuleSlots, qtype: u16) -> Option<&Rule> {
        if let Some(rule) = self.rule_at(slots.cname) {
            return Some(rule);
        }
        match qtype {
            1 => self.rule_at(slots.a),
            28 => self.rule_at(slots.aaaa),
            _ => None,
        }
    }

    /// Returns the rules answering an mDNS query. `query_name` must already be
    /// normalized (lowercase, no trailing dot), as produced by `mdns::parse_name`.
    pub(crate) fn lookup_for_mdns(&self, query_name: &str, qtype: u16) -> Vec<&Rule> {
        match qtype {
            1 | 28 => self
                .lookup_for_qtype(query_name, qtype)
                .into_iter()
                .collect(),
            5 => self.lookup_cname(query_name).into_iter().collect(),
            255 => {
                let slots = match self.exact.get(query_name) {
                    Some(slots) => Some(slots),
                    None => self.closest_wildcard(query_name),
                };
                match slots {
                    Some(slots) => self.any_for_slots(slots),
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }

    /// Every rule for one name: CNAME alone when present, otherwise A and AAAA.
    fn any_for_slots(&self, slots: &RuleSlots) -> Vec<&Rule> {
        if let Some(rule) = self.rule_at(slots.cname) {
            return vec![rule];
        }
        [slots.a, slots.aaaa]
            .into_iter()
            .filter_map(|index| self.rule_at(index))
            .collect()
    }

    /// Returns the CNAME rule for the closest matching name, if any. Stops at
    /// the first wildcard suffix that has any entry, even when it has no CNAME.
    pub(crate) fn lookup_cname(&self, query_name: &str) -> Option<&Rule> {
        if let Some(slots) = self.exact.get(query_name) {
            return self.rule_at(slots.cname);
        }
        self.closest_wildcard(query_name)
            .and_then(|slots| self.rule_at(slots.cname))
    }

    /// Ungated lookup: exact CNAME, A, AAAA, then per wildcard suffix CNAME,
    /// A, AAAA, returning the first hit. Unlike `lookup_for_qtype`, it does
    /// not stop at an exact entry that lacks a hit, so it can fall through to
    /// wildcards.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lookup_normalized(&self, query_name: &str) -> Option<&Rule> {
        if let Some(slots) = self.exact.get(query_name) {
            let hit = [slots.cname, slots.a, slots.aaaa]
                .into_iter()
                .find_map(|index| self.rule_at(index));
            if hit.is_some() {
                return hit;
            }
        }
        for (dot, _) in query_name.match_indices('.') {
            let suffix = &query_name[dot + 1..];
            if let Some(slots) = self.wildcard.get(suffix) {
                let hit = [slots.cname, slots.a, slots.aaaa]
                    .into_iter()
                    .find_map(|index| self.rule_at(index));
                if hit.is_some() {
                    return hit;
                }
            }
        }
        None
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
    fn lookup_for_mdns_supported_types() {
        let entries = vec![
            RuleInput {
                name: "dual.example.local".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.1".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "dual.example.local".into(),
                record_type: Some(RuleType::Aaaa),
                address: Some("2001:db8::1".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "*.wild.example.local".into(),
                record_type: Some(RuleType::A),
                address: Some("192.0.2.2".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "*.wild.example.local".into(),
                record_type: Some(RuleType::Aaaa),
                address: Some("2001:db8::2".into()),
                target: None,
                ttl: Some(60),
            },
            RuleInput {
                name: "alias.example.local".into(),
                record_type: Some(RuleType::Cname),
                address: None,
                target: Some("dual.example.local".into()),
                ttl: Some(60),
            },
        ];
        let rules = validate_rules(entries, "dns-shunt.local", 60).unwrap();
        let compiled = CompiledRules::with_builtin(rules, "dns-shunt.local", 60);

        // QTYPE 1 (A)
        let res_a = compiled.lookup_for_mdns("dual.example.local", 1);
        assert_eq!(res_a.len(), 1);
        assert_eq!(res_a[0].record_type, RuleType::A);

        // QTYPE 28 (AAAA)
        let res_aaaa = compiled.lookup_for_mdns("dual.example.local", 28);
        assert_eq!(res_aaaa.len(), 1);
        assert_eq!(res_aaaa[0].record_type, RuleType::Aaaa);

        // QTYPE 5 (CNAME)
        let res_cname = compiled.lookup_for_mdns("alias.example.local", 5);
        assert_eq!(res_cname.len(), 1);
        assert_eq!(res_cname[0].record_type, RuleType::Cname);

        let res_no_cname = compiled.lookup_for_mdns("dual.example.local", 5);
        assert!(res_no_cname.is_empty());

        // QTYPE 255 (ANY) for exact dual-stack
        let res_any = compiled.lookup_for_mdns("dual.example.local", 255);
        assert_eq!(res_any.len(), 2);
        assert!(res_any.iter().any(|r| r.record_type == RuleType::A));
        assert!(res_any.iter().any(|r| r.record_type == RuleType::Aaaa));

        // QTYPE 255 (ANY) for CNAME
        let res_any_cname = compiled.lookup_for_mdns("alias.example.local", 255);
        assert_eq!(res_any_cname.len(), 1);
        assert_eq!(res_any_cname[0].record_type, RuleType::Cname);

        // QTYPE 255 (ANY) for wildcard
        let res_any_wild = compiled.lookup_for_mdns("sub.wild.example.local", 255);
        assert_eq!(res_any_wild.len(), 2);
        assert!(res_any_wild.iter().any(|r| r.record_type == RuleType::A));
        assert!(res_any_wild.iter().any(|r| r.record_type == RuleType::Aaaa));

        // QTYPE 255 (ANY) for builtin gui_name
        let res_any_gui = compiled.lookup_for_mdns("dns-shunt.local", 255);
        assert_eq!(res_any_gui.len(), 2);
        assert!(res_any_gui.iter().all(|r| r.is_builtin));

        // Unsupported QTYPE (e.g. MX 15, TXT 16)
        let res_txt = compiled.lookup_for_mdns("dual.example.local", 16);
        assert!(res_txt.is_empty());
    }

    fn char_input(name: &str, record_type: RuleType, value: &str) -> RuleInput {
        let (address, target) = match record_type {
            RuleType::Cname => (None, Some(value.to_owned())),
            _ => (Some(value.to_owned()), None),
        };
        RuleInput {
            name: name.into(),
            record_type: Some(record_type),
            address,
            target,
            ttl: Some(60),
        }
    }

    fn compile_characterization(entries: Vec<RuleInput>) -> CompiledRules {
        CompiledRules::new(validate_rules(entries, "dns-shunt.local", 60).unwrap())
    }

    // Validation rejects duplicate names and mixed CNAME/A on one name, so
    // precedence tests build the compiled form from raw rules directly.
    fn raw_rule(name: &str, record_type: RuleType, wildcard: bool, value: &str) -> Rule {
        let (address, target) = match record_type {
            RuleType::Cname => (None, Some(value.to_owned())),
            _ => (Some(value.parse().unwrap()), None),
        };
        Rule {
            name: name.to_owned(),
            wildcard,
            record_type,
            address,
            target,
            ttl: 60,
            is_builtin: false,
        }
    }

    #[test]
    fn exact_aaaa_rule_blocks_wildcard_a_for_same_name() {
        let compiled = compile_characterization(vec![
            char_input("*.example.com", RuleType::A, "192.0.2.1"),
            char_input("a.b.example.com", RuleType::Aaaa, "2001:db8::1"),
        ]);
        // Exact name present for AAAA shadows the wildcard A for every qtype.
        assert!(compiled.lookup_for_qtype("a.b.example.com", 1).is_none());
        assert!(compiled.lookup_for_qtype("a.b.example.com", 28).is_some());
        assert!(compiled.lookup_for_mdns("a.b.example.com", 1).is_empty());
    }

    #[test]
    fn exact_cname_shadows_exact_a_and_aaaa() {
        let compiled = CompiledRules::new(vec![
            raw_rule("alias.example.com", RuleType::A, false, "192.0.2.1"),
            raw_rule("alias.example.com", RuleType::Aaaa, false, "2001:db8::1"),
            raw_rule("alias.example.com", RuleType::Cname, false, "t.example.net"),
        ]);
        for qtype in [1u16, 28, 255] {
            let rule = compiled.lookup_for_qtype("alias.example.com", qtype);
            if qtype == 255 {
                continue;
            }
            assert_eq!(rule.unwrap().record_type, RuleType::Cname);
        }
        let any = compiled.lookup_for_mdns("alias.example.com", 255);
        assert_eq!(any.len(), 1);
        assert_eq!(any[0].record_type, RuleType::Cname);
        assert_eq!(
            compiled
                .lookup_cname("alias.example.com")
                .unwrap()
                .record_type,
            RuleType::Cname
        );
    }

    #[test]
    fn closest_wildcard_wins_over_outer_wildcard() {
        let compiled = compile_characterization(vec![
            char_input("*.example.com", RuleType::A, "192.0.2.1"),
            char_input("*.b.example.com", RuleType::A, "192.0.2.2"),
        ]);
        let rule = compiled.lookup_for_qtype("a.b.example.com", 1).unwrap();
        assert_eq!(rule.name, "b.example.com");
        assert_eq!(rule.address, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        let outer = compiled.lookup_for_qtype("x.example.com", 1).unwrap();
        assert_eq!(outer.name, "example.com");
        assert_eq!(outer.address, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn wildcard_does_not_match_its_own_base_name() {
        let compiled =
            compile_characterization(vec![char_input("*.example.com", RuleType::A, "192.0.2.1")]);
        assert!(compiled.lookup_for_qtype("example.com", 1).is_none());
        assert!(compiled.lookup_for_qtype("example.com", 255).is_none());
        assert!(compiled.lookup_for_mdns("example.com", 255).is_empty());
        assert!(compiled.lookup_cname("example.com").is_none());
        assert!(compiled.lookup_for_qtype("sub.example.com", 1).is_some());
    }

    #[test]
    fn deep_query_matches_shallow_wildcard_base() {
        let compiled =
            compile_characterization(vec![char_input("*.com", RuleType::A, "192.0.2.1")]);
        let rule = compiled.lookup_for_qtype("a.b.c.d.example.com", 1);
        assert_eq!(rule.unwrap().name, "com");
        assert!(compiled.lookup_for_qtype("com", 1).is_none());
    }

    #[test]
    fn no_wildcard_rules_is_exact_only() {
        let compiled = compile_characterization(vec![char_input(
            "only.example.com",
            RuleType::A,
            "192.0.2.1",
        )]);
        assert!(compiled.lookup_for_qtype("x.only.example.com", 1).is_none());
        assert!(compiled.lookup_for_qtype("only.example.com", 1).is_some());
        assert!(
            compiled
                .lookup_for_mdns("x.only.example.com", 255)
                .is_empty()
        );
        assert!(compiled.lookup_cname("x.only.example.com").is_none());
    }

    #[test]
    fn lookup_cname_stops_at_first_wildcard_suffix_without_cname() {
        let compiled = compile_characterization(vec![
            char_input("*.b.example.com", RuleType::A, "192.0.2.2"),
            char_input("*.example.com", RuleType::Cname, "t.example.net"),
        ]);
        // Closest suffix has a wildcard A but no CNAME: the walk stops there.
        assert!(compiled.lookup_cname("a.b.example.com").is_none());
        assert_eq!(
            compiled.lookup_cname("a.example.com").unwrap().record_type,
            RuleType::Cname
        );
    }

    #[test]
    fn duplicate_names_first_rule_wins_per_type() {
        let compiled = CompiledRules::new(vec![
            raw_rule("dup.example.com", RuleType::A, false, "192.0.2.1"),
            raw_rule("dup.example.com", RuleType::A, false, "192.0.2.9"),
            raw_rule("wd.example.com", RuleType::Aaaa, true, "2001:db8::1"),
            raw_rule("wd.example.com", RuleType::Aaaa, true, "2001:db8::9"),
        ]);
        assert_eq!(
            compiled
                .lookup_for_qtype("dup.example.com", 1)
                .unwrap()
                .address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            compiled
                .lookup_for_qtype("x.wd.example.com", 28)
                .unwrap()
                .address,
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
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
