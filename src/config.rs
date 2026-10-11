use serde::Deserialize;
use std::{collections::HashSet, fs, net::Ipv4Addr, path::Path, str::FromStr};
use thiserror::Error;

const DEFAULT_TTL: u32 = 60;

#[derive(Debug, Clone)]
pub struct Config {
    pub upstream: Ipv4Addr,
    pub source_port: u16,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub wildcard: bool,
    pub address: Ipv4Addr,
    pub ttl: u32,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    upstream: String,
    source_port: u16,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    name: String,
    address: String,
    ttl: Option<u32>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("upstream must be a fixed, non-unspecified IPv4 address")]
    Upstream,
    #[error("reserved UDP source port must be in 1024..=65535 and cannot be 53")]
    SourcePort,
    #[error("default TTL must be between 1 and 86400 seconds")]
    DefaultTtl,
    #[error("invalid rule address for {0}")]
    RuleAddress(String),
    #[error("invalid DNS name or wildcard syntax: {0}")]
    RuleName(String),
    #[error("rule TTL for {0} must be between 1 and 86400 seconds")]
    RuleTtl(String),
    #[error("duplicate or overlapping wildcard rule: {0}")]
    Conflict(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text)?;
        let upstream = Ipv4Addr::from_str(&raw.upstream).map_err(|_| ConfigError::Upstream)?;
        if upstream.is_unspecified() || upstream.is_broadcast() || upstream.is_multicast() {
            return Err(ConfigError::Upstream);
        }
        if raw.source_port < 1024 || raw.source_port == 53 {
            return Err(ConfigError::SourcePort);
        }
        validate_ttl(raw.ttl).map_err(|_| ConfigError::DefaultTtl)?;

        let mut rules = Vec::with_capacity(raw.rules.len());
        let mut seen = HashSet::new();
        for raw_rule in raw.rules {
            let (name, wildcard) = canonical_rule_name(&raw_rule.name)?;
            let key = (name.clone(), wildcard);
            if !seen.insert(key) {
                return Err(ConfigError::Conflict(raw_rule.name));
            }
            if wildcard
                && rules.iter().any(|rule: &Rule| {
                    rule.wildcard
                        && (name.ends_with(&format!(".{}", rule.name))
                            || rule.name.ends_with(&format!(".{name}")))
                })
            {
                return Err(ConfigError::Conflict(raw_rule.name));
            }
            let address = Ipv4Addr::from_str(&raw_rule.address)
                .map_err(|_| ConfigError::RuleAddress(raw_rule.name.clone()))?;
            let ttl = raw_rule.ttl.unwrap_or(raw.ttl);
            validate_ttl(ttl).map_err(|_| ConfigError::RuleTtl(raw_rule.name.clone()))?;
            rules.push(Rule {
                name,
                wildcard,
                address,
                ttl,
            });
        }

        Ok(Self {
            upstream,
            source_port: raw.source_port,
            rules,
        })
    }

    pub fn lookup(&self, query_name: &str) -> Option<&Rule> {
        let name = query_name.trim_end_matches('.').to_ascii_lowercase();
        self.rules
            .iter()
            .find(|rule| !rule.wildcard && rule.name == name)
            .or_else(|| {
                self.rules
                    .iter()
                    .filter(|rule| rule.wildcard && name.len() > rule.name.len())
                    .find(|rule| {
                        name.ends_with(&rule.name)
                            && name.as_bytes().get(name.len() - rule.name.len() - 1) == Some(&b'.')
                    })
            })
    }
}

fn canonical_rule_name(input: &str) -> Result<(String, bool), ConfigError> {
    if input.ends_with("..") {
        return Err(ConfigError::RuleName(input.to_owned()));
    }
    let (name, wildcard) = match input.strip_prefix("*.") {
        Some(name) => (name, true),
        None if input.contains('*') => return Err(ConfigError::RuleName(input.to_owned())),
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

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
upstream = "1.1.1.1"
source_port = 53053
ttl = 120

[[rules]]
name = "example.com"
address = "192.0.2.1"

[[rules]]
name = "*.example.net"
address = "192.0.2.2"
ttl = 30
"#;

    #[test]
    fn validates_settings_and_normalizes_names() {
        let config = Config::parse(BASE).unwrap();
        assert_eq!(config.upstream, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.lookup("EXAMPLE.COM.").unwrap().ttl, 120);
    }

    #[test]
    fn wildcard_matches_subdomain_depth_but_not_apex() {
        let config = Config::parse(BASE).unwrap();
        assert_eq!(config.lookup("www.example.net").unwrap().ttl, 30);
        assert!(config.lookup("a.b.example.net").is_some());
        assert!(config.lookup("example.net").is_none());
        assert!(config.lookup("notexample.net").is_none());
    }

    #[test]
    fn exact_rule_precedes_wildcard() {
        let config = Config::parse(
            r#"
upstream = "8.8.8.8"
source_port = 53053
[[rules]]
name = "*.example.com"
address = "192.0.2.1"
[[rules]]
name = "api.example.com"
address = "192.0.2.2"
"#,
        )
        .unwrap();
        assert_eq!(
            config.lookup("api.example.com").unwrap().address,
            Ipv4Addr::new(192, 0, 2, 2)
        );
    }

    #[test]
    fn rejects_invalid_names_ports_and_ambiguous_wildcards() {
        for config_text in [
            BASE.replace("53053", "53"),
            BASE.replace("example.com", "bad..example"),
            BASE.replace("example.com", "example.com.."),
            BASE.replace("*.example.net", "bad*.example.net"),
        ] {
            assert!(Config::parse(&config_text).is_err());
        }
        let overlapping_wildcards = r#"
upstream = "8.8.8.8"
source_port = 53053
[[rules]]
name = "*.example.net"
address = "192.0.2.1"
[[rules]]
name = "*.sub.example.net"
address = "192.0.2.2"
"#;
        assert!(Config::parse(overlapping_wildcards).is_err());
    }

    #[test]
    fn rejects_invalid_addresses_ttls_and_duplicate_rules() {
        for config_text in [
            BASE.replace("1.1.1.1", "not-an-ip"),
            BASE.replace("192.0.2.1", "300.0.2.1"),
            BASE.replace("ttl = 120", "ttl = 0"),
            BASE.replace("ttl = 30", "ttl = 86401"),
            format!("{BASE}\n[[rules]]\nname = \"example.com\"\naddress = \"192.0.2.3\"\n"),
        ] {
            assert!(Config::parse(&config_text).is_err());
        }
        let multicast_upstream = BASE.replace("1.1.1.1", "224.0.0.1");
        assert!(Config::parse(&multicast_upstream).is_err());
    }
}
