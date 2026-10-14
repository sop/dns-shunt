use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::Ipv4Addr,
    path::Path,
    str::FromStr,
};
use thiserror::Error;

const DEFAULT_TTL: u32 = 60;
pub const DEFAULT_GUI_NAME: &str = "dns-shunt.local";
pub const DEFAULT_GUI_PORT: u16 = 53080;

#[derive(Debug, Clone)]
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub struct Config {
    pub ttl: u32,
    pub gui_name: String,
    #[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
    pub gui_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub struct Rule {
    pub name: String,
    pub wildcard: bool,
    pub address: Ipv4Addr,
    pub ttl: u32,
}

#[derive(Debug)]
pub(crate) struct CompiledRules {
    rules: Vec<Rule>,
    exact_names: HashMap<String, usize>,
    wildcard_suffixes: HashMap<String, usize>,
}

impl CompiledRules {
    pub(crate) fn new(rules: Vec<Rule>) -> Self {
        let mut exact_names = HashMap::new();
        let mut wildcard_suffixes = HashMap::new();
        for (index, rule) in rules.iter().enumerate() {
            let names = if rule.wildcard {
                &mut wildcard_suffixes
            } else {
                &mut exact_names
            };
            names.entry(rule.name.clone()).or_insert(index);
        }
        Self {
            rules,
            exact_names,
            wildcard_suffixes,
        }
    }

    pub(crate) fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub(crate) fn lookup_normalized(&self, query_name: &str) -> Option<&Rule> {
        let index = self.exact_names.get(query_name).copied().or_else(|| {
            query_name
                .match_indices('.')
                .find_map(|(dot, _)| self.wildcard_suffixes.get(&query_name[dot + 1..]))
                .copied()
        })?;
        self.rules.get(index)
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
    pub address: String,
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
    #[error("invalid rule address for {0}")]
    RuleAddress(String),
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

        Ok(Self {
            ttl: raw.ttl,
            gui_name,
            gui_port: raw.gui_port,
        })
    }
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn validate_rules(
    inputs: Vec<RuleInput>,
    reserved_name: &str,
    default_ttl: u32,
) -> Result<Vec<Rule>, ConfigError> {
    let mut rules = Vec::with_capacity(inputs.len());
    let mut seen = HashSet::new();
    for input in inputs {
        let (name, wildcard) = canonical_rule_name(&input.name)?;
        if !wildcard && name == reserved_name {
            return Err(ConfigError::Conflict(input.name));
        }
        let key = (name.clone(), wildcard);
        if !seen.insert(key) {
            return Err(ConfigError::Conflict(input.name));
        }
        let address = Ipv4Addr::from_str(&input.address)
            .map_err(|_| ConfigError::RuleAddress(input.name.clone()))?;
        let ttl = input.ttl.unwrap_or(default_ttl);
        validate_ttl(ttl).map_err(|_| ConfigError::RuleTtl(input.name.clone()))?;
        rules.push(Rule {
            name,
            wildcard,
            address,
            ttl,
        });
    }
    rules.sort_by(compare_rules);
    Ok(rules)
}

fn compare_rules(left: &Rule, right: &Rule) -> std::cmp::Ordering {
    left.name
        .split('.')
        .rev()
        .cmp(right.name.split('.').rev())
        .then_with(|| left.wildcard.cmp(&right.wildcard))
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
        address: rule.address.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "ttl = 120\n";

    fn inputs() -> Vec<RuleInput> {
        vec![
            RuleInput {
                name: "example.com".into(),
                address: "192.0.2.1".into(),
                ttl: None,
            },
            RuleInput {
                name: "*.example.net".into(),
                address: "192.0.2.2".into(),
                ttl: Some(30),
            },
        ]
    }

    #[test]
    fn validates_override_settings_and_gui_defaults() {
        let config = Config::parse(BASE).unwrap();
        assert_eq!(config.ttl, 120);
        assert_eq!(config.gui_name, DEFAULT_GUI_NAME);
        assert_eq!(config.gui_port, DEFAULT_GUI_PORT);
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
                    address: "127.0.0.2".into(),
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
                address: "192.0.2.3".into(),
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
                address: "192.0.2.1".into(),
                ttl: None,
            },
            RuleInput {
                name: "api.example.com".into(),
                address: "192.0.2.2".into(),
                ttl: None,
            },
        ];
        let rules = validate_rules(entries, "dns-shunt.local", 60).unwrap();
        assert_eq!(
            lookup_rule(&rules, "api.example.com").unwrap().address,
            Ipv4Addr::new(192, 0, 2, 2)
        );
        for input in [
            RuleInput {
                name: "bad..example".into(),
                address: "192.0.2.1".into(),
                ttl: None,
            },
            RuleInput {
                name: "bad*.example".into(),
                address: "192.0.2.1".into(),
                ttl: None,
            },
            RuleInput {
                name: "good.example".into(),
                address: "not-an-ip".into(),
                ttl: None,
            },
            RuleInput {
                name: "good.example".into(),
                address: "192.0.2.1".into(),
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
            address: "192.0.2.1".into(),
            ttl: None,
        };
        let nested = RuleInput {
            name: "*.sub.example.com".into(),
            address: "192.0.2.2".into(),
            ttl: None,
        };
        let exact = RuleInput {
            name: "api.sub.example.com".into(),
            address: "192.0.2.3".into(),
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
                    Ipv4Addr::new(192, 0, 2, 2)
                );
                assert_eq!(
                    compiled.lookup(query).unwrap().address,
                    Ipv4Addr::new(192, 0, 2, 2)
                );
            }
            assert_eq!(
                lookup_rule(&rules, "www.example.com").unwrap().address,
                Ipv4Addr::new(192, 0, 2, 1)
            );
            assert_eq!(
                compiled.lookup("www.example.com").unwrap().address,
                Ipv4Addr::new(192, 0, 2, 1)
            );
            assert_eq!(
                lookup_rule(&rules, "api.sub.example.com").unwrap().address,
                Ipv4Addr::new(192, 0, 2, 3)
            );
            assert_eq!(
                compiled.lookup("api.sub.example.com").unwrap().address,
                Ipv4Addr::new(192, 0, 2, 3)
            );
            assert!(lookup_rule(&rules, "example.com").is_none());
            assert!(compiled.lookup("example.com").is_none());
            assert_eq!(
                compiled.lookup("sub.example.com").unwrap().address,
                Ipv4Addr::new(192, 0, 2, 1)
            );
        }

        assert!(
            validate_rules(
                vec![
                    RuleInput {
                        name: "*.Example.com.".into(),
                        address: "192.0.2.1".into(),
                        ttl: None,
                    },
                    RuleInput {
                        name: "*.example.com".into(),
                        address: "192.0.2.2".into(),
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
                address: "192.0.2.1".into(),
                ttl: None,
            },
            RuleInput {
                name: "z.example.com".into(),
                address: "192.0.2.2".into(),
                ttl: None,
            },
            RuleInput {
                name: "example.net".into(),
                address: "192.0.2.3".into(),
                ttl: None,
            },
            RuleInput {
                name: "example.com".into(),
                address: "192.0.2.4".into(),
                ttl: None,
            },
            RuleInput {
                name: "a.example.com".into(),
                address: "192.0.2.5".into(),
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
                address: "192.0.2.1".into(),
                ttl: None,
            },
            RuleInput {
                name: "api.example.net".into(),
                address: "192.0.2.2".into(),
                ttl: None,
            },
            RuleInput {
                name: "*.example.com".into(),
                address: "192.0.2.3".into(),
                ttl: None,
            },
        ];
        let rules = CompiledRules::new(validate_rules(entries, "dns-shunt.local", 60).unwrap());

        assert_eq!(
            rules.lookup_normalized("api.example.net").unwrap().address,
            Ipv4Addr::new(192, 0, 2, 2)
        );
        assert_eq!(
            rules.lookup_normalized("a.b.example.net").unwrap().address,
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert!(rules.lookup_normalized("example.net").is_none());
        assert!(rules.lookup_normalized("notexample.net").is_none());
        assert_eq!(
            rules.lookup("WWW.EXAMPLE.COM.").unwrap().address,
            Ipv4Addr::new(192, 0, 2, 3)
        );
        assert!(lookup_rule(rules.rules(), "API.EXAMPLE.NET.").is_some());
    }
}
