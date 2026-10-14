use crate::config::{self, CompiledRules, ConfigError, Rule, RuleInput};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct RuleManager {
    path: PathBuf,
    reserved_name: String,
    default_ttl: u32,
    snapshot: RwLock<Arc<CompiledRules>>,
    mutation: Mutex<()>,
}

#[derive(Debug, Error)]
pub enum RuleStoreError {
    #[error("rule store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rule store JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid rule set: {0}")]
    Validation(#[from] ConfigError),
    #[error("rule update rejected: {0}")]
    Update(String),
}

impl RuleManager {
    pub fn load(
        path: PathBuf,
        reserved_name: String,
        default_ttl: u32,
    ) -> Result<Self, RuleStoreError> {
        let inputs = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Vec<RuleInput>>(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let input_order = inputs
            .iter()
            .map(|input| {
                let wildcard = input.name.starts_with("*.");
                let name = input
                    .name
                    .strip_prefix("*.")
                    .unwrap_or(&input.name)
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                (name, wildcard)
            })
            .collect::<Vec<_>>();
        let rules = config::validate_rules(inputs, &reserved_name, default_ttl)?;
        let sorted_order = rules
            .iter()
            .map(|rule| (rule.name.clone(), rule.wildcard))
            .collect::<Vec<_>>();
        if input_order != sorted_order {
            let sorted_inputs = rules.iter().map(config::rule_input).collect::<Vec<_>>();
            let _ = persist(&path, &sorted_inputs);
        }
        Ok(Self {
            path,
            reserved_name,
            default_ttl,
            snapshot: RwLock::new(Arc::new(CompiledRules::new(rules))),
            mutation: Mutex::new(()),
        })
    }

    pub fn snapshot(&self) -> Vec<Rule> {
        self.packet_snapshot().rules().to_vec()
    }

    pub(crate) fn packet_snapshot(&self) -> Arc<CompiledRules> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    pub fn store_path(&self) -> &Path {
        &self.path
    }

    pub fn transact<F>(&self, change: F) -> Result<Vec<Rule>, RuleStoreError>
    where
        F: FnOnce(&[Rule]) -> Result<Vec<RuleInput>, String>,
    {
        let _guard = self
            .mutation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.snapshot();
        let proposed = change(&current).map_err(RuleStoreError::Update)?;
        let validated =
            config::validate_rules(proposed.clone(), &self.reserved_name, self.default_ttl)?;
        let compiled = Arc::new(CompiledRules::new(validated.clone()));
        let sorted_inputs = validated.iter().map(config::rule_input).collect::<Vec<_>>();
        persist(&self.path, &sorted_inputs)?;
        *self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = compiled;
        Ok(validated)
    }
}

pub fn default_store_path() -> Result<PathBuf, std::io::Error> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(|home| PathBuf::from(home).join("AppData").join("Roaming"))
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                concat!(
                    "could not locate the current user's ",
                    "application-data directory"
                ),
            )
        })?;

    #[cfg(not(target_os = "windows"))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not locate the current user's data directory",
            )
        })?;

    Ok(base.join("dns-shunt").join("rules.json"))
}

fn persist(path: &Path, inputs: &[RuleInput]) -> Result<(), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rule store path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(".rules-{}-{sequence}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        serde_json::to_writer_pretty(&mut file, inputs)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        replace_file(&temp_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn replace_file(temp: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(temp, destination)
}

#[cfg(target_os = "windows")]
fn replace_file(temp: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let temp: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            temp.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("dns-shunt-rules-{}-{nonce}", std::process::id()))
            .join("rules.json")
    }

    fn input(name: &str, address: &str) -> RuleInput {
        RuleInput {
            name: name.into(),
            address: address.into(),
            ttl: Some(60),
        }
    }

    #[test]
    fn loads_missing_store_and_atomically_replaces_complete_rule_sets() {
        let path = test_path();
        let manager = RuleManager::load(path.clone(), "dns-shunt.local".into(), 60).unwrap();
        assert!(manager.snapshot().is_empty());
        manager
            .transact(|_| Ok(vec![input("one.example", "192.0.2.1")]))
            .unwrap();
        let prior_snapshot = manager.packet_snapshot();
        assert!(
            manager
                .packet_snapshot()
                .lookup_normalized("one.example")
                .is_some()
        );
        manager
            .transact(|_| Ok(vec![input("two.example", "192.0.2.2")]))
            .unwrap();
        let packet_snapshot = manager.packet_snapshot();
        assert!(prior_snapshot.lookup_normalized("one.example").is_some());
        assert!(prior_snapshot.lookup_normalized("two.example").is_none());
        assert!(packet_snapshot.lookup_normalized("one.example").is_none());
        assert!(packet_snapshot.lookup_normalized("two.example").is_some());
        let reopened = RuleManager::load(path.clone(), "dns-shunt.local".into(), 60).unwrap();
        assert_eq!(reopened.snapshot()[0].name, "two.example");
        assert!(!fs::read_to_string(&path).unwrap().contains("query"));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn normalizes_existing_store_order_and_sorts_mutations() {
        let path = test_path();
        let unsorted = vec![
            input("z.example.com", "192.0.2.1"),
            input("example.net", "192.0.2.2"),
            input("example.com", "192.0.2.3"),
        ];
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_vec(&unsorted).unwrap()).unwrap();

        let manager = RuleManager::load(path.clone(), "dns-shunt.local".into(), 60).unwrap();
        assert_eq!(
            manager
                .snapshot()
                .iter()
                .map(|rule| rule.name.as_str())
                .collect::<Vec<_>>(),
            ["example.com", "z.example.com", "example.net"]
        );
        let stored: Vec<RuleInput> = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            stored
                .iter()
                .map(|rule| rule.name.as_str())
                .collect::<Vec<_>>(),
            ["example.com", "z.example.com", "example.net"]
        );

        manager
            .transact(|_| {
                Ok(vec![
                    input("*.example.com", "192.0.2.4"),
                    input("example.net", "192.0.2.5"),
                    input("example.com", "192.0.2.6"),
                ])
            })
            .unwrap();
        let stored: Vec<RuleInput> = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            stored
                .iter()
                .map(|rule| rule.name.as_str())
                .collect::<Vec<_>>(),
            ["example.com", "*.example.com", "example.net"]
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rejects_corrupt_store_and_preserves_active_snapshot_on_failed_update() {
        let path = test_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json").unwrap();
        assert!(RuleManager::load(path.clone(), "dns-shunt.local".into(), 60).is_err());
        fs::remove_file(&path).unwrap();
        let manager = RuleManager::load(path.clone(), "dns-shunt.local".into(), 60).unwrap();
        manager
            .transact(|_| Ok(vec![input("old.example", "192.0.2.1")]))
            .unwrap();
        let active_snapshot = manager.packet_snapshot();
        assert!(
            manager
                .transact(|_| Ok(vec![input("dns-shunt.local", "192.0.2.2")]))
                .is_err()
        );
        assert_eq!(manager.snapshot()[0].name, "old.example");
        assert!(
            manager
                .packet_snapshot()
                .lookup_normalized("old.example")
                .is_some()
        );
        assert!(Arc::ptr_eq(&active_snapshot, &manager.packet_snapshot()));

        fs::remove_file(&path).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
        fs::write(path.parent().unwrap(), b"block parent creation").unwrap();
        assert!(
            manager
                .transact(|_| Ok(vec![input("new.example", "192.0.2.3")]))
                .is_err()
        );
        assert_eq!(manager.snapshot()[0].name, "old.example");
        assert!(
            manager
                .packet_snapshot()
                .lookup_normalized("old.example")
                .is_some()
        );
        assert!(Arc::ptr_eq(&active_snapshot, &manager.packet_snapshot()));
        let _ = fs::remove_file(path.parent().unwrap());
    }
}
