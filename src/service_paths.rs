use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct ServicePaths {
    pub config: PathBuf,
    pub rules: PathBuf,
    pub rules_dir: PathBuf,
    pub legacy_rules: PathBuf,
    pub log_dir: PathBuf,
}

pub fn paths_under(program_data: &Path) -> ServicePaths {
    let root = program_data.join("dns-shunt");
    let rules_dir = root.join("rules");
    ServicePaths {
        config: root.join("config.toml"),
        rules: rules_dir.join("rules.json"),
        rules_dir,
        legacy_rules: root.join("rules.json"),
        log_dir: root.join("logs"),
    }
}

pub fn service_paths() -> Result<ServicePaths, std::io::Error> {
    let root = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not locate the ProgramData directory",
            )
        })?;
    Ok(paths_under(&root))
}

pub fn migrate_rules(paths: &ServicePaths) -> io::Result<()> {
    fs::create_dir_all(&paths.rules_dir)?;
    let legacy_exists = paths.legacy_rules.exists();
    let current_exists = paths.rules.exists();
    if legacy_exists && current_exists {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "both legacy and current rules files exist: {} and {}",
                paths.legacy_rules.display(),
                paths.rules.display()
            ),
        ));
    }
    if legacy_exists {
        fs::rename(&paths.legacy_rules, &paths.rules)?;
    } else if !current_exists {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&paths.rules)
        {
            Ok(mut file) => file.write_all(b"[]\n")?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_paths() -> ServicePaths {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        paths_under(&std::env::temp_dir().join(format!(
            "dns-shunt-service-paths-{nonce}-{}",
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )))
    }

    #[test]
    fn migrates_old_rules_and_initializes_missing_store() {
        let paths = test_paths();
        fs::create_dir_all(paths.legacy_rules.parent().unwrap()).unwrap();
        fs::write(&paths.legacy_rules, b"legacy rules").unwrap();
        migrate_rules(&paths).unwrap();
        assert_eq!(fs::read(&paths.rules).unwrap(), b"legacy rules");
        assert!(!paths.legacy_rules.exists());
        fs::remove_dir_all(paths.legacy_rules.parent().unwrap()).unwrap();

        let paths = test_paths();
        migrate_rules(&paths).unwrap();
        assert_eq!(fs::read(&paths.rules).unwrap(), b"[]\n");
        fs::remove_dir_all(paths.legacy_rules.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_ambiguous_rules_migration_without_discarding_either_file() {
        let paths = test_paths();
        fs::create_dir_all(paths.rules_dir.parent().unwrap()).unwrap();
        fs::create_dir_all(&paths.rules_dir).unwrap();
        fs::write(&paths.legacy_rules, b"legacy").unwrap();
        fs::write(&paths.rules, b"current").unwrap();
        assert!(migrate_rules(&paths).is_err());
        assert_eq!(fs::read(&paths.legacy_rules).unwrap(), b"legacy");
        assert_eq!(fs::read(&paths.rules).unwrap(), b"current");
        fs::remove_dir_all(paths.legacy_rules.parent().unwrap()).unwrap();
    }

    #[test]
    fn paths_under_sets_expected_locations() {
        let base = Path::new(r"C:\ProgramData");
        let paths = paths_under(base);
        assert_eq!(
            paths.config,
            PathBuf::from(r"C:\ProgramData\dns-shunt\config.toml")
        );
        assert_eq!(
            paths.rules,
            PathBuf::from(r"C:\ProgramData\dns-shunt\rules\rules.json")
        );
        assert_eq!(
            paths.rules_dir,
            PathBuf::from(r"C:\ProgramData\dns-shunt\rules")
        );
        assert_eq!(
            paths.legacy_rules,
            PathBuf::from(r"C:\ProgramData\dns-shunt\rules.json")
        );
        assert_eq!(
            paths.log_dir,
            PathBuf::from(r"C:\ProgramData\dns-shunt\logs")
        );
    }
}
