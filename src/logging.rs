//! Structured logging subsystem and log retention management.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Parses a case-insensitive string into a standard tracing `Level`.
#[allow(dead_code)]
#[must_use]
pub fn parse_level(level: &str) -> Option<Level> {
    match level.trim().to_ascii_lowercase().as_str() {
        "trace" => Some(Level::TRACE),
        "debug" => Some(Level::DEBUG),
        "info" => Some(Level::INFO),
        "warn" => Some(Level::WARN),
        "error" => Some(Level::ERROR),
        _ => None,
    }
}

/// Resolves the effective log level following the precedence rule:
/// CLI argument > RUST_LOG environment variable > configuration > default ("info").
#[must_use]
pub fn resolve_log_level(cli_arg: Option<&str>, config_level: Option<&str>) -> String {
    if let Some(level) = cli_arg {
        let trimmed = level.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(env_level) = std::env::var("RUST_LOG") {
        let trimmed = env_level.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(cfg) = config_level {
        let trimmed = cfg.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "info".to_string()
}

/// Initializes foreground logging to standard output with timestamps and colors.
pub fn init_foreground(level: Option<&str>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = if let Some(lvl) = level {
        EnvFilter::try_new(lvl).unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stdout)
        .try_init()?;
    Ok(())
}

/// Initializes service logging with non-blocking daily rolling files.
/// Returns the `WorkerGuard` which must be held until shutdown to flush logs.
pub fn init_service(
    level: &str,
    log_dir: &Path,
) -> Result<WorkerGuard, Box<dyn Error + Send + Sync>> {
    fs::create_dir_all(log_dir)?;

    let file_appender = tracing_appender::rolling::daily(log_dir, "dns-shunt.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .try_init()?;

    Ok(guard)
}

/// Prunes log files matching `dns-shunt.log*` in `log_dir` older than `max_age_days`.
/// Passing `max_age_days = 0` disables pruning and returns `Ok(0)`.
pub fn prune_old_logs(log_dir: &Path, max_age_days: u32) -> io::Result<usize> {
    if max_age_days == 0 {
        return Ok(0);
    }

    if !log_dir.exists() {
        return Ok(0);
    }

    let max_age = Duration::from_secs(u64::from(max_age_days) * 86_400);
    let now = SystemTime::now();
    let cutoff = match now.checked_sub(max_age) {
        Some(t) => t,
        None => return Ok(0),
    };

    let mut deleted = 0;
    for entry in fs::read_dir(log_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(%err, "failed to read log directory entry during pruning");
                continue;
            }
        };

        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(err) => {
                tracing::warn!(path = ?entry.path(), %err, "failed to read file type during pruning");
                continue;
            }
        };

        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if !name_str.starts_with("dns-shunt.log") {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!(
                    path = ?entry.path(),
                    %err,
                    "failed to read log file metadata during pruning"
                );
                continue;
            }
        };

        let file_time = metadata.modified().or_else(|_| metadata.created());
        let file_time = match file_time {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(
                    path = ?entry.path(),
                    %err,
                    "failed to determine log file time during pruning"
                );
                continue;
            }
        };

        if file_time < cutoff {
            match fs::remove_file(entry.path()) {
                Ok(()) => {
                    deleted += 1;
                    tracing::debug!(path = ?entry.path(), "pruned old log file");
                }
                Err(err) => {
                    tracing::warn!(
                        path = ?entry.path(),
                        %err,
                        "failed to remove old log file (may be locked or in use)"
                    );
                }
            }
        }
    }

    tracing::info!(removed_count = deleted, "completed log file pruning");
    Ok(deleted)
}

/// Spawns a background thread running daily log pruning every 24 hours.
/// Terminates promptly when `stop` is signaled.
#[must_use]
pub fn spawn_log_pruner(
    log_dir: PathBuf,
    max_age_days: u32,
    stop: Arc<AtomicBool>,
) -> Option<JoinHandle<()>> {
    if max_age_days == 0 {
        return None;
    }

    let handle = thread::Builder::new()
        .name("log-pruner".to_string())
        .spawn(move || {
            const CHECK_INTERVAL: Duration = Duration::from_secs(2);
            const PRUNE_INTERVAL: Duration = Duration::from_secs(86_400);

            if stop.load(Ordering::Relaxed) {
                return;
            }

            if let Err(err) = prune_old_logs(&log_dir, max_age_days) {
                tracing::warn!(%err, "initial log pruning failed");
            }

            let mut elapsed = Duration::ZERO;
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(CHECK_INTERVAL);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                elapsed += CHECK_INTERVAL;
                if elapsed >= PRUNE_INTERVAL {
                    elapsed = Duration::ZERO;
                    if let Err(err) = prune_old_logs(&log_dir, max_age_days) {
                        tracing::warn!(%err, "periodic log pruning failed");
                    }
                }
            }
        })
        .ok()?;

    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File, FileTimes};

    #[test]
    fn test_parse_level() {
        assert_eq!(parse_level("trace"), Some(Level::TRACE));
        assert_eq!(parse_level("DEBUG"), Some(Level::DEBUG));
        assert_eq!(parse_level("  Info  "), Some(Level::INFO));
        assert_eq!(parse_level("warn"), Some(Level::WARN));
        assert_eq!(parse_level("Error"), Some(Level::ERROR));
        assert_eq!(parse_level("invalid"), None);
        assert_eq!(parse_level(""), None);
    }

    #[test]
    fn test_resolve_log_level() {
        assert_eq!(resolve_log_level(Some("debug"), Some("warn")), "debug");
        assert_eq!(resolve_log_level(None, Some("warn")), "warn");
        assert_eq!(resolve_log_level(None, None), "info");
        assert_eq!(resolve_log_level(Some(""), Some("trace")), "trace");
    }

    #[test]
    fn test_prune_disabled_when_zero() {
        let temp_dir = std::env::temp_dir().join("dns_shunt_prune_zero_test");
        let _ = fs::create_dir_all(&temp_dir);
        let res = prune_old_logs(&temp_dir, 0);
        let _ = fs::remove_dir_all(&temp_dir);
        assert_eq!(res.unwrap(), 0);
    }

    #[test]
    fn test_prune_old_logs() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("dns_shunt_prune_test_{unique}"));
        fs::create_dir_all(&temp_dir).unwrap();

        let old_file = temp_dir.join("dns-shunt.log.2026-01-01");
        let recent_file = temp_dir.join("dns-shunt.log.2026-10-31");
        let other_old_file = temp_dir.join("other-service.log.2026-01-01");

        File::create(&old_file).unwrap();
        File::create(&recent_file).unwrap();
        File::create(&other_old_file).unwrap();

        // Set times: old files 30 days ago
        let old_time = SystemTime::now() - Duration::from_secs(30 * 86_400);
        let times = FileTimes::new().set_modified(old_time);
        fs::OpenOptions::new()
            .write(true)
            .open(&old_file)
            .unwrap()
            .set_times(times)
            .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&other_old_file)
            .unwrap()
            .set_times(times)
            .unwrap();

        // Prune older than 7 days
        let pruned = prune_old_logs(&temp_dir, 7).unwrap();
        assert_eq!(pruned, 1);

        assert!(!old_file.exists());
        assert!(recent_file.exists());
        assert!(other_old_file.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
