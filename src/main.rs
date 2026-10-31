#[cfg(any(target_os = "windows", test))]
mod admin;
#[cfg(any(target_os = "windows", test))]
mod backend;
mod config;
#[cfg(any(target_os = "windows", test))]
mod dns;
#[cfg(any(target_os = "windows", test))]
mod interfaces;
mod logging;
#[cfg(any(target_os = "windows", test))]
mod mdns;
#[cfg(any(target_os = "windows", test))]
mod mdns_scheduler;
#[cfg(any(target_os = "windows", test))]
mod packet;
#[cfg(any(target_os = "windows", test))]
mod rules;

#[cfg(target_os = "windows")]
mod service;
mod service_paths;
#[cfg(target_os = "windows")]
mod windivert_backend;

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    #[cfg(target_os = "windows")]
    let service_mode = env::args().any(|arg| arg == "--service");
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(target_os = "windows")]
            if service_mode {
                service::log_error(&format!("dns-shunt service mode failed: {error}"));
            } else {
                eprintln!("dns-shunt: {error}");
            }
            #[cfg(not(target_os = "windows"))]
            eprintln!("dns-shunt: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_arguments(env::args().skip(1))?;
    if arguments.help {
        print_help();
        return Ok(());
    }
    if arguments.version {
        println!("{}", version_string());
        return Ok(());
    }
    if let Some(command) = arguments.service_command {
        #[cfg(target_os = "windows")]
        return service::manage(command);
        #[cfg(not(target_os = "windows"))]
        return Err("service management is supported on Windows only".into());
    }
    let config_path = arguments.config_path;
    let enable_capture = arguments.enable_capture;
    let service_mode = arguments.service_mode;

    if service_mode {
        #[cfg(target_os = "windows")]
        return service::dispatch();
        #[cfg(not(target_os = "windows"))]
        return Err("--service is supported on Windows only".into());
    }

    let config_path = config_path.ok_or("--config is required; use --help")?;
    let config = config::Config::load(&config_path)?;
    let effective_log_level =
        logging::resolve_log_level(arguments.log_level.as_deref(), Some(&config.log_level));
    let _ = logging::init_foreground(Some(&effective_log_level));
    tracing::info!(
        admin_name = %config.gui_name,
        "validated override configuration"
    );

    if !enable_capture {
        tracing::info!("capture is disabled; pass --run to enable the interception backend");
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let rules_path = rules::default_store_path()?;
        run_capture(config, rules_path, true)?;
    }

    #[cfg(not(target_os = "windows"))]
    return Err("WinDivert interception is supported on Windows only".into());

    #[cfg(target_os = "windows")]
    Ok(())
}

struct Arguments {
    config_path: Option<PathBuf>,
    enable_capture: bool,
    service_mode: bool,
    service_command: Option<ServiceCommand>,
    log_level: Option<String>,
    help: bool,
    version: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum ServiceCommand {
    Start,
    Stop,
    Install,
    Uninstall,
    PrepareUpgrade {
        install_dir: PathBuf,
        error_file: PathBuf,
    },
}

fn parse_arguments(
    args: impl IntoIterator<Item = String>,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut enable_capture = false;
    let mut service_mode = false;
    let mut service_command = None;
    let mut service_command_count = 0;
    let mut log_level = None;
    let mut help = false;
    let mut version = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let path = args.next().ok_or("--config requires a path")?;
                config_path = Some(PathBuf::from(path));
            }
            "--run" => enable_capture = true,
            "--service" => service_mode = true,
            "--log-level" | "-l" => {
                let level = args.next().ok_or("--log-level requires a level")?;
                log_level = Some(level);
            }
            "--start-service" => {
                service_command = Some(ServiceCommand::Start);
                service_command_count += 1;
            }
            "--stop-service" => {
                service_command = Some(ServiceCommand::Stop);
                service_command_count += 1;
            }
            "--install-service" => {
                service_command = Some(ServiceCommand::Install);
                service_command_count += 1;
            }
            "--uninstall-service" => {
                service_command = Some(ServiceCommand::Uninstall);
                service_command_count += 1;
            }
            "--prepare-upgrade" => {
                let path = args
                    .next()
                    .ok_or("--prepare-upgrade requires an install path")?;
                let error_file = args
                    .next()
                    .ok_or("--prepare-upgrade requires an error-file path")?;
                service_command = Some(ServiceCommand::PrepareUpgrade {
                    install_dir: PathBuf::from(path),
                    error_file: PathBuf::from(error_file),
                });
                service_command_count += 1;
            }
            "--help" | "-h" => help = true,
            "--version" => version = true,
            _ => {
                return Err(format!("unknown argument: {arg}; use --help").into());
            }
        }
    }

    let has_management_command = service_command.is_some();
    if service_command_count > 1 {
        return Err("only one service-management command may be specified".into());
    }
    if service_mode
        && (config_path.is_some()
            || enable_capture
            || has_management_command
            || log_level.is_some())
    {
        return Err("--service cannot be combined with other options".into());
    }
    if has_management_command && (config_path.is_some() || enable_capture || log_level.is_some()) {
        return Err("service-management commands cannot be combined with other options".into());
    }
    if version
        && (config_path.is_some()
            || enable_capture
            || service_mode
            || has_management_command
            || log_level.is_some())
    {
        return Err("--version cannot be combined with other options".into());
    }
    Ok(Arguments {
        config_path,
        enable_capture,
        service_mode,
        service_command,
        log_level,
        help,
        version,
    })
}

fn version_string() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

#[cfg(target_os = "windows")]
fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let paths = service::service_paths()?;
    let config = config::Config::load(&paths.config)?;
    let mut rules_access = service::RulesAccessGuard::lock(paths.clone())?;
    let run_result = run_capture(config, paths.rules, false);
    let restore_result = rules_access.restore();
    match (run_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(run_error), Err(restore_error)) => Err(format!(
            "{run_error}; additionally failed to restore rules edit access: {restore_error}"
        )
        .into()),
    }
}

#[cfg(target_os = "windows")]
fn run_capture(
    config: config::Config,
    rules_path: PathBuf,
    console_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = rules::RuleManager::load(rules_path, config.gui_name.clone(), config.ttl)?;
    if console_mode {
        tracing::info!(
            rules_count = rules.snapshot().len(),
            "loaded web-managed override rule(s)"
        );
    }
    let runtime = admin::RuntimeState::new(config.clone(), rules, "WinDivert")?;
    if !console_mode {
        service::attach_runtime(&runtime);
        runtime.set_error_callback(std::sync::Arc::new(service::log_error));
    }
    let server = admin::AdminServer::bind(&runtime)?;
    if console_mode {
        tracing::info!(
            url = %format!("http://{}:{}", config.gui_name, config.gui_port),
            "admin interface available"
        );
    }
    let result = windivert_backend::run(config, runtime.clone(), console_mode);
    runtime.stop();
    let server_result = server.join();
    result?;
    server_result?;
    Ok(())
}

fn print_help() {
    println!(concat!(
        "dns-shunt --config <path> [--run] [--log-level <level>]\n",
        "dns-shunt --version\n",
        "dns-shunt --service (Windows Service Control Manager only)\n\n",
        "dns-shunt --start-service | --stop-service | ",
        "--install-service | --uninstall-service\n",
        "dns-shunt --prepare-upgrade <install-path> <error-file>\n\n",
        "Validate config by default. --run starts the loopback web admin ",
        "and elevated WinDivert capture. Rules are stored in ",
        "the current user's application-data directory. Service installation, ",
        "removal, and upgrade preparation require an elevated administrator."
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_service_mode_and_rejects_foreground_options() {
        let args = parse_arguments(["--service".to_owned()]).unwrap();
        assert!(args.service_mode);
        assert!(!args.enable_capture);
        assert!(args.config_path.is_none());
        assert!(parse_arguments(["--service".to_owned(), "--run".to_owned()]).is_err());
        assert!(
            parse_arguments([
                "--service".to_owned(),
                "--config".to_owned(),
                "config.toml".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_arguments([
                "--service".to_owned(),
                "--log-level".to_owned(),
                "debug".to_owned()
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_log_level_flag() {
        let args = parse_arguments([
            "--config".to_owned(),
            "config.toml".to_owned(),
            "--log-level".to_owned(),
            "debug".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.log_level.as_deref(), Some("debug"));

        let args = parse_arguments([
            "--config".to_owned(),
            "config.toml".to_owned(),
            "-l".to_owned(),
            "trace".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.log_level.as_deref(), Some("trace"));

        assert!(
            parse_arguments([
                "--config".to_owned(),
                "config.toml".to_owned(),
                "--log-level".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn version_is_standalone_and_does_not_require_configuration() {
        let args = parse_arguments(["--version".to_owned()]).unwrap();
        assert!(args.version);
        assert!(args.config_path.is_none());
        assert_eq!(
            version_string(),
            format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        );

        for arguments in [
            vec![
                "--version".to_owned(),
                "--config".to_owned(),
                "config.toml".to_owned(),
            ],
            vec!["--version".to_owned(), "--run".to_owned()],
            vec!["--version".to_owned(), "--service".to_owned()],
            vec!["--version".to_owned(), "--install-service".to_owned()],
        ] {
            assert!(parse_arguments(arguments).is_err());
        }
    }

    #[test]
    fn service_management_commands_are_exclusive() {
        assert_eq!(
            parse_arguments(["--start-service".to_owned()])
                .unwrap()
                .service_command,
            Some(ServiceCommand::Start)
        );
        assert_eq!(
            parse_arguments(["--install-service".to_owned()])
                .unwrap()
                .service_command,
            Some(ServiceCommand::Install)
        );
        assert_eq!(
            parse_arguments(["--stop-service".to_owned()])
                .unwrap()
                .service_command,
            Some(ServiceCommand::Stop)
        );
        assert_eq!(
            parse_arguments(["--uninstall-service".to_owned()])
                .unwrap()
                .service_command,
            Some(ServiceCommand::Uninstall)
        );
        assert_eq!(
            parse_arguments([
                "--prepare-upgrade".to_owned(),
                "C:\\Program Files\\DNS Shunt".to_owned(),
                "C:\\Temp\\upgrade-error.txt".to_owned(),
            ])
            .unwrap()
            .service_command,
            Some(ServiceCommand::PrepareUpgrade {
                install_dir: PathBuf::from("C:\\Program Files\\DNS Shunt"),
                error_file: PathBuf::from("C:\\Temp\\upgrade-error.txt"),
            })
        );
        assert!(parse_arguments(["--prepare-upgrade".to_owned()]).is_err());
        assert!(
            parse_arguments([
                "--prepare-upgrade".to_owned(),
                "C:\\Program Files\\DNS Shunt".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_arguments([
                "--install-service".to_owned(),
                "--uninstall-service".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_arguments(["--start-service".to_owned(), "--stop-service".to_owned(),]).is_err()
        );
        assert!(
            parse_arguments([
                "--prepare-upgrade".to_owned(),
                "C:\\Program Files\\DNS Shunt".to_owned(),
                "C:\\Temp\\upgrade-error.txt".to_owned(),
                "--stop-service".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_arguments(["--install-service".to_owned(), "--service".to_owned(),]).is_err()
        );
        assert!(parse_arguments(["--install-service".to_owned(), "--run".to_owned(),]).is_err());
    }

    #[test]
    fn service_mode_is_exclusive_and_uses_fixed_machine_paths() {
        let paths = service_paths::paths_under(std::path::Path::new("C:/ProgramData"));
        assert_eq!(
            paths.config,
            PathBuf::from("C:/ProgramData/dns-shunt/config.toml")
        );
        assert_eq!(
            paths.rules,
            PathBuf::from("C:/ProgramData/dns-shunt/rules/rules.json")
        );
    }
}
