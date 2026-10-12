#[cfg(any(target_os = "windows", test))]
mod admin;
#[cfg(any(target_os = "windows", test))]
mod backend;
mod config;
#[cfg(any(target_os = "windows", test))]
mod dns;
#[cfg(any(target_os = "windows", test))]
mod packet;
#[cfg(any(target_os = "windows", test))]
mod rules;

#[cfg(target_os = "windows")]
mod service;
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
    println!(
        "validated override configuration, admin name {}",
        config.gui_name
    );

    if !enable_capture {
        println!("capture is disabled; pass --run to enable the interception backend");
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
    help: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceCommand {
    Stop,
    Install,
    Uninstall,
}

fn parse_arguments(
    args: impl IntoIterator<Item = String>,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut enable_capture = false;
    let mut service_mode = false;
    let mut service_command = None;
    let mut service_command_count = 0;
    let mut help = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let path = args.next().ok_or("--config requires a path")?;
                config_path = Some(PathBuf::from(path));
            }
            "--run" => enable_capture = true,
            "--service" => service_mode = true,
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
            "--help" | "-h" => help = true,
            _ => {
                return Err(format!("unknown argument: {arg}; use --help").into());
            }
        }
    }

    let has_management_command = service_command.is_some();
    if service_command_count > 1 {
        return Err("only one service-management command may be specified".into());
    }
    if service_mode && (config_path.is_some() || enable_capture || has_management_command) {
        return Err("--service cannot be combined with other options".into());
    }
    if has_management_command && (config_path.is_some() || enable_capture) {
        return Err("service-management commands cannot be combined with other options".into());
    }
    Ok(Arguments {
        config_path,
        enable_capture,
        service_mode,
        service_command,
        help,
    })
}

#[cfg(target_os = "windows")]
fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let paths = service::service_paths()?;
    let config = config::Config::load(&paths.config)?;
    run_capture(config, paths.rules, false)
}

#[cfg(target_os = "windows")]
fn run_capture(
    config: config::Config,
    rules_path: PathBuf,
    console_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = rules::RuleManager::load(rules_path, config.gui_name.clone(), config.ttl)?;
    if console_mode {
        println!(
            "loaded {} web-managed override rule(s)",
            rules.snapshot().len()
        );
    }
    let runtime = admin::RuntimeState::new(config.clone(), rules, "WinDivert");
    if !console_mode {
        service::attach_runtime(&runtime);
        runtime.set_error_callback(std::sync::Arc::new(service::log_error));
    }
    let server = admin::AdminServer::bind(&runtime)?;
    if console_mode {
        println!("admin interface: http://127.0.0.1:{}", config.gui_port);
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
        "dns-shunt --config <path> [--run]\n",
        "dns-shunt --service (Windows Service Control Manager only)\n\n",
        "dns-shunt --stop-service | --install-service | --uninstall-service\n\n",
        "Validate config by default. --run starts the loopback web admin ",
        "and elevated WinDivert capture. Rules are stored in ",
        "the current user's application-data directory. Service management ",
        "requires an elevated administrator."
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
    }

    #[test]
    fn service_management_commands_are_exclusive() {
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
        assert!(
            parse_arguments([
                "--install-service".to_owned(),
                "--uninstall-service".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_arguments(["--install-service".to_owned(), "--service".to_owned(),]).is_err()
        );
        assert!(parse_arguments(["--install-service".to_owned(), "--run".to_owned(),]).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn service_mode_is_exclusive_and_uses_fixed_machine_paths() {
        let paths = service::paths_under(std::path::Path::new("C:/ProgramData"));
        assert_eq!(
            paths.config,
            PathBuf::from("C:/ProgramData/dns-shunt/config.toml")
        );
        assert_eq!(
            paths.rules,
            PathBuf::from("C:/ProgramData/dns-shunt/rules.json")
        );
    }
}
