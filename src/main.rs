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
#[cfg(any(target_os = "windows", test))]
mod wfp_protocol;

#[cfg(target_os = "windows")]
mod service;
#[cfg(target_os = "windows")]
mod wfp_backend;
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
    let config_path = arguments.config_path;
    let enable_capture = arguments.enable_capture;
    let service_mode = arguments.service_mode;
    let backend = arguments.backend;

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
        run_capture(config, rules_path, selected_backend(backend), true)?;
    }

    #[cfg(not(target_os = "windows"))]
    return Err(format!(
        "{} interception is supported on Windows only",
        match selected_backend(backend) {
            BackendChoice::Wfp => "WFP",
            BackendChoice::WinDivert => "WinDivert",
        }
    )
    .into());

    #[cfg(target_os = "windows")]
    Ok(())
}

struct Arguments {
    config_path: Option<PathBuf>,
    enable_capture: bool,
    service_mode: bool,
    backend: Option<BackendChoice>,
    help: bool,
}

fn parse_arguments(
    args: impl IntoIterator<Item = String>,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut enable_capture = false;
    let mut service_mode = false;
    let mut backend = None;
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
            "--backend" => {
                let value = args.next().ok_or("--backend requires wfp or windivert")?;
                backend = Some(parse_backend(&value)?);
            }
            "--help" | "-h" => help = true,
            _ => {
                return Err(format!("unknown argument: {arg}; use --help").into());
            }
        }
    }

    if service_mode && (config_path.is_some() || enable_capture || backend.is_some()) {
        return Err("--service cannot be combined with other options".into());
    }
    Ok(Arguments {
        config_path,
        enable_capture,
        service_mode,
        backend,
        help,
    })
}

#[cfg(target_os = "windows")]
fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let paths = service::service_paths()?;
    let config = config::Config::load(&paths.config)?;
    run_capture(config, paths.rules, BackendChoice::WinDivert, false)
}

#[cfg(target_os = "windows")]
fn run_capture(
    config: config::Config,
    rules_path: PathBuf,
    choice: BackendChoice,
    console_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = rules::RuleManager::load(rules_path, config.gui_name.clone(), config.ttl)?;
    if console_mode {
        println!(
            "loaded {} web-managed override rule(s)",
            rules.snapshot().len()
        );
    }
    let runtime = admin::RuntimeState::new(config.clone(), rules, choice.label());
    if !console_mode {
        service::attach_runtime(&runtime);
        runtime.set_error_callback(std::sync::Arc::new(service::log_error));
    }
    let server = admin::AdminServer::bind(&runtime)?;
    if console_mode {
        println!("admin interface: http://127.0.0.1:{}", config.gui_port);
    }
    let result = match choice {
        BackendChoice::Wfp => wfp_backend::run(config, runtime.clone(), console_mode),
        BackendChoice::WinDivert => windivert_backend::run(config, runtime.clone(), console_mode),
    };
    runtime.stop();
    let server_result = server.join();
    result?;
    server_result?;
    Ok(())
}

fn print_help() {
    println!(concat!(
        "dns-shunt --config <path> [--run] [--backend windivert|wfp]\n",
        "dns-shunt --service (Windows Service Control Manager only)\n\n",
        "Validate config by default. --run starts the loopback web admin ",
        "and elevated capture (WinDivert by default). Rules are stored in ",
        "the current user's application-data directory. Install its ",
        "signed runtime assets with install-windivert.ps1.\n",
        "Use --backend wfp to select the experimental WFP backend; it ",
        "requires an installed x64 callout driver, elevation, and a ",
        "test-signing-enabled test machine for locally built drivers. ",
        "Build the driver with the Windows Driver Kit (WDK)."
    ));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendChoice {
    Wfp,
    WinDivert,
}

impl BackendChoice {
    #[cfg(target_os = "windows")]
    const fn label(self) -> &'static str {
        match self {
            Self::Wfp => "WFP",
            Self::WinDivert => "WinDivert",
        }
    }
}

fn parse_backend(value: &str) -> Result<BackendChoice, Box<dyn std::error::Error>> {
    match value {
        "wfp" => Ok(BackendChoice::Wfp),
        "windivert" => Ok(BackendChoice::WinDivert),
        _ => Err(format!("invalid backend '{value}'; expected wfp or windivert").into()),
    }
}

fn selected_backend(requested: Option<BackendChoice>) -> BackendChoice {
    requested.unwrap_or(BackendChoice::WinDivert)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_backends_and_rejects_unknown_values() {
        assert_eq!(parse_backend("wfp").unwrap(), BackendChoice::Wfp);
        assert_eq!(
            parse_backend("windivert").unwrap(),
            BackendChoice::WinDivert
        );
        assert!(parse_backend("other").is_err());
        assert_eq!(selected_backend(None), BackendChoice::WinDivert);
        assert_eq!(
            selected_backend(Some(BackendChoice::Wfp)),
            BackendChoice::Wfp
        );
        assert_eq!(
            selected_backend(Some(BackendChoice::WinDivert)),
            BackendChoice::WinDivert
        );
    }

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
