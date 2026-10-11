#[cfg(any(target_os = "windows", test))]
mod backend;
mod config;
#[cfg(any(target_os = "windows", test))]
mod dns;
#[cfg(any(target_os = "windows", test))]
mod packet;
#[cfg(any(target_os = "windows", test))]
mod wfp_protocol;

#[cfg(target_os = "windows")]
mod upstream_socket;
#[cfg(target_os = "windows")]
mod wfp_backend;
#[cfg(target_os = "windows")]
mod windivert_backend;

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dns-shunt: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut enable_capture = false;
    let mut backend = None;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let path = args.next().ok_or("--config requires a path")?;
                config_path = Some(PathBuf::from(path));
            }
            "--run" => enable_capture = true,
            "--backend" => {
                let value = args.next().ok_or("--backend requires wfp or windivert")?;
                backend = Some(parse_backend(&value)?);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}; use --help").into()),
        }
    }

    let config_path = config_path.ok_or("--config is required; use --help")?;
    let config = config::Config::load(&config_path)?;
    println!(
        "validated {} override rule(s), upstream {}, reserved UDP port {}",
        config.rules.len(),
        config.upstream,
        config.source_port
    );

    if !enable_capture {
        println!("capture is disabled; pass --run to enable the interception backend");
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        match selected_backend(backend) {
            BackendChoice::Wfp => wfp_backend::run(config)?,
            BackendChoice::WinDivert => windivert_backend::run(config)?,
        }
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

fn print_help() {
    println!(
        "dns-shunt --config <path> [--run] [--backend windivert|wfp]\n\nValidate config by default. --run enables elevated capture (WinDivert by default). Install its signed runtime assets with install-windivert.ps1.\nUse --backend wfp to select the experimental WFP backend; it requires an installed x64 callout driver, elevation, and a test-signing-enabled test machine for locally built drivers. Build the driver with the Windows Driver Kit (WDK)."
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendChoice {
    Wfp,
    WinDivert,
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
}
