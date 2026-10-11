mod backend;
mod config;
mod dns;
mod packet;

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
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let path = args.next().ok_or("--config requires a path")?;
                config_path = Some(PathBuf::from(path));
            }
            "--run" => enable_capture = true,
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
    windivert_backend::run(config)?;

    #[cfg(not(target_os = "windows"))]
    return Err("packet interception is supported on Windows only".into());

    Ok(())
}

fn print_help() {
    println!(
        "dns-shunt --config <path> [--run]\n\nValidate config by default. --run explicitly enables elevated WinDivert capture."
    );
}
