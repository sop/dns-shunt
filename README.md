# dns-shunt

`dns-shunt` is a production-ready Windows DNS override with foreground and Windows service modes. It synthesizes answers only for matching A/IN records managed through a local web interface. All other DNS packets are passed through unchanged to the resolver Windows selected; the application does not select, configure, or proxy to a resolver. It does not change adapter DNS settings. Capture is opt-in: foreground capture requires `--run`, while installing the automatic-start service is the machine-wide opt-in. WinDivert is the packet interception backend.

WinDivert inspects only outbound, non-loopback IPv4 UDP DNS packets to port 53. IPv6, TCP/53, inbound DNS, and loopback traffic are outside the interception scope.

## Requirements

- Rust stable with the MSVC toolchain for native Windows builds.
- Windows 10/11 x64 to run packet interception.
- Administrator privileges to start interception.
- Elevated PowerShell to install or uninstall the Windows service.
- The signed WinDivert runtime assets installed by `install-windivert.ps1`.

The scripts in this repository do not modify adapter DNS or resolver selection.

## Build And Validate

From the repository root:

```powershell
cargo fmt --check
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The Windows release executable is `target\release\dns-shunt.exe`. Run it directly to validate a configuration or start capture:

```powershell
.\target\release\dns-shunt.exe --config .\dns-shunt.example.toml
.\target\release\dns-shunt.exe --config .\dns-shunt.example.toml --run
```

On a non-Windows system, Rust checks and tests can run, but packet interception is Windows-only. A Windows-target check can also be run with:

```powershell
cargo check --target x86_64-pc-windows-msvc
```

## Configuration

Start with [`dns-shunt.example.toml`](dns-shunt.example.toml):

```toml
ttl = 60
gui_name = "dns-shunt.local"
gui_port = 53080
```

`ttl` is the default for web-managed rules. `gui_name` defaults to `dns-shunt.local` and is a reserved built-in exact override to `127.0.0.1`; `gui_port` defaults to `53080` and is the local HTTP listener port. Rules are not loaded from TOML. Legacy `[[rules]]` entries are ignored and are neither imported nor activated. Older `upstream` and `source_port` keys are also ignored and have no runtime effect.

The application does not change adapter DNS settings or the original DNS destination. Windows continues to choose the resolver for unmatched queries.

## Run

Validate a configuration without enabling capture:

```powershell
cargo run -- --config .\dns-shunt.example.toml
```

Install the WinDivert runtime assets once, then run the default backend:

```powershell
.\install-windivert.ps1
cargo run -- --config .\dns-shunt.example.toml --run
```

With `--run`, the unauthenticated dashboard is available at
`http://dns-shunt.local:53080` by default (or the configured `gui_name` and
`gui_port`). The listener binds only to IPv4 loopback and retains Host
validation and same-origin checks for rule changes. Any local user or process
can view dashboard data and add, edit, reorder, or delete rules; do not expose
the listener beyond the local machine. The configured `gui_name` resolves to
loopback through intercepted DNS as well; use
`http://127.0.0.1:53080` if DNS-over-HTTPS or another DNS path bypasses
interception. A port conflict prevents capture from starting.

Foreground user rules are stored as human-readable JSON in `%APPDATA%\dns-shunt\rules.json` on Windows. The service instead uses the shared `%ProgramData%\dns-shunt\rules.json` and `%ProgramData%\dns-shunt\config.toml` files. The browser can add, edit, and delete rules immediately; exact names precede wildcards, and wildcards match subdomains but not their apex. Only matching A/IN queries receive synthesized responses. Nonmatching names, AAAA queries, other classes, malformed DNS, and unsupported messages are immediately reinjected unchanged; unmatched traffic is neither correlated nor counted. The JSON store is validated in full before it is persisted and published. Corrupt or unreadable stores fail startup rather than silently disabling overrides. Aggregate override, fail-open, and error counters, uptime, and per-rule hit counts cover only the current run and are not written to disk; individual query names are never retained. TTL, GUI name, and HTTP port remain read-only TOML settings.

## Windows Service

The service runs one machine-wide capture process as `LocalSystem`; it starts at boot without a user session. Installing it from an elevated PowerShell session is the administrator's explicit opt-in. It uses WinDivert and the fixed ProgramData config/rules paths.

Build the release executable and install the service from an elevated PowerShell at the repository root:

```powershell
cargo build --release
.\install-service.ps1
```

The installer stages the executable and signed WinDivert runtime assets under `%ProgramFiles%\dns-shunt`, creates `%ProgramData%\dns-shunt` with write access for SYSTEM and Administrators, seeds `config.toml` from the example only when absent, validates it, and creates/starts an automatic `LocalSystem` service. Check status and startup diagnostics with:

```powershell
Get-Service DnsShunt
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Dns-Shunt' }
```

The dashboard remains unauthenticated and loopback-only as described above.
Any local user or process can view status/rules or make changes; service-mode
rule changes affect all users on the computer because the TOML and JSON rule
files are shared under `%ProgramData%`. The service does not modify adapter
DNS settings or Windows resolver selection.

Stop the service through SCM, or uninstall it from an elevated PowerShell:

```powershell
Stop-Service DnsShunt
.\uninstall-service.ps1
```

Uninstall stops/deletes the service and removes its installed binaries. It preserves `%ProgramData%\dns-shunt` configuration and rules by default. Confirm ordinary DNS resumes after stopping the service.

Run commands from an elevated terminal. `--help` prints the available options and prerequisites.

## WinDivert

Install WinDivert's signed x64 runtime assets with the setup script, then run:

```powershell
.\install-windivert.ps1
cargo run -- --config .\dns-shunt.example.toml --run
```

The WinDivert setup script validates the downloaded archive size and driver signature before staging its runtime files.
