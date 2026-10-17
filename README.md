# dns-shunt

`dns-shunt` is a production-ready Windows DNS override with foreground and Windows service modes. It synthesizes answers only for matching A/IN records managed through a local web interface. All other DNS packets are passed through unchanged to the resolver Windows selected; the application does not select, configure, or proxy to a resolver. It does not change adapter DNS settings. Capture is opt-in: foreground capture requires `--run`, while installing the automatic-start service is the machine-wide opt-in. WinDivert is the packet interception backend.

WinDivert inspects only outbound, non-loopback IPv4 UDP DNS packets to port 53. IPv6, TCP/53, inbound DNS, and loopback traffic are outside the interception scope.

## Requirements

- Rust stable with the MSVC toolchain for native Windows builds.
- Windows 10/11 x64 to run packet interception.
- Administrator privileges for manual foreground capture and service
  installation. Installed service control is available to local users.
- The signed WinDivert runtime assets installed by
  `scripts/install-windivert.ps1` for
  manual foreground capture.

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

Run the local interception-path microbenchmarks with:

```powershell
cargo bench --bench interception
```

The benchmark compares packet/payload copies on typical and EDNS-padded
packets against an owned-buffer pass-through, full DNS parsing against early
classification of unsupported questions, and linear rule scans/snapshot
copies against compiled lookups and shared snapshots. It also measures
uncontended receive-buffer locking. Each result is the median of five runs;
WinDivert/kernel costs are excluded. Set `DNS_SHUNT_BENCH_ITERS` to adjust
iterations per case (default: `200000`).

## Build The Windows Installer

Build the machine-wide service installer on a Windows x64 host with the Rust
x86_64 MSVC toolchain and Inno Setup 6.3+ or 7 installed. Run from any
directory:

```powershell
.\scripts\build-installer.ps1
```

The script builds the `x86_64-pc-windows-msvc` release, downloads or reuses the
pinned WinDivert 2.2.2 x64 archive, checks its SHA-256 and driver signature,
then compiles `dist\DNS-Shunt-Setup.exe`. Staged files and the archive cache
are isolated under `dist\`; the workflow does not modify
`target\debug`/`target\release` runtime assets or stop an active WinDivert
driver.

The installer requires administrator privileges and Windows 10/11 x64. It
installs and starts the automatic `LocalSystem` service without changing
adapter DNS settings or resolver selection. The target computer does not need
PowerShell. Uninstall stops and removes the service and installer-owned files
while preserving
`%ProgramData%\dns-shunt\config.toml` and
`%ProgramData%\dns-shunt\rules\rules.json`.

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
cargo run --bin dns-shunt -- --config .\dns-shunt.example.toml
```

Install the WinDivert runtime assets once, then run the default backend:

```powershell
.\scripts\install-windivert.ps1
cargo run --bin dns-shunt -- --config .\dns-shunt.example.toml --run
```

With `--run`, the unauthenticated dashboard is available at
`http://dns-shunt.local:53080` by default (or the configured `gui_name` and
`gui_port`). The listener binds only to IPv4 loopback and retains Host
validation and same-origin checks for rule changes. Any local user or process
can view dashboard data and add, edit, or delete rules; do not expose
the listener beyond the local machine. The configured `gui_name` resolves to
loopback through intercepted DNS as well; use
`http://127.0.0.1:53080` if DNS-over-HTTPS or another DNS path bypasses
interception. A port conflict prevents capture from starting.

Foreground user rules are stored as human-readable JSON in
`%APPDATA%\dns-shunt\rules.json` on Windows. The service instead uses the
shared `%ProgramData%\dns-shunt\rules\rules.json` and
`%ProgramData%\dns-shunt\config.toml` files. The browser can add, edit, and
delete rules immediately. Exact names win; otherwise, the most-specific
matching wildcard wins. Wildcards match subdomains but not their apex. Only
matching A/IN queries receive synthesized responses. Nonmatching names, AAAA
queries, other classes, malformed DNS, and unsupported messages are immediately
reinjected unchanged; unmatched traffic is neither correlated nor counted. The
JSON store is validated in full before it is persisted and published. Corrupt
or unreadable stores fail startup rather than silently disabling overrides.
Aggregate override, fail-open, and error counters, uptime, and per-rule hit
counts cover only the current run and are not written to disk; individual query
names are never retained. TTL, GUI name, and HTTP port remain read-only TOML
settings.

## Windows Service

The service runs one machine-wide capture process as `LocalSystem`; it starts
at boot without a user session. Installing it through the Inno Setup package is
the administrator's explicit opt-in. The notification-area tray starts for
each interactive user at logon and is launched after setup for the installing
user. It shows shared service state and provides start/stop, GUI, and rules-file
actions. Local users can start, stop, and query the installed service without
elevation. Install, update, uninstall,
and crash-recovery operations remain administrator-only. Native commands are
also available for automation:

```powershell
.\target\release\dns-shunt.exe --install-service
.\target\release\dns-shunt.exe --start-service
.\target\release\dns-shunt.exe --stop-service
.\target\release\dns-shunt.exe --uninstall-service
```

Installation and uninstallation require an elevated administrator. Start and
stop use SCM authorization and are available to local users. Installation
creates `%ProgramData%\dns-shunt`, keeps the directory protected, grants local
users read-only access to `config.toml`, seeds it only when absent, validates
it, registers the `Dns-Shunt` Event Log source, and creates or updates and
starts the automatic service. The shared rules file is under
`%ProgramData%\dns-shunt\rules\rules.json`; local users can edit it only while
the service is stopped. The service revokes that access before loading rules
and restores it after shutdown or a handled startup failure. The tray disables
Open Rules File while running and disables Open GUI while stopped. Starting
the service from the tray does not require confirmation. The installer stages
both executables, the signed WinDivert runtime, and example configuration under
`%ProgramFiles%\DNS Shunt`. Check status and startup diagnostics with:

```powershell
Get-Service DnsShunt
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Dns-Shunt' }
```

The dashboard remains unauthenticated and loopback-only as described above.
Any local user or process can view the loopback dashboard and change its rules
while the service is running. Service-mode rule changes affect every account
on the computer because the rules file is shared under `%ProgramData%`. Users
can also edit the shared JSON file directly while the service is stopped; those
changes load on the next start. The tray opens the configured GUI hostname and
port from `config.toml`. The service does not modify adapter DNS settings or
Windows resolver selection.

Stop the service through SCM or the native command, or remove it through
Windows Apps > Installed apps:

```powershell
.\target\release\dns-shunt.exe --stop-service
```

Uninstall stops/deletes the service and removes its installed binaries and
Event Log registration. It preserves `%ProgramData%\dns-shunt` configuration
and rules. Confirm ordinary DNS resumes after stopping the service.

Run install/uninstall commands from an elevated terminal. `--help` prints the
available options and prerequisites.

## WinDivert

Install WinDivert's signed x64 runtime assets with the setup script, then run:

```powershell
.\scripts\install-windivert.ps1
cargo run --bin dns-shunt -- --config .\dns-shunt.example.toml --run
```

The WinDivert setup script validates the downloaded archive size and driver signature before staging its runtime files.
