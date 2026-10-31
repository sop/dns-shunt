# Technical Details

This guide covers building, configuring, and operating DNS Shunt. For a
project overview, see the [README](../README.md).

## Requirements

- Rust stable with the MSVC toolchain for native Windows builds.
- Windows 10/11 x64 to run packet interception.
- Administrator privileges for manual foreground capture and service
  installation. Installed service control is available to local users.
- The signed WinDivert runtime assets installed by
  `scripts/install-windivert.ps1` for manual foreground capture.

The scripts in this repository do not modify adapter DNS or resolver
selection.

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
then compiles `dist\DNS-Shunt-Setup-<version>.exe` (currently
`DNS-Shunt-Setup-0.1.0.exe`). Staged files and the archive cache are isolated
under `dist\`; the workflow does not modify
`target\debug`/`target\release` runtime assets or stop an active WinDivert
driver.

The installer requires administrator privileges and Windows 10/11 x64. It
installs and starts the automatic `LocalSystem` service without changing
adapter DNS settings or resolver selection. The target computer does not need
PowerShell. Uninstall stops and removes the service and installer-owned files
while preserving
`%ProgramData%\dns-shunt\config.toml` and
`%ProgramData%\dns-shunt\rules\rules.json`.

## Build And Run The Executable

The Windows release executable is `target\release\dns-shunt.exe`. Run it
directly to validate a configuration or start capture:

```powershell
.\target\release\dns-shunt.exe --config .\dns-shunt.example.toml
.\target\release\dns-shunt.exe --config .\dns-shunt.example.toml --run
```

On a non-Windows system, Rust checks and tests can run, but packet interception
is Windows-only. A Windows-target check can also be run with:

```powershell
cargo check --target x86_64-pc-windows-msvc
```

## Configuration

Start with [`dns-shunt.example.toml`](../dns-shunt.example.toml):

```toml
ttl = 60
gui_name = "dns-shunt.local"
gui_port = 53080
log_level = "info"
log_dir = "C:\\ProgramData\\dns-shunt\\logs"
log_retention_days = 7
```

`ttl` is the default for web-managed rules. `gui_name` defaults to
`dns-shunt.local` and is a reserved built-in exact override to `127.0.0.1`;
`gui_port` defaults to `53080` and is the local HTTP listener port.
`log_level` specifies the minimum logging verbosity (`trace`, `debug`, `info`,
`warn`, or `error`), defaulting to `info`.
`log_dir` optionally overrides the directory for rolling log files in service
mode (defaults to `%ProgramData%\dns-shunt\logs`).
`log_retention_days` controls automated log pruning in service mode, defaulting
to 7 days (`0` disables pruning).

The effective log level follows the precedence order:
CLI argument (`--log-level <LEVEL>` or `-l <LEVEL>`) >
`RUST_LOG` environment variable >
`config.toml` (`log_level`) >
default (`info`).

Rules are not loaded from TOML. Legacy `[[rules]]` entries are ignored and are neither
imported nor activated. Older `upstream` and `source_port` keys are also
ignored and have no runtime effect.

The application does not change adapter DNS settings or the original DNS
destination. Windows continues to choose the resolver for unmatched queries.

## Foreground Operation

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
can view dashboard data and add, edit, or delete rules; do not expose the
listener beyond the local machine. The configured `gui_name` resolves to
loopback through intercepted DNS as well; use
`http://127.0.0.1:53080` if DNS-over-HTTPS or another DNS path bypasses
interception. A port conflict prevents capture from starting.

Foreground user rules are stored as human-readable JSON in
`%APPDATA%\dns-shunt\rules.json` on Windows. The service instead uses the
shared `%ProgramData%\dns-shunt\rules\rules.json` and
`%ProgramData%\dns-shunt\config.toml` files. The browser can add, edit, and
delete rules immediately. Rules can be A overrides (`type: "A"`, `address`) or
CNAME aliases (`type: "CNAME"`, `target`); legacy JSON entries containing only
`name`, `address`, and `ttl` load as A rules. Exact names win; otherwise, the
most-specific matching wildcard wins. Wildcards match subdomains but not their
apex. A rules answer A/IN queries only. CNAME rules answer A, AAAA, and explicit
CNAME/IN queries. For A lookups, DNS Shunt includes a local CNAME chain and
terminal A record when the target matches a local A rule. For AAAA it returns
the local CNAME chain without an AAAA record, leaving target resolution to the
configured DNS server. Explicit CNAME questions receive only the queried
alias's CNAME record. If a chain reaches an unruled target, DNS Shunt returns
the known chain and does not query upstream; clients may issue a target lookup
through the unchanged resolver path. Windows APIs and applications can differ
in how they expose or follow a CNAME-only answer; no behavior is guaranteed for
every caller. A rule queried for a different type,
nonmatching names, other classes, malformed DNS, and unsupported messages are
re-injected unchanged; unmatched traffic is neither correlated nor counted.
CNAME chains include at most 16 CNAME records, plus a terminal A record when
available, and are bounded by the advertised UDP payload size (capped at 1232
bytes). If necessary, the response contains only the longest leading CNAME
prefix that fits.
The JSON store is validated in full before it is persisted and published.
CNAME targets must be concrete DNS names, and configured chains that resolve
back into a CNAME loop are rejected.
Corrupt or unreadable stores fail startup rather than silently disabling
overrides. Aggregate override, fail-open, and error counters, uptime, and
per-rule hit counts cover only the current run and are not written to disk;
individual query names are never retained. TTL, GUI name, and HTTP port remain
read-only TOML settings.

## Windows Service

The service runs one machine-wide capture process as `LocalSystem`; it starts
at boot without a user session. Installing it through the Inno Setup package is
the administrator's explicit opt-in. The notification-area tray starts for
each interactive user at logon and is launched after setup for the installing
user. It shows shared service state and provides start/stop, GUI, and rules-file
actions. Local users can start, stop, and query the installed service without
elevation. Install, update, uninstall, and crash-recovery operations remain
administrator-only. Native commands are also available for automation:

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

Detailed operational logs are stored in daily rolling files under
`%ProgramData%\dns-shunt\logs\dns-shunt.log.<YYYY-MM-DD>`. File logs exclude
ANSI escape sequences and are automatically pruned according to
`log_retention_days` (defaulting to 7 days). Setting `log_level = "debug"`
enables structured packet disposition logging, recording whether each
intercepted DNS or mDNS query was handled or passed through and the reason.
Critical service lifecycle transitions and unhandled errors continue to report
to the Windows Event Log alongside file logging.

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

The WinDivert setup script validates the downloaded archive size and driver
signature before staging its runtime files. It inspects only outbound,
non-loopback IPv4 UDP DNS packets to port 53. IPv6, TCP/53, inbound DNS, and
loopback traffic are outside the interception scope.
The CNAME behavior above applies only to intercepted unicast UDP/53 traffic.
It does not add mDNS support: `.local` multicast queries on UDP/5353 remain
outside this path and retain their distinct link-local resolution behavior.
