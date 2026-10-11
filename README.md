# dns-shunt

`dns-shunt` is a foreground Windows DNS interception prototype. It returns IPv4 A-record overrides managed through a local web interface and forwards other supported DNS queries to a configured upstream resolver. Capture and the web interface are opt-in; without `--run`, the program only validates TOML configuration. WinDivert is the default interception backend; the experimental WFP backend remains available through explicit selection.

The WFP backend is experimental kernel-driver code. It has not been independently validated across Windows versions and is not production-ready. Use it only in a disposable Windows test environment.

## Requirements

- Rust stable with the MSVC toolchain for native Windows builds.
- Windows 10/11 x64 to run packet interception.
- Administrator privileges to start interception.
- The signed WinDivert runtime assets installed by `install-windivert.ps1` for the default backend.
- For WFP development: Visual Studio or Build Tools with MSBuild and the Windows Driver Kit (WDK).
- A disposable test VM with the required test-driver signing configuration to load a locally built WFP driver. Secure Boot and system policy may prevent test drivers from loading.

The scripts in this repository do not enable test signing or modify BCD, Secure Boot, adapter DNS, or persistent WFP policy. Do not weaken boot security on a normal workstation to test this prototype.

## Build And Validate

From the repository root:

```powershell
cargo fmt --check
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The Windows release executable is `target\release\dns-shunt.exe`. Run it directly to validate a configuration or start the selected backend:

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
upstream = "1.1.1.1"
source_port = 53053
ttl = 60
gui_name = "dns-shunt.local"
gui_port = 8080
```

`upstream` is an IPv4 resolver address on UDP port 53. `source_port` is exclusively bound while the proxy runs and excluded from capture to prevent recapturing its own upstream requests. `ttl` is the default for web-managed rules. `gui_name` defaults to `dns-shunt.local` and is a reserved built-in exact override to `127.0.0.1`; `gui_port` defaults to `8080` and is the local HTTP listener port. Rules are not loaded from TOML. Legacy `[[rules]]` entries are ignored and are neither imported nor activated.

The application does not change adapter DNS settings. The example addresses are from documentation-only ranges; replace them with addresses appropriate to your test.

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

With `--run`, the dashboard is available at `http://127.0.0.1:8080` (or the configured `gui_port`). The listener binds only to IPv4 loopback and must be accessed using an allowed local Host/Origin. It has no login and must not be exposed beyond the local machine. The configured `gui_name` resolves to loopback through intercepted DNS as well; use the numeric URL if DNS-over-HTTPS or another DNS path bypasses interception. A port conflict prevents capture from starting.

User rules are stored as human-readable JSON in `%APPDATA%\dns-shunt\rules.json` on Windows. The browser can add, edit, and delete rules immediately; exact names precede wildcards, and wildcards match subdomains but not their apex. The JSON store is validated in full before it is persisted and published. Corrupt or unreadable stores fail startup rather than silently disabling overrides. Aggregate counters, uptime, and per-rule hit counts cover only the current run and are not written to disk; individual query names are never retained. Upstream, DNS source port, default TTL, GUI name, and HTTP port remain read-only TOML settings.

WinDivert can also be selected explicitly. The experimental WFP backend remains available with `--backend wfp`:

```powershell
cargo run -- --config .\dns-shunt.example.toml --run --backend windivert
cargo run -- --config .\dns-shunt.example.toml --run --backend wfp
```

Run commands from an elevated terminal. The WFP driver must already be installed when selecting that backend. `--help` prints the available options and prerequisites.

## Develop And Test WFP

### Build The Driver

Open an x64 Developer PowerShell with the WDK installed, then build the WDK project from the repository root:

```powershell
msbuild .\driver\DnsShuntWfp.vcxproj /m /p:Configuration=Debug /p:Platform=x64
```

The project is configured for WDK test signing. The generated package is expected under `driver\x64\Debug` and includes the INF, SYS, and CAT files required by the install script. The test certificate and test-signing policy must be handled using your approved workflow on a disposable VM; the repository does not change those settings.

### Install And Start

From an elevated PowerShell in the repository root:

```powershell
.\driver\install-wfp.ps1 -PackageDirectory .\driver\x64\Debug
```

This stages the driver package, copies the driver to the Windows drivers directory, registers the demand-start kernel service if needed, and starts it. The script refuses to run without administrator privileges and does not modify boot-security settings.

If the service is stopped, the WFP backend starts it for the run and stops it when the application exits. If the install script already started the service, the application leaves that pre-existing service running; the WFP filters themselves are dynamic and are removed when the application exits.

### Run Queries

Run the application elevated with the test configuration:

```powershell
cargo run -- --config .\dns-shunt.example.toml --run --backend wfp
```

In another terminal, query the configured override directly through the upstream resolver:

```powershell
Resolve-DnsName dev.example.com -Type A -Server 1.1.1.1 -DnsOnly
```

The answer should contain the configured address (`192.0.2.10` in the example). An unmatched name should be forwarded upstream:

```powershell
Resolve-DnsName example.com -Type A -Server 1.1.1.1 -DnsOnly
```

To exercise the wildcard rule, query a name below `test.example.net`, such as `host.test.example.net`. Use a DNS query tool that sends ordinary IPv4 UDP DNS to port 53; the current WFP filter does not intercept IPv6, TCP DNS, inbound queries, loopback traffic, or traffic from the reserved upstream source port.

Press Ctrl+C in the proxy terminal to stop. Confirm ordinary DNS works afterward and that no dynamic WFP filter remains. If the install script started the driver, stop and remove the service with:

```powershell
.\driver\remove-wfp.ps1
```

Add `-RemovePackage` to remove the staged driver package as well:

```powershell
.\driver\remove-wfp.ps1 -RemovePackage
```

### Failure And Regression Checks

For driver or proxy changes, verify at minimum:

- Configured A overrides and unmatched upstream forwarding.
- Parallel queries with repeated DNS transaction IDs.
- Malformed DNS and upstream timeout behavior.
- Ctrl+C, controller process termination, and driver stop restore normal DNS without duplicate replies.
- Queue saturation fails open and does not leave packets held.
- Non-DNS UDP, loopback, reserved-source-port traffic, IPv6, and inbound DNS are not captured.
- The client-visible response tuple is the reverse of the original query tuple, and dynamic filters disappear on exit.

These packet-level checks require a disposable, correctly configured Windows test VM. The WFP driver has not been built or validated in every supported environment; successful Rust tests do not establish kernel-driver safety.

## WinDivert Backend

WinDivert is the default backend. Install its signed x64 runtime assets with the setup script, then run without an explicit backend selection:

```powershell
.\install-windivert.ps1
cargo run -- --config .\dns-shunt.example.toml --run
```

The WinDivert setup script validates the downloaded archive size and driver signature before staging its runtime files.
