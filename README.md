# DNS Shunt

DNS Shunt is a Windows utility for managing local DNS overrides. Use its
browser-based dashboard to direct selected domain names to chosen IP addresses
or local CNAME targets without changing your Windows DNS settings.

## What It Does

- Create, edit, and remove DNS override rules in a local dashboard.
- Create A address overrides and CNAME aliases, including wildcard aliases.
- Match a domain exactly or use a wildcard for its subdomains.
- Run as a Windows service with a notification-area tray app, or run it
  manually when needed.
- View current-run activity and rule hit counts. DNS query names are not
  retained.

DNS Shunt only handles supported matching DNS requests. Other requests are
passed through unchanged, and Windows continues to choose the DNS resolver.
The app does not change network adapter settings or configure a resolver.
CNAME chains are resolved locally when they reach a matching A rule; if a
target is not locally ruled, DNS Shunt returns the known CNAME chain without
querying upstream. The client may then look up that target through the unchanged
DNS path.

## Use Cases

- **Local development:** Point development domains at a local service while
  keeping the hostname your app expects.
- **Staging and QA:** Direct selected domains to a staging or QA endpoint from
  your machine without changing system DNS settings.
- **Deployment testing:** Check a new server by its production hostname before
  changing public DNS.
- **Migration and rollback:** Temporarily direct a hostname to an old or new
  endpoint while validating a migration or recovery.
- **Virtual host and TLS checks:** Test hostname-based web server routing and
  certificates against a chosen server IP.
- **Troubleshooting:** Reproduce an issue against a diagnostic endpoint or
  resolve an internal service name to a reachable private IP.

## Requirements

- Windows 10 or 11, 64-bit.
- Administrator access to install the Windows service or run manual packet
  capture.

The dashboard is available only on the local computer and has no sign-in.
Anyone or any software running on that computer can view it and change rules;
do not expose it to your network.

## Get Started

Download the latest Windows installer from the
[Releases page](https://github.com/sop/dns-shunt/releases) and run it as an
administrator. Setup installs and starts the service and tray app. Use the
tray icon to open the dashboard, manage rules, or control the service.

## For Developers

For source builds, temporary foreground runs, configuration, and service
operation, see the [technical guide](docs/technical-details.md). An example
configuration is available in [`dns-shunt.example.toml`](dns-shunt.example.toml).

## How It Works

When enabled, DNS Shunt checks supported outbound IPv4 DNS requests against
your rules. A match receives a synthesized answer; anything else continues to
the resolver selected by Windows. Capture is opt-in for manual runs. The
Windows service starts at boot only after an administrator installs it.

See the [technical guide](docs/technical-details.md) for configuration,
installation details, service operation, and packet-handling scope.
