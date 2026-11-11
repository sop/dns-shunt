# DNS Shunt

DNS Shunt is a Windows utility for managing local DNS overrides. Use its
browser-based dashboard to direct selected domain names to chosen IPv4 addresses,
IPv6 addresses, or local CNAME targets without changing your Windows DNS settings.

## What It Does

- Create, edit, and remove DNS override rules in a local dashboard.
- Create A (IPv4) overrides, AAAA (IPv6) overrides, and CNAME aliases,
  including wildcard aliases.
- Match a domain exactly or use a wildcard for its subdomains.
- Intercept outbound standard unicast DNS (UDP/53) and multicast DNS (mDNS
  on UDP/5353) across IPv4 and IPv6.
- Dual-stack support: A and AAAA rules for the same domain or wildcard can
  coexist. For standard DNS, queries for an unconfigured address family pass
  through fail-open to the resolver selected by Windows.
- An exact-name rule takes precedence over wildcard rules for every query type.
  If its record type does not match the query, the query passes through rather
  than falling back to a wildcard rule.
- Run as a Windows service with a notification-area tray app, or run it
  manually when needed.
- View current-run activity, uptime, passed-through and fail-open counts,
  errors, and rule hits. Passed-through counts DNS/mDNS requests successfully
  sent onward when local rules did not fully handle them; fail-open recovery is
  excluded.
  Query names are not part of the dashboard statistics, but debug logs include
  DNS and mDNS question names.

DNS Shunt only handles supported matching DNS and mDNS requests. Unmatched
unicast DNS follows the resolver path selected by Windows; unmatched mDNS is
forwarded on its multicast link. The app does not change network adapter
settings or configure a resolver. For standard DNS, CNAME chains are resolved
locally when they reach a matching A or AAAA rule; if a target is not locally
ruled, DNS Shunt returns the known CNAME chain without querying upstream. The
client may then look up that target through the unchanged DNS path. For mDNS,
outbound link-local queries on UDP/5353 across IPv4 (224.0.0.251) and IPv6
([ff02::fb]) support A, AAAA, CNAME, and ANY questions with known-answer
suppression and fail-open forwarding. An mDNS CNAME answer may include an
exact-name A or AAAA rule for its target.

## Use Cases

- **Local development:** Point development domains or .local mDNS names at a
  local service while keeping the hostname your app expects.
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

When enabled, DNS Shunt checks supported outbound IPv4 and IPv6 DNS requests
(UDP/53) and multicast DNS requests (UDP/5353) against your rules. A match
receives a synthesized answer; anything else continues to the physical network
or the resolver selected by Windows. Capture is opt-in for manual runs. The
Windows service starts at boot only after an administrator installs it.

See the [technical guide](docs/technical-details.md) for configuration,
installation details, service operation, and packet-handling scope.
