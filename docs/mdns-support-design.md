# Future Design: mDNS Support

**Status:** Proposed; no implementation is implied by this memo.

## Motivation

DNS Shunt currently intercepts outbound, non-loopback IPv4 UDP queries to
port 53. That covers conventional unicast DNS, but `.local` names may be
resolved using multicast DNS (mDNS) on UDP port 5353 instead. Such traffic
does not reach the current interception path.

The motivating rule set is:

```text
example.local        A      <configured IPv4 address>
*.example.local      CNAME  example.local
```

A lookup for `api.example.local` should receive a CNAME to
`example.local`; a subsequent lookup for the target should receive its
configured A record. Names without an applicable DNS Shunt rule must
continue to be answered by other mDNS participants without modification.

## Protocol Boundary

mDNS is not unicast DNS with a different port. It is link-local multicast
discovery and does not provide recursive resolution. The implementation
must keep mDNS separate from the existing unicast DNS behavior:

- IPv4 mDNS uses `224.0.0.251:5353`; IPv6 mDNS uses
  `[ff02::fb]:5353`.
- Responses are link-scoped. IPv6 handling must preserve the network
  interface/scope used by the captured packet.
- mDNS packets have protocol-specific requirements, including a
  link-local TTL/hop limit of 255, query flags, and response record
  semantics. A unicast DNS response builder must not be reused without
  adapting and validating those details.
- Resolving a CNAME target requires another mDNS query when that target
  is a `.local` name. The app must not assume a unicast recursive server
  will resolve it.

## Proposed Behavior

1. Add a distinct mDNS packet path. Initially limit it to valid DNS
   messages sent to the mDNS multicast destination and UDP port 5353.
   Handle IPv4 and IPv6 explicitly; do not broaden the unicast DNS filter
   as a side effect.
2. Match explicit rules using the existing exact-name-first,
   most-specific-wildcard policy. Wildcards match subdomains but not
   their apex, so the example wildcard does not shadow the exact
   `example.local` A rule.
3. For a matching rule, synthesize an mDNS-formatted answer for the
   supported record type. A wildcard CNAME answer points to
   `example.local`; a later query for `example.local` matches its A rule.
   Support both A and AAAA queries that need the alias, along with
   explicit CNAME queries, so parallel address lookups do not bypass the
   alias. IPv6 address overrides are a separate capability and should
   not be implied by CNAME support.
4. For names without an applicable local rule, reinject captured queries
   unchanged. Do not terminate, proxy, or synthesize answers for ordinary
   mDNS traffic. Leave inbound responses from other participants
   untouched.
5. For malformed or unsupported packets, fail open by reinjecting the
   original packet unchanged, consistent with the current safety model.

For a future mDNS path, CNAMEs not overridden by DNS Shunt would remain the
responsibility of other mDNS participants. That path would supply a configured
CNAME for a matching local rule but would not chase arbitrary CNAME chains.
This remains separate from local CNAME-chain resolution on unicast UDP/53.

## Rule Model

Unicast rules now distinguish A addresses from CNAME targets. Legacy JSON
rules containing only an address load as A records, and new rules serialize
their type explicitly. The dashboard and API expose only the data field valid
for each type. Unicast CNAME targets are encoded as DNS names in RDATA.

This rule-model change does not implement mDNS. The existing WinDivert path
still captures only outbound, non-loopback IPv4 UDP queries to port 53; mDNS
multicast on UDP/5353 remains outside interception. Even if a configured CNAME
uses a `.local` name, this does not make the target resolvable through mDNS or
change the separate resolution behavior described in this memo.

## Capture And Response Requirements

- Extend capture deliberately for mDNS multicast, rather than capturing
  all UDP/5353 traffic. Preserve interface metadata required to send a
  response on the same link.
- Define response delivery for multicast questions and questions that
  request a unicast response. Preserve correct IP/UDP addressing and
  checksums for each supported network family.
- Parse and validate mDNS questions before applying rules. Account for
  the mDNS-specific question class bits, known-answer sections, and
  response flags instead of assuming unicast DNS header conventions.
- Construct standards-compliant answer records, including mDNS class,
  cache-flush behavior where applicable, and bounded TTLs.
- Avoid responding to a query more than once and prevent a packet
  injected by DNS Shunt from being recaptured as a new query.
- Keep statistics privacy-preserving. Existing aggregate counters can
  distinguish local mDNS answers from pass-through packets without
  retaining queried names.

## Safety And Interoperability

mDNS is shared on a link. Another device may already answer for a
configured name, potentially producing multiple or conflicting records.
The initial implementation should define how configured names interact
with existing responders and how conflicts are surfaced. It must not
silently claim or announce names unless probing, conflict detection, and
announcement behavior are designed explicitly.

Do not modify adapter DNS settings, resolver selection, or unicast DNS
behavior. Keep capture opt-in for foreground use and preserve explicit
service-installation requirements. Unsupported mDNS records and packets
must remain fail-open.

## Testing Plan

- Unit-test mDNS name parsing, compression bounds, question class bits,
  known-answer sections, record construction, and malformed input.
- Test the motivating flow: wildcard A query receives CNAME, target A
  query receives the exact A override, and the wildcard does not match
  the apex.
- Test explicit CNAME and AAAA questions for a CNAME rule.
- Test that an unconfigured mDNS name and an unconfigured CNAME query
  are reinjected byte-for-byte and that other participants' responses
  are not rewritten.
- Test IPv4 and IPv6 multicast scope, response destination selection,
  TTL/hop limit, checksums, duplicate suppression, and recapture
  prevention on Windows with WinDivert.
- Exercise Windows name-resolution APIs and representative applications;
  verify actual packet behavior because applications may differ in how
  they use mDNS and CNAME answers.

## Open Decisions

- Whether the first release supports both IPv4 and IPv6 mDNS or ships
  IPv4-only with an explicit limitation.
- Which record types are supported initially beyond A and CNAME. AAAA
  query aliasing is useful, but local AAAA overrides and DNS-SD records
  such as PTR, SRV, and TXT are distinct features.
- How to handle name conflicts and whether the app should ever probe or
  announce configured records.
- How to represent A and CNAME variants in the existing JSON rule store
  without surprising existing users.
- Whether mDNS-specific hit and pass-through counters are needed in the
  dashboard.
