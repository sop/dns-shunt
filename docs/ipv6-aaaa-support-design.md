# Future Design: IPv6 and AAAA Support

**Status:** Proposed; no implementation is implied by this memo.

## Purpose and Scope

DNS Shunt currently intercepts outbound, non-loopback IPv4 UDP queries to
port 53 and synthesizes A/IN answers for matching rules. This memo proposes
adding IPv6 support without changing resolver selection, adapter DNS settings,
or the existing opt-in and fail-open behavior.

Two separate capabilities are involved:

- **IPv6 DNS transport:** capture DNS packets carried over IPv6, including
  queries sent to an IPv6 DNS server.
- **AAAA records:** match QTYPE AAAA and synthesize IPv6 address records.

Either capability can be useful without the other. AAAA records can be
queried over IPv4 transport, and IPv6 transport can carry existing A queries.
The design should implement and test them independently before enabling them
together.

This proposal concerns unicast DNS on UDP port 53. IPv6 mDNS on
`[ff02::fb]:5353` is a distinct protocol and remains out of scope; see
`mdns-support-design.md`.

## Current Constraints

- The WinDivert filter selects IPv4 UDP/53 traffic.
- `packet::FlowTuple` and IPv4 packet parsing/building use `Ipv4Addr`.
- The WinDivert backend only extracts IPv4/UDP tuples and constructs IPv4
  responses.
- DNS classification accepts only A/IN queries; the A response builder emits
  a four-byte IPv4 RDATA value.
- Each rule stores one `Ipv4Addr`. Unmatched names and all AAAA queries are
  reinjected unchanged.

These boundaries mean that adding AAAA parsing alone would not provide a
usable IPv6 override, and broadening the WinDivert filter alone would only
cause IPv6 packets to fail open until the packet backend supports them.

## Proposed Behavior

1. Preserve the current IPv4 A/IN path and its response behavior.
2. Add IPv6 UDP/53 capture and response injection as a distinct packet-family
   path. Reverse the original source/destination addresses and ports when
   synthesizing a response, and preserve required WinDivert interface metadata
   for scoped IPv6 DNS servers.
3. Add AAAA/IN question handling. A matching IPv6 address rule returns an
   AAAA record whose RDATA is the address's 16 network-order octets.
4. Select address rules by both owner-name match and query type. An A query
   uses an IPv4 address; an AAAA query uses an IPv6 address. A rule for one
   family must not be emitted as the other record type.
5. Continue to reinject unmatched names, unsupported query types, unsupported
   packet forms, and malformed messages unchanged. Do not fabricate negative
   answers for a family that has no matching rule in the initial design.
6. Keep capture opt-in for foreground use and preserve explicit Windows
   service installation requirements.

An A or AAAA query may be carried by either IPv4 or IPv6 transport. Rule
matching must depend on the DNS question, not the outer packet family.

## Rule Model

The current rule has one `address` field that must parse as IPv4. The future
model must represent record family explicitly or infer it from an `IpAddr`
value. Conceptually, a hostname may have both records:

```text
service.example.test  A      192.0.2.10
service.example.test  AAAA   2001:db8::10
```

Allow one A and one AAAA rule for the same canonical owner and wildcard
setting, while rejecting duplicate rules for the same owner and family. Keep
exact-name precedence and most-specific wildcard matching independently for
each family. CNAME rules, if implemented, remain mutually exclusive with A
and AAAA rules at the same owner name.

Persisted rules are user data: choose a schema and migration policy before
changing `rules.json`. A compatible option is to keep the existing `name`,
`address`, and `ttl` shape and parse `address` as an IP address; its family
determines A versus AAAA. This permits existing IPv4 rules to remain valid and
allows two entries for one name when their address families differ. The API
and dashboard must display the inferred record type, validate family-specific
duplicates, and allow separate A and AAAA entries.

The GUI hostname currently resolves through the built-in IPv4 loopback
override. If GUI IPv6 loopback behavior is desired, it must be an explicit
decision rather than an automatic consequence of enabling AAAA records.

## DNS Answer Construction

For a matching A query, retain the current A response format. For a matching
AAAA query, emit an AAAA RR with TYPE 28, CLASS IN, the selected rule TTL,
RDLENGTH 16, and the IPv6 address octets. Preserve the query ID, question,
relevant flags, and any valid EDNS data. Update section counts and bounds-check
all sizes before injecting the response.

If CNAME rules are added, an A query can include the matching CNAME chain and
its terminal A record when the target resolves to a local A rule. Likewise,
an AAAA query can include that chain and its terminal AAAA record when the
target resolves to a local AAAA rule. Do not put an A record in place of an
AAAA answer. If no local terminal record exists for the requested family,
return the CNAME chain alone and let the normal resolver path continue. Bound
chain depth and detect loops; on an unsafe chain, fail open rather than emit a
partial or malformed answer.

Each record in a synthesized chain has its own configured TTL. Test packet
size and EDNS behavior for multi-record answers; if a response cannot be
safely represented within supported limits, fail open rather than truncate
silently.

## IPv6 Packet Handling

Packet-family-neutral flow data is preferable to duplicating interception
logic. A tuple can use `IpAddr` for source and destination, while packet
parsing and response building retain family-specific validation and
serialization. Keep the original WinDivert address metadata alongside the
tuple so reinjection and response injection preserve interface information.

IPv6 response construction must account for:

- The 40-byte base header, payload length, next-header value, hop limit, and
  reversed endpoint addresses.
- UDP length and the IPv6 pseudo-header checksum. Unlike IPv4 UDP, an IPv6 UDP
  checksum is required and cannot be sent as zero.
- Link-local DNS server addresses, whose usable scope depends on the
  interface index from the captured packet.
- WinDivert checksum handling and prevention of response recapture.
- Extension headers and fragmentation. The initial implementation may
  support only packets it can safely parse, but unsupported captured packets
  must be reinjected byte-for-byte. Filter design must not silently drop
  unsupported traffic.

The WinDivert filter should be broadened only to the intended outbound,
non-loopback IPv6 UDP/53 traffic. It must not capture IPv6 TCP/53, inbound
traffic, loopback traffic, or mDNS as a side effect. Preserve existing IPv4
filter behavior.

## Address-Family Fallback

The initial recommendation is independent, fail-open family matching:

- A rule answers A queries; an AAAA rule answers AAAA queries.
- If a name has only an A rule, its AAAA query is reinjected unchanged.
- If a name has only an AAAA rule, its A query is reinjected unchanged.
- A name with both rules receives the appropriate record for each query.

This preserves the current behavior for unsupported or unmatched questions,
but it has an important consequence: clients that ask for both families may
receive an upstream address for a family without a local rule. If users need
an IPv4-only or IPv6-only override to suppress upstream results for the other
family, add an explicit policy (for example, return NODATA for the missing
family). Do not make that behavior implicit in the first AAAA implementation.

## Testing Plan

- Unit-test IPv6 UDP packet parsing/building, reversed tuples, lengths, and
  mandatory UDP checksums, including scoped link-local flow metadata where
  testable.
- Test malformed headers, fragments, extension headers, unsupported transport
  forms, and oversized packets; confirm captured unsupported traffic is
  reinjected byte-for-byte.
- Test AAAA question classification and construction of 16-byte RDATA, along
  with malformed and non-IN questions.
- Test A and AAAA rules for the same name, duplicate-family rejection,
  wildcard matching, exact-name precedence, and family mismatch pass-through.
- Test queries for A and AAAA over both IPv4 and IPv6 transport.
- If CNAME support is implemented, test internal chain synthesis for A and
  AAAA separately, target-family selection, independent TTLs, loop detection,
  and fallback when the target has no matching rule.
- On Windows, test response injection to IPv4 and IPv6 DNS servers, including
  a link-local DNS server, and verify no adapter DNS or resolver-selection
  changes occur.
- Exercise Windows DNS APIs and representative applications. Verify actual
  A/AAAA query behavior, cache behavior, and pass-through using packet capture.
- Confirm IPv6 DNS capture does not include IPv6 mDNS, inbound DNS, loopback,
  or TCP/53.

## Rollout

Implement in stages: first make packet flow handling family-neutral while
keeping IPv4 behavior unchanged; next add IPv6 UDP/53 parsing and response
injection with DNS queries still passed through; then add AAAA rule storage,
matching, and response construction; finally add the optional CNAME-chain
integration. Update `technical-details.md`, the dashboard/API, examples, and
installer behavior only when implementation is ready. Until then, document
IPv6 and AAAA traffic as unsupported and fail it open.

## Open Decisions

- Whether extension headers are supported initially or always fail open.
- The exact persisted rule schema and migration behavior for existing JSON.
- Whether an absent address family always passes through or may be configured
  to return NODATA.
- Whether IPv6 loopback is supported for the built-in GUI hostname.
- Whether CNAME chain synthesis ships with AAAA support or remains a separate
  follow-up feature.
- How IPv6 packet-family and address-family counters are represented without
  retaining queried names.
