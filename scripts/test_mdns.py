import argparse
import socket
import struct
import sys

RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

RCODES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
}


def encode_domain(domain: str) -> bytes:
    domain = domain.strip().rstrip(".")
    if not domain:
        return b"\x00"
    encoded = b""
    for part in domain.split("."):
        part_bytes = part.encode("utf-8")
        if len(part_bytes) > 63:
            raise ValueError(f"Label '{part}' exceeds 63 bytes")
        encoded += bytes([len(part_bytes)]) + part_bytes
    return encoded + b"\x00"


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS label sequence, handling compression pointers."""
    labels = []
    curr = offset
    jumped = False
    next_offset = offset
    visited = set()

    while curr < len(data):
        length = data[curr]

        # Compression pointer (starts with bits 11: 0xC0)
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                if not jumped:
                    next_offset = len(data)
                break
            ptr = struct.unpack("!H", data[curr : curr + 2])[0] & 0x3FFF
            if not jumped:
                next_offset = curr + 2
                jumped = True
            if ptr in visited or ptr >= len(data):
                break
            visited.add(ptr)
            curr = ptr
            continue

        curr += 1
        if length == 0:
            if not jumped:
                next_offset = curr
            break

        if curr + length > len(data):
            if not jumped:
                next_offset = len(data)
            break
        labels.append(data[curr : curr + length].decode("utf-8", errors="replace"))
        curr += length

    if not jumped:
        next_offset = curr

    return ".".join(labels), next_offset


def format_hex_dump(data: bytes, indent: str = "  ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{i:04x}  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines)


def print_dns_response(data: bytes, addr: tuple[str, int]) -> None:
    if len(data) < 12:
        print(f"Packet too short ({len(data)} bytes) from {addr}")
        return

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )

    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF
    rcode_str = RCODES.get(rcode, f"RCODE({rcode})")

    flag_names = []
    if qr:
        flag_names.append("QR (Response)")
    else:
        flag_names.append("QR (Query)")
    if aa:
        flag_names.append("AA (Authoritative)")
    if tc:
        flag_names.append("TC (Truncated)")
    if rd:
        flag_names.append("RD (Recursion Desired)")
    if ra:
        flag_names.append("RA (Recursion Available)")

    print(f"\n--- Header (from {addr[0]}:{addr[1]}) ---")
    print(f"  Transaction ID: 0x{tx_id:04x} ({tx_id})")
    print(
        f"  Flags: 0x{flags:04x} [Opcode={opcode}, Status={rcode_str}, {', '.join(flag_names)}]"
    )
    print(
        f"  Counts: Questions={qdcount}, Answers={ancount}, Authority={nscount}, Additional={arcount}"
    )

    offset = 12

    # Questions
    if qdcount > 0:
        print(f"\n--- Questions ({qdcount}) ---")
        for i in range(qdcount):
            qname, offset = decode_name(data, offset)
            if offset + 4 > len(data):
                print(f"  [{i+1}] Truncated question")
                break
            qtype, raw_qclass = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            qclass = raw_qclass & 0x7FFF
            qu = bool(raw_qclass & 0x8000)
            qtype_str = RECORD_TYPES.get(qtype, f"TYPE({qtype})")
            class_str = "IN" if qclass == 1 else f"CLASS({qclass})"
            qu_str = " (QU/unicast)" if qu else " (QM/multicast)"
            name_display = f"{qname}." if qname else "."
            print(f"  [{i+1}] {name_display} {class_str} {qtype_str}{qu_str}")

    # Helper for Resource Records
    def parse_records(section_name: str, count: int, curr_offset: int) -> int:
        if count == 0:
            return curr_offset
        print(f"\n--- {section_name} ({count}) ---")
        for i in range(count):
            if curr_offset >= len(data):
                print("  [Truncated packet]")
                break
            name, curr_offset = decode_name(data, curr_offset)
            if curr_offset + 10 > len(data):
                print("  [Truncated record header]")
                break
            rtype, raw_rclass, ttl, rdlength = struct.unpack(
                "!HHIH", data[curr_offset : curr_offset + 10]
            )
            curr_offset += 10
            rclass = raw_rclass & 0x7FFF
            flush = bool(raw_rclass & 0x8000)
            rtype_str = RECORD_TYPES.get(rtype, f"TYPE({rtype})")
            class_str = "IN" if rclass == 1 else f"CLASS({rclass})"

            rd_start = curr_offset
            rd_end = curr_offset + rdlength
            if rd_end > len(data):
                name_display = f"{name}." if name else "."
                print(
                    f"  [{i+1}] {name_display} {ttl}s {class_str} {rtype_str} [Truncated RDATA]"
                )
                curr_offset = len(data)
                break

            rdata = data[rd_start:rd_end]
            try:
                if rtype == 1 and rdlength == 4:  # A
                    rdata_desc = socket.inet_ntoa(rdata)
                elif rtype == 28 and rdlength == 16:  # AAAA
                    if hasattr(socket, "inet_ntop"):
                        rdata_desc = socket.inet_ntop(socket.AF_INET6, rdata)
                    else:
                        rdata_desc = ":".join(
                            f"{rdata[j:j+2].hex()}" for j in range(0, 16, 2)
                        )
                elif rtype in (2, 5, 12):  # NS, CNAME, PTR
                    target_name, _ = decode_name(data, rd_start)
                    rdata_desc = f"{target_name}." if target_name else "."
                elif rtype == 16:  # TXT
                    txts = []
                    tp = 0
                    while tp < len(rdata):
                        tlen = rdata[tp]
                        tp += 1
                        txts.append(
                            rdata[tp : tp + tlen].decode("utf-8", errors="replace")
                        )
                        tp += tlen
                    rdata_desc = '"' + '" "'.join(txts) + '"'
                elif rtype == 33 and rdlength >= 6:  # SRV
                    pri, weight, port = struct.unpack("!HHH", rdata[:6])
                    target_name, _ = decode_name(data, rd_start + 6)
                    target_display = f"{target_name}." if target_name else "."
                    rdata_desc = f"priority={pri}, weight={weight}, port={port}, target={target_display}"
                else:
                    rdata_desc = f"0x{rdata.hex()}"
            except Exception as e:
                rdata_desc = f"0x{rdata.hex()} (parse error: {e})"

            flush_str = " [cache-flush]" if flush else ""
            name_display = f"{name}." if name else "."
            print(
                f"  [{i+1}] {name_display} {ttl}s {class_str}{flush_str} {rtype_str} {rdata_desc}"
            )
            curr_offset = rd_end
        return curr_offset

    offset = parse_records("Answers", ancount, offset)
    offset = parse_records("Authority", nscount, offset)
    offset = parse_records("Additional Records", arcount, offset)

    print(f"\n--- Hex Dump ({len(data)} bytes) ---")
    print(format_hex_dump(data))


def main():
    parser = argparse.ArgumentParser(description="Send an mDNS query for a domain.")
    parser.add_argument(
        "domain",
        nargs="?",
        default="example.local",
        help="Domain name to query (default: example.local)",
    )
    args = parser.parse_args()
    domain = args.domain

    try:
        qname = encode_domain(domain)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Raw DNS query packet (Type A, Class IN, unicast-response bit set)
    # Transaction ID: 0x0000 (standard for mDNS)
    # Flags: 0x0000 (standard query)
    # Questions: 1, Answers: 0, Authority: 0, Additional: 0
    query = (
        b"\x00\x00"  # Transaction ID = 0 (required by RFC 6762)
        b"\x00\x00"  # Standard query flags
        b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
        + qname
        + b"\x00\x01"  # Type: A (1)
        b"\x80\x01"  # Class: IN (1) with QU (unicast response requested)
    )

    print(f"Sending mDNS query for '{domain}' to 224.0.0.251:5353...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(3.0)

    # Critical: RFC 6762 mandates link-local multicast TTL = 255
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

    # Send to IPv4 mDNS multicast address
    sock.sendto(query, ("224.0.0.251", 5353))

    responses = 0
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                responses += 1
                print(
                    f"\n=== Response #{responses} ({len(data)} bytes from {addr[0]}:{addr[1]}) ==="
                )
                print_dns_response(data, addr)
                # Brief follow-up window to catch any additional responders
                sock.settimeout(0.5)
            except socket.timeout:
                if responses == 0:
                    print("Timed out waiting for mDNS response")
                break
    finally:
        sock.close()


if __name__ == "__main__":
    main()
