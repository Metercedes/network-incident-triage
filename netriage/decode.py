"""Protocol decoding, from the link layer up to the few application protocols that matter here.

Every decoder returns None rather than raising when a packet is truncated or malformed. A capture
taken under load is full of short packets, and an analysis tool that stops on the first one is
useless. Counts of what could not be decoded are reported instead.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from netriage.capture import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_NULL, Packet

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_ARP = 0x0806

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)


@dataclass
class Decoded:
    packet: Packet
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: int | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int = 0
    payload: bytes = b""
    vlan_ids: list[int] = field(default_factory=list)
    ip_version: int | None = None
    ttl: int | None = None

    @property
    def transport(self) -> str:
        return {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp", PROTO_ICMPV6: "icmpv6"}.get(
            self.protocol, str(self.protocol)
        )

    @property
    def flag_string(self) -> str:
        names = [
            (TCP_SYN, "S"),
            (TCP_ACK, "A"),
            (TCP_FIN, "F"),
            (TCP_RST, "R"),
            (TCP_PSH, "P"),
            (TCP_URG, "U"),
        ]
        return "".join(letter for bit, letter in names if self.tcp_flags & bit)


def decode(packet: Packet) -> Decoded | None:
    data = packet.data
    result = Decoded(packet=packet)

    if packet.linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
            if len(data) < offset + 4:
                return None
            tag = struct.unpack("!H", data[offset : offset + 2])[0]
            result.vlan_ids.append(tag & 0x0FFF)
            ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
        data = data[offset:]
        if ethertype == ETHERTYPE_IPV4:
            return _decode_ipv4(data, result)
        if ethertype == ETHERTYPE_IPV6:
            return _decode_ipv6(data, result)
        return None

    if packet.linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack("!H", data[14:16])[0]
        data = data[16:]
        if ethertype == ETHERTYPE_IPV4:
            return _decode_ipv4(data, result)
        if ethertype == ETHERTYPE_IPV6:
            return _decode_ipv6(data, result)
        return None

    if packet.linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        family = struct.unpack("<I", data[:4])[0]
        data = data[4:]
        if family == 2:
            return _decode_ipv4(data, result)
        if family in (24, 28, 30):
            return _decode_ipv6(data, result)
        return None

    # LINKTYPE_RAW: the IP header starts at byte zero.
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        return _decode_ipv4(data, result)
    if version == 6:
        return _decode_ipv6(data, result)
    return None


def _decode_ipv4(data: bytes, result: Decoded) -> Decoded | None:
    if len(data) < 20:
        return None
    header_length = (data[0] & 0x0F) * 4
    if header_length < 20 or len(data) < header_length:
        return None
    total_length = struct.unpack("!H", data[2:4])[0]
    fragment_field = struct.unpack("!H", data[6:8])[0]
    result.ip_version = 4
    result.ttl = data[8]
    result.protocol = data[9]
    result.source_ip = str(ipaddress.IPv4Address(data[12:16]))
    result.destination_ip = str(ipaddress.IPv4Address(data[16:20]))

    body = (
        data[header_length:total_length] if 0 < total_length <= len(data) else data[header_length:]
    )
    # Only the first fragment carries transport headers; later fragments are counted, not parsed.
    if fragment_field & 0x1FFF:
        return result
    return _decode_transport(body, result)


def _decode_ipv6(data: bytes, result: Decoded) -> Decoded | None:
    if len(data) < 40:
        return None
    result.ip_version = 6
    result.ttl = data[7]
    next_header = data[6]
    result.source_ip = str(ipaddress.IPv6Address(data[8:24]))
    result.destination_ip = str(ipaddress.IPv6Address(data[24:40]))
    body = data[40:]

    # Walk the extension header chain to reach the transport header.
    extension_headers = {0, 43, 44, 60}
    while next_header in extension_headers and len(body) >= 8:
        length = (body[1] + 1) * 8
        next_header = body[0]
        body = body[length:]
    result.protocol = next_header
    return _decode_transport(body, result)


def _decode_transport(body: bytes, result: Decoded) -> Decoded:
    if result.protocol == PROTO_TCP and len(body) >= 20:
        result.source_port, result.destination_port = struct.unpack("!HH", body[:4])
        data_offset = (body[12] >> 4) * 4
        result.tcp_flags = body[13]
        if data_offset >= 20:
            result.payload = body[data_offset:]
    elif result.protocol == PROTO_UDP and len(body) >= 8:
        result.source_port, result.destination_port = struct.unpack("!HH", body[:4])
        length = struct.unpack("!H", body[4:6])[0]
        result.payload = body[8:length] if 8 <= length <= len(body) else body[8:]
    return result


@dataclass
class DnsQuestion:
    name: str
    qtype: int


@dataclass
class DnsAnswer:
    name: str
    rtype: int
    value: str


@dataclass
class DnsMessage:
    transaction_id: int
    is_response: bool
    rcode: int
    questions: list[DnsQuestion] = field(default_factory=list)
    answers: list[DnsAnswer] = field(default_factory=list)


DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    257: "CAA",
}


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Read a DNS name, following compression pointers.

    Depth is bounded because a capture can contain a pointer loop, either from corruption or
    deliberately, and an unbounded reader would hang on it.
    """
    labels: list[str] = []
    if depth > 10:
        return "", offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                break
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            suffix, _ = _read_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            return ".".join(labels), offset + 2
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def parse_dns(payload: bytes) -> DnsMessage | None:
    if len(payload) < 12:
        return None
    transaction_id, flags, qd_count, an_count = struct.unpack("!HHHH", payload[:8])
    message = DnsMessage(transaction_id, bool(flags & 0x8000), flags & 0x000F)
    offset = 12
    try:
        for _ in range(min(qd_count, 20)):
            name, offset = _read_name(payload, offset)
            if offset + 4 > len(payload):
                return message
            qtype = struct.unpack("!H", payload[offset : offset + 2])[0]
            message.questions.append(DnsQuestion(name, qtype))
            offset += 4
        for _ in range(min(an_count, 50)):
            name, offset = _read_name(payload, offset)
            if offset + 10 > len(payload):
                return message
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10
            rdata = payload[offset : offset + rdlength]
            message.answers.append(
                DnsAnswer(name, rtype, _rdata_value(rtype, rdata, payload, offset))
            )
            offset += rdlength
    except (struct.error, IndexError):
        return message
    return message


def _rdata_value(rtype: int, rdata: bytes, full: bytes, offset: int) -> str:
    if rtype == 1 and len(rdata) == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype == 28 and len(rdata) == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (2, 5, 12):
        name, _ = _read_name(full, offset)
        return name
    if rtype == 16 and rdata:
        return rdata[1 : 1 + rdata[0]].decode("utf-8", errors="replace")
    return rdata.hex()


def parse_http_request(payload: bytes) -> dict | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    try:
        head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except UnicodeDecodeError:
        return None
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return {
        "method": parts[0],
        "uri": parts[1],
        "version": parts[2] if len(parts) > 2 else "",
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
        "referer": headers.get("referer", ""),
        "content_type": headers.get("content-type", ""),
    }


def parse_tls_sni(payload: bytes) -> str | None:
    """Extract the server name from a TLS ClientHello.

    SNI is the last reliable way to see which host a connection is for once the traffic is
    encrypted, which makes it the single most useful field in a modern capture.
    """
    if len(payload) < 45 or payload[0] != 0x16:
        return None
    try:
        offset = 5
        if payload[offset] != 0x01:
            return None
        offset += 4 + 2 + 32
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        cipher_suites_length = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2 + cipher_suites_length
        compression_length = payload[offset]
        offset += 1 + compression_length
        if offset + 2 > len(payload):
            return None
        extensions_length = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        end = min(offset + extensions_length, len(payload))
        while offset + 4 <= end:
            extension_type, extension_length = struct.unpack("!HH", payload[offset : offset + 4])
            offset += 4
            if extension_type == 0x0000:
                # server_name extension: list length, name type, name length, name
                name_length = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
                return payload[offset + 5 : offset + 5 + name_length].decode(
                    "ascii", errors="replace"
                )
            offset += extension_length
    except (struct.error, IndexError):
        return None
    return None
