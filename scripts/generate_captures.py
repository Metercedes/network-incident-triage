#!/usr/bin/env python3
"""Build the test captures byte by byte.

Nothing here is recorded traffic. Every packet is constructed from documented header layouts, so
the fixtures can be committed without publishing anyone's network activity, and so each scenario
contains exactly the behaviour a test needs.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
BASE_TIME = 1772442000  # 2026-03-02T09:00:00Z

CLIENT_MAC = bytes.fromhex("00163e1a2b3c")
GATEWAY_MAC = bytes.fromhex("00163e9f8e7d")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return GATEWAY_MAC + CLIENT_MAC + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, source: str, destination: str, protocol: int, ttl: int = 64) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0,
        ttl,
        protocol,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(
    payload: bytes,
    source_port: int,
    destination_port: int,
    flags: int,
    sequence: int = 1000,
    ack: int = 0,
) -> bytes:
    offset_and_reserved = 5 << 4
    header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        ack,
        offset_and_reserved,
        flags,
        64240,
        0,
        0,
    )
    return header + payload


def udp(payload: bytes, source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns_query(name: str, transaction_id: int, qtype: int = 1) -> bytes:
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + dns_name(name)
        + struct.pack("!HH", qtype, 1)
    )


def dns_response(name: str, transaction_id: int, address: str, rcode: int = 0) -> bytes:
    flags = 0x8180 | rcode
    answer_count = 1 if rcode == 0 else 0
    message = (
        struct.pack("!HHHHHH", transaction_id, flags, 1, answer_count, 0, 0)
        + dns_name(name)
        + struct.pack("!HH", 1, 1)
    )
    if rcode == 0:
        message += (
            b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ipaddress.IPv4Address(address).packed
        )
    return message


def tls_client_hello(server_name: str) -> bytes:
    name = server_name.encode()
    server_name_list = struct.pack("!BH", 0, len(name)) + name
    sni_extension = (
        struct.pack("!HHH", 0x0000, len(server_name_list) + 2, len(server_name_list))
        + server_name_list
    )
    body = (
        struct.pack("!H", 0x0303)
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(sni_extension))
        + sni_extension
    )
    handshake = struct.pack("!B", 0x01) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def http_get(host: str, path: str, user_agent: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n"
        f"Accept: */*\r\nConnection: keep-alive\r\n\r\n"
    ).encode()


def http_post(host: str, path: str) -> bytes:
    body = "username=admin&password=hunter2"
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    ).encode()


def write_pcap(path: Path, records: list[tuple[float, bytes]], linktype: int = 1) -> None:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
    for offset, frame in records:
        seconds = int(BASE_TIME + offset)
        microseconds = int(round((BASE_TIME + offset - seconds) * 1_000_000))
        out += struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)) + frame
    path.write_bytes(bytes(out))


def write_pcapng(path: Path, records: list[tuple[float, bytes]], linktype: int = 1) -> None:
    def block(block_type: int, body: bytes) -> bytes:
        padded = body + b"\x00" * (-len(body) % 4)
        length = 12 + len(padded)
        return struct.pack("<II", block_type, length) + padded + struct.pack("<I", length)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(
        0x00000001,
        struct.pack("<HHI", linktype, 0, 262144)
        + struct.pack("<HH", 9, 1)
        + bytes([6])
        + b"\x00" * 3
        + struct.pack("<HH", 0, 0),
    )
    out = bytearray(shb + idb)
    for offset, frame in records:
        ticks = int(round((BASE_TIME + offset) * 1_000_000))
        body = (
            struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame))
            + frame
            + b"\x00" * (-len(frame) % 4)
        )
        out += block(0x00000006, body)
    path.write_bytes(bytes(out))


def frame(payload: bytes, source: str, destination: str, protocol: int) -> bytes:
    return ethernet(ipv4(payload, source, destination, protocol))


def build_browsing() -> list[tuple[float, bytes]]:
    client, resolver, web, cdn = "10.20.1.15", "10.20.1.1", "93.184.216.34", "151.101.1.140"
    records: list[tuple[float, bytes]] = []

    records.append(
        (
            0.00,
            frame(udp(dns_query("intranet.contoso.com", 0x1A2B), 51514, 53), client, resolver, 17),
        )
    )
    records.append(
        (
            0.01,
            frame(
                udp(dns_response("intranet.contoso.com", 0x1A2B, web), 53, 51514),
                resolver,
                client,
                17,
            ),
        )
    )
    records.append((0.05, frame(tcp(b"", 49200, 80, 0x02), client, web, 6)))
    records.append((0.06, frame(tcp(b"", 80, 49200, 0x12), web, client, 6)))
    records.append((0.07, frame(tcp(b"", 49200, 80, 0x10), client, web, 6)))
    records.append(
        (
            0.08,
            frame(
                tcp(
                    http_get(
                        "intranet.contoso.com",
                        "/dashboard",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    ),
                    49200,
                    80,
                    0x18,
                ),
                client,
                web,
                6,
            ),
        )
    )
    records.append(
        (
            0.12,
            frame(
                tcp(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 80, 49200, 0x18),
                web,
                client,
                6,
            ),
        )
    )

    records.append(
        (1.00, frame(udp(dns_query("cdn.example.net", 0x3C4D), 51515, 53), client, resolver, 17))
    )
    records.append(
        (
            1.01,
            frame(
                udp(dns_response("cdn.example.net", 0x3C4D, cdn), 53, 51515), resolver, client, 17
            ),
        )
    )
    records.append((1.05, frame(tcp(b"", 49201, 443, 0x02), client, cdn, 6)))
    records.append((1.06, frame(tcp(b"", 443, 49201, 0x12), cdn, client, 6)))
    records.append(
        (1.08, frame(tcp(tls_client_hello("cdn.example.net"), 49201, 443, 0x18), client, cdn, 6))
    )

    records.append(
        (
            2.00,
            frame(udp(dns_query("missing.contoso.com", 0x5E6F), 51516, 53), client, resolver, 17),
        )
    )
    records.append(
        (
            2.01,
            frame(
                udp(dns_response("missing.contoso.com", 0x5E6F, "0.0.0.0", rcode=3), 53, 51516),
                resolver,
                client,
                17,
            ),
        )
    )

    records.append(
        (
            3.00,
            frame(
                tcp(http_post("legacy.contoso.com", "/login"), 49202, 80, 0x18),
                client,
                "10.20.1.50",
                6,
            ),
        )
    )
    return records


def build_port_scan() -> list[tuple[float, bytes]]:
    attacker, target = "10.20.9.99", "10.20.1.50"
    records = []
    open_ports = {22, 80, 443}
    for index, port in enumerate(range(20, 61)):
        records.append(
            (index * 0.01, frame(tcp(b"", 40000 + index, port, 0x02), attacker, target, 6))
        )
        if port in open_ports:
            records.append(
                (
                    index * 0.01 + 0.002,
                    frame(tcp(b"", port, 40000 + index, 0x12), target, attacker, 6),
                )
            )
        else:
            records.append(
                (
                    index * 0.01 + 0.002,
                    frame(tcp(b"", port, 40000 + index, 0x14), target, attacker, 6),
                )
            )
    return records


def build_host_sweep() -> list[tuple[float, bytes]]:
    attacker = "10.20.9.99"
    records = []
    for index in range(30):
        target = f"10.20.1.{index + 10}"
        records.append(
            (index * 0.02, frame(tcp(b"", 41000 + index, 445, 0x02), attacker, target, 6))
        )
    return records


def build_beacon() -> list[tuple[float, bytes]]:
    """A regular 60-second check-in with 2% jitter, plus irregular human browsing alongside."""
    implant, controller = "10.20.1.77", "198.51.100.23"
    records = []
    for index in range(12):
        offset = index * 60.0 + (index % 3) * 0.9
        records.append((offset, frame(tcp(b"", 50000 + index, 443, 0x02), implant, controller, 6)))
        records.append(
            (offset + 0.02, frame(tcp(b"", 443, 50000 + index, 0x12), controller, implant, 6))
        )
        records.append(
            (
                offset + 0.05,
                frame(
                    tcp(tls_client_hello("update.cdn-sync.top"), 50000 + index, 443, 0x18),
                    implant,
                    controller,
                    6,
                ),
            )
        )
    for index, offset in enumerate([5.0, 43.0, 91.0, 96.0, 210.0, 480.0, 500.0]):
        records.append(
            (offset, frame(tcp(b"", 51000 + index, 443, 0x02), implant, "93.184.216.34", 6))
        )
    return sorted(records, key=lambda r: r[0])


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    write_pcap(FIXTURES / "browsing.pcap", build_browsing())
    write_pcapng(FIXTURES / "browsing.pcapng", build_browsing())
    write_pcap(FIXTURES / "port_scan.pcap", build_port_scan())
    write_pcap(FIXTURES / "host_sweep.pcap", build_host_sweep())
    write_pcap(FIXTURES / "beacon.pcap", build_beacon())
    write_pcap(FIXTURES / "truncated.pcap", [(0.0, ethernet(b"\x45\x00\x00")[:10])])
    for path in sorted(FIXTURES.glob("*.pcap*")):
        print(f"wrote {path.name} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
