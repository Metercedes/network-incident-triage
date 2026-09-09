"""Readers for the two capture container formats.

Classic pcap is a 24-byte file header followed by fixed 16-byte record headers. pcapng is a
sequence of typed blocks, where the interface description blocks define the timestamp resolution
that the packet blocks are expressed in. Both are handled here so the rest of the package sees
one packet type regardless of which format the analyst was handed.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

PCAP_MAGIC_MICRO = 0xA1B2C3D4
PCAP_MAGIC_NANO = 0xA1B23C4D
PCAPNG_BLOCK_SHB = 0x0A0D0D0A

# Only these link types are decoded. Anything else is reported rather than silently mis-parsed.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0
SUPPORTED_LINKTYPES = {LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_NULL}


class CaptureError(Exception):
    pass


@dataclass(frozen=True)
class Packet:
    index: int
    timestamp: datetime
    captured_length: int
    original_length: int
    linktype: int
    data: bytes

    @property
    def truncated(self) -> bool:
        return self.captured_length < self.original_length


def _timestamp(seconds: int, fraction: int, divisor: int) -> datetime:
    return datetime.fromtimestamp(seconds + fraction / divisor, tz=UTC)


def read_pcap(raw: bytes) -> Iterator[Packet]:
    if len(raw) < 24:
        raise CaptureError("file is shorter than a pcap header")
    magic = struct.unpack("<I", raw[:4])[0]
    if magic in (PCAP_MAGIC_MICRO, PCAP_MAGIC_NANO):
        endian = "<"
    elif struct.unpack(">I", raw[:4])[0] in (PCAP_MAGIC_MICRO, PCAP_MAGIC_NANO):
        endian = ">"
        magic = struct.unpack(">I", raw[:4])[0]
    else:
        raise CaptureError(f"not a pcap file: magic {raw[:4].hex()}")

    divisor = 1_000_000_000 if magic == PCAP_MAGIC_NANO else 1_000_000
    linktype = struct.unpack(f"{endian}I", raw[20:24])[0]

    offset = 24
    index = 0
    while offset + 16 <= len(raw):
        seconds, fraction, captured, original = struct.unpack(
            f"{endian}IIII", raw[offset : offset + 16]
        )
        offset += 16
        if offset + captured > len(raw):
            raise CaptureError(f"packet {index} claims {captured} bytes past the end of the file")
        yield Packet(
            index,
            _timestamp(seconds, fraction, divisor),
            captured,
            original,
            linktype,
            raw[offset : offset + captured],
        )
        offset += captured
        index += 1


def read_pcapng(raw: bytes) -> Iterator[Packet]:
    offset = 0
    index = 0
    endian = "<"
    interfaces: list[tuple[int, int]] = []

    while offset + 12 <= len(raw):
        block_type = struct.unpack(f"{endian}I", raw[offset : offset + 4])[0]
        if block_type == PCAPNG_BLOCK_SHB:
            byte_order = struct.unpack("<I", raw[offset + 8 : offset + 12])[0]
            endian = "<" if byte_order == 0x1A2B3C4D else ">"
            block_type = struct.unpack(f"{endian}I", raw[offset : offset + 4])[0]
        block_length = struct.unpack(f"{endian}I", raw[offset + 4 : offset + 8])[0]
        if block_length < 12 or offset + block_length > len(raw):
            raise CaptureError(f"pcapng block at offset {offset} has an impossible length")
        body = raw[offset + 8 : offset + block_length - 4]

        if block_type == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(f"{endian}H", body[0:2])[0]
            interfaces.append((linktype, _if_tsresol(body[8:], endian)))
        elif block_type == 0x00000006:  # Enhanced Packet Block
            interface_id, high, low, captured, original = struct.unpack(f"{endian}IIIII", body[:20])
            linktype, resolution = (
                interfaces[interface_id]
                if interface_id < len(interfaces)
                else (LINKTYPE_ETHERNET, 6)
            )
            ticks = (high << 32) | low
            divisor = 10**resolution
            yield Packet(
                index,
                _timestamp(ticks // divisor, ticks % divisor, divisor),
                captured,
                original,
                linktype,
                body[20 : 20 + captured],
            )
            index += 1
        elif block_type == 0x00000003:  # Simple Packet Block
            original = struct.unpack(f"{endian}I", body[:4])[0]
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            payload = body[4:]
            yield Packet(
                index, datetime.fromtimestamp(0, tz=UTC), len(payload), original, linktype, payload
            )
            index += 1

        offset += block_length


def _if_tsresol(options: bytes, endian: str) -> int:
    """Read if_tsresol (option code 9). Absent means microseconds."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(f"{endian}HH", options[offset : offset + 4])
        if code == 0:
            break
        value = options[offset + 4 : offset + 4 + length]
        if code == 9 and value:
            resolution = value[0]
            # The high bit selects a power of two rather than a power of ten; captures using it
            # are vanishingly rare, so fall back rather than decode timestamps wrongly.
            return 6 if resolution & 0x80 else resolution
        offset += 4 + length + (-length % 4)
    return 6


def read_capture(path: Path) -> list[Packet]:
    raw = path.read_bytes()
    if len(raw) < 4:
        raise CaptureError(f"{path.name} is too short to be a capture")
    first = struct.unpack("<I", raw[:4])[0]
    packets = list(read_pcapng(raw)) if first == PCAPNG_BLOCK_SHB else list(read_pcap(raw))
    unsupported = {p.linktype for p in packets} - SUPPORTED_LINKTYPES
    if unsupported:
        raise CaptureError(
            f"{path.name} uses unsupported link type(s) {sorted(unsupported)}; "
            f"supported: {sorted(SUPPORTED_LINKTYPES)}"
        )
    return packets
