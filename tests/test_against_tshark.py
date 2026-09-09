"""Cross-validation of the parser against tshark.

Writing a packet decoder means deciding what every byte means, and being confidently wrong is
easy. These tests run tshark over the same captures and compare the fields both tools claim to
have read. They are skipped when tshark is not installed, so the suite still runs anywhere, but
they are the reason to believe the decoder at all.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from netriage.analysis import analyse
from netriage.capture import read_capture
from netriage.decode import decode

FIXTURES = Path(__file__).parent / "fixtures"
TSHARK = shutil.which("tshark")

pytestmark = pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")

CAPTURES = ["browsing.pcap", "browsing.pcapng", "port_scan.pcap", "host_sweep.pcap", "beacon.pcap"]


def tshark_fields(capture: str, fields: list[str]) -> list[list[str]]:
    """Run tshark and return one row per packet, padded so absent fields are empty strings.

    tshark drops trailing separators when the last fields are empty, so rows must be padded to
    the requested width or zip() would silently misalign the comparison.
    """
    command = [TSHARK, "-r", str(FIXTURES / capture), "-T", "fields"]
    for field in fields:
        command += ["-e", field]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    rows = []
    for line in result.stdout.split("\n")[:-1]:
        row = line.split("\t")
        rows.append(row + [""] * (len(fields) - len(row)))
    return rows


@pytest.mark.parametrize("capture", CAPTURES)
def test_packet_count_matches(capture):
    ours = len(read_capture(FIXTURES / capture))
    theirs = len(tshark_fields(capture, ["frame.number"]))
    assert ours == theirs


@pytest.mark.parametrize("capture", CAPTURES)
def test_addresses_and_ports_match(capture):
    theirs = tshark_fields(
        capture, ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
    )
    ours = [decode(p) for p in read_capture(FIXTURES / capture)]
    assert len(ours) == len(theirs)

    for decoded, row in zip(ours, theirs, strict=True):
        source, destination, tcp_source, tcp_destination, udp_source, udp_destination = row
        assert decoded is not None
        assert decoded.source_ip == source
        assert decoded.destination_ip == destination
        expected_source = tcp_source or udp_source
        expected_destination = tcp_destination or udp_destination
        if expected_source:
            assert str(decoded.source_port) == expected_source
            assert str(decoded.destination_port) == expected_destination


@pytest.mark.parametrize("capture", CAPTURES)
def test_timestamps_match(capture):
    theirs = [float(row[0]) for row in tshark_fields(capture, ["frame.time_epoch"])]
    ours = [p.timestamp.timestamp() for p in read_capture(FIXTURES / capture)]
    assert len(ours) == len(theirs)
    for mine, other in zip(ours, theirs, strict=True):
        assert abs(mine - other) < 1e-6


@pytest.mark.parametrize("capture", CAPTURES)
def test_frame_lengths_match(capture):
    theirs = [int(row[0]) for row in tshark_fields(capture, ["frame.len"])]
    ours = [p.original_length for p in read_capture(FIXTURES / capture)]
    assert ours == theirs


def test_dns_query_names_match():
    theirs = {row[0] for row in tshark_fields("browsing.pcap", ["dns.qry.name"]) if row[0]}
    ours = {q["name"] for q in analyse(read_capture(FIXTURES / "browsing.pcap")).dns_queries}
    assert ours == theirs


def test_dns_answer_addresses_match():
    theirs = {row[0] for row in tshark_fields("browsing.pcap", ["dns.a"]) if row[0]}
    analysis = analyse(read_capture(FIXTURES / "browsing.pcap"))
    ours = {
        answer.split(" ", 1)[1]
        for query in analysis.dns_queries
        for answer in query["answers"]
        if answer.startswith("A ")
    }
    assert ours == theirs


def test_tls_server_names_match():
    theirs = {
        row[0]
        for row in tshark_fields("browsing.pcap", ["tls.handshake.extensions_server_name"])
        if row[0]
    }
    ours = {t["server_name"] for t in analyse(read_capture(FIXTURES / "browsing.pcap")).tls_names}
    assert ours == theirs


def test_http_hosts_and_uris_match():
    theirs = {
        (row[0], row[1])
        for row in tshark_fields("browsing.pcap", ["http.host", "http.request.uri"])
        if row[0]
    }
    analysis = analyse(read_capture(FIXTURES / "browsing.pcap"))
    ours = {(r["host"], r["uri"]) for r in analysis.http_requests}
    assert ours == theirs


def test_tcp_flag_decoding_matches():
    theirs = [row[0] for row in tshark_fields("port_scan.pcap", ["tcp.flags"])]
    ours = [decode(p).tcp_flags for p in read_capture(FIXTURES / "port_scan.pcap")]
    assert len(ours) == len(theirs)
    for mine, other in zip(ours, theirs, strict=True):
        # tshark reports the 12-bit field including the reserved and offset bits.
        assert mine == int(other, 16) & 0xFF


def test_syn_packet_count_matches():
    # tshark renders boolean fields as True/False rather than 1/0.
    theirs = tshark_fields("port_scan.pcap", ["tcp.flags.syn", "tcp.flags.ack"])
    expected = sum(1 for syn, ack in theirs if syn == "True" and ack == "False")
    ours = sum(
        1
        for p in read_capture(FIXTURES / "port_scan.pcap")
        if (d := decode(p)) and d.tcp_flags & 0x02 and not d.tcp_flags & 0x10
    )
    assert ours == expected


def test_unique_conversation_count_matches():
    """tshark's conversation view is bidirectional; ours is directional, so compare the
    unordered address/port pairs rather than the raw counts."""
    theirs = tshark_fields(
        "browsing.pcap",
        ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"],
    )
    expected = set()
    for source, destination, ts, td, us, ud in theirs:
        source_port, destination_port = (ts or us), (td or ud)
        expected.add(frozenset({(source, source_port), (destination, destination_port)}))

    analysis = analyse(read_capture(FIXTURES / "browsing.pcap"))
    ours = {
        frozenset({(f.source_ip, str(f.source_port)), (f.destination_ip, str(f.destination_port))})
        for f in analysis.flows
    }
    assert ours == expected
