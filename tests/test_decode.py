from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from netriage.capture import read_capture
from netriage.decode import decode, parse_dns, parse_http_request, parse_tls_sni

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def browsing():
    return [decode(p) for p in read_capture(FIXTURES / "browsing.pcap")]


class TestNetworkLayer:
    def test_every_packet_decodes(self, browsing):
        assert all(d is not None for d in browsing)

    def test_addresses(self, browsing):
        assert browsing[0].source_ip == "10.20.1.15"
        assert browsing[0].destination_ip == "10.20.1.1"

    def test_ports(self, browsing):
        assert (browsing[0].source_port, browsing[0].destination_port) == (51514, 53)

    def test_transport_names(self, browsing):
        assert browsing[0].transport == "udp"
        assert browsing[2].transport == "tcp"

    def test_tcp_flags(self, browsing):
        assert browsing[2].flag_string == "S"
        assert browsing[3].flag_string == "SA"

    def test_short_frame_returns_none_rather_than_raising(self):
        from datetime import datetime

        from netriage.capture import Packet

        packet = Packet(0, datetime.now(UTC), 4, 4, 1, b"\x00\x01\x02\x03")
        assert decode(packet) is None


class TestDns:
    def test_query(self, browsing):
        message = parse_dns(browsing[0].payload)
        assert message.questions[0].name == "intranet.contoso.com"
        assert message.is_response is False

    def test_response_with_answer(self, browsing):
        message = parse_dns(browsing[1].payload)
        assert message.is_response is True
        assert message.answers[0].value == "93.184.216.34"

    def test_name_compression_is_followed(self, browsing):
        # The answer name is a pointer back to the question name.
        assert parse_dns(browsing[1].payload).answers[0].name == "intranet.contoso.com"

    def test_nxdomain_rcode(self, browsing):
        assert parse_dns(browsing[13].payload).rcode == 3

    def test_truncated_message_returns_none(self):
        assert parse_dns(b"\x00\x01") is None

    def test_compression_pointer_loop_terminates(self):
        # A name that is a pointer to its own offset would make a naive reader recurse forever.
        header = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        assert parse_dns(header + b"\xc0\x0c") is not None


class TestTls:
    def test_sni_is_extracted(self, browsing):
        hello = next(d for d in browsing if d.payload[:1] == b"\x16")
        assert parse_tls_sni(hello.payload) == "cdn.example.net"

    def test_non_tls_payload_returns_none(self):
        assert parse_tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None

    def test_truncated_hello_returns_none(self):
        assert parse_tls_sni(b"\x16\x03\x01\x00\x05") is None


class TestHttp:
    def test_request_line_and_headers(self, browsing):
        request = next(
            parse_http_request(d.payload) for d in browsing if d.payload.startswith(b"GET ")
        )
        assert request["method"] == "GET"
        assert request["uri"] == "/dashboard"
        assert request["host"] == "intranet.contoso.com"
        assert "Mozilla" in request["user_agent"]

    def test_post_content_type(self, browsing):
        request = next(
            parse_http_request(d.payload) for d in browsing if d.payload.startswith(b"POST ")
        )
        assert request["content_type"] == "application/x-www-form-urlencoded"

    def test_response_is_not_a_request(self):
        assert parse_http_request(b"HTTP/1.1 200 OK\r\n\r\n") is None

    def test_binary_payload_is_not_a_request(self):
        assert parse_http_request(b"\x00\x01\x02\x03") is None
