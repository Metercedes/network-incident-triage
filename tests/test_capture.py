from __future__ import annotations

from pathlib import Path

import pytest

from netriage.capture import CaptureError, read_capture

FIXTURES = Path(__file__).parent / "fixtures"


class TestReading:
    def test_pcap(self):
        assert len(read_capture(FIXTURES / "browsing.pcap")) == 15

    def test_pcapng(self):
        assert len(read_capture(FIXTURES / "browsing.pcapng")) == 15

    def test_both_formats_agree_on_content(self):
        pcap = read_capture(FIXTURES / "browsing.pcap")
        pcapng = read_capture(FIXTURES / "browsing.pcapng")
        assert [p.data for p in pcap] == [p.data for p in pcapng]
        assert [p.timestamp for p in pcap] == [p.timestamp for p in pcapng]

    def test_timestamps_are_ordered_and_timezone_aware(self):
        packets = read_capture(FIXTURES / "browsing.pcap")
        assert all(p.timestamp.tzinfo is not None for p in packets)
        assert [p.timestamp for p in packets] == sorted(p.timestamp for p in packets)

    def test_packet_indices_are_sequential(self):
        packets = read_capture(FIXTURES / "beacon.pcap")
        assert [p.index for p in packets] == list(range(len(packets)))


class TestErrorHandling:
    def test_missing_magic_is_rejected(self, tmp_path):
        path = tmp_path / "bad.pcap"
        path.write_bytes(b"not a capture at all, really not" * 2)
        with pytest.raises(CaptureError, match="not a pcap"):
            read_capture(path)

    def test_empty_file_is_rejected(self, tmp_path):
        path = tmp_path / "empty.pcap"
        path.write_bytes(b"")
        with pytest.raises(CaptureError):
            read_capture(path)

    def test_header_without_packets_is_valid(self, tmp_path):
        import struct

        path = tmp_path / "headeronly.pcap"
        path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        assert read_capture(path) == []

    def test_truncated_record_is_reported_not_ignored(self, tmp_path):
        import struct

        path = tmp_path / "short.pcap"
        path.write_bytes(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
            + struct.pack("<IIII", 1772442000, 0, 500, 500)
            + b"\x00" * 10
        )
        with pytest.raises(CaptureError, match="past the end"):
            read_capture(path)

    def test_unsupported_linktype_is_reported(self, tmp_path):
        import struct

        path = tmp_path / "wifi.pcap"
        path.write_bytes(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 127)
            + struct.pack("<IIII", 1772442000, 0, 4, 4)
            + b"\x00\x01\x02\x03"
        )
        with pytest.raises(CaptureError, match="unsupported link type"):
            read_capture(path)

    def test_big_endian_pcap(self, tmp_path):
        import struct

        path = tmp_path / "be.pcap"
        path.write_bytes(
            struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
            + struct.pack(">IIII", 1772442000, 0, 4, 4)
            + b"\x00" * 4
        )
        assert len(read_capture(path)) == 1
