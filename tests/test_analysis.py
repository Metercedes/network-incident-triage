from __future__ import annotations

import json
from pathlib import Path

import pytest

from netriage.analysis import analyse
from netriage.capture import read_capture
from netriage.cli import main
from netriage.report import to_csv, to_dict, to_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def analysis_of(name: str, **kwargs):
    return analyse(read_capture(FIXTURES / name), **kwargs)


@pytest.fixture(scope="module")
def browsing():
    return analysis_of("browsing.pcap")


def kinds(analysis) -> set[str]:
    return {f.kind for f in analysis.findings}


class TestFlows:
    def test_flows_are_directional(self, browsing):
        pairs = {(f.source_ip, f.destination_ip) for f in browsing.flows}
        assert ("10.20.1.15", "93.184.216.34") in pairs
        assert ("93.184.216.34", "10.20.1.15") in pairs

    def test_bytes_and_packets_are_counted(self, browsing):
        flow = next(
            f
            for f in browsing.flows
            if f.source_ip == "10.20.1.15"
            and f.destination_port == 80
            and f.destination_ip == "93.184.216.34"
        )
        assert flow.packets == 3
        assert flow.bytes > 0

    def test_service_names_are_resolved(self, browsing):
        assert {f.service for f in browsing.flows} >= {"http", "https", "dns"}

    def test_all_packets_are_accounted_for(self, browsing):
        assert browsing.decoded_count + browsing.undecoded_count == browsing.packet_count


class TestHosts:
    def test_inventory_covers_every_address(self, browsing):
        assert set(browsing.hosts) == {
            "10.20.1.15",
            "10.20.1.1",
            "93.184.216.34",
            "151.101.1.140",
            "10.20.1.50",
        }

    def test_client_contacted_expected_ports(self, browsing):
        assert set(browsing.hosts["10.20.1.15"]["ports_contacted"]) >= {53, 80, 443}


class TestApplicationRecords:
    def test_dns_queries_and_responses(self, browsing):
        names = {q["name"] for q in browsing.dns_queries}
        assert names == {"intranet.contoso.com", "cdn.example.net", "missing.contoso.com"}

    def test_nxdomain_is_recorded(self, browsing):
        assert any(q["rcode"] == 3 for q in browsing.dns_queries if q["is_response"])

    def test_tls_server_name(self, browsing):
        assert [t["server_name"] for t in browsing.tls_names] == ["cdn.example.net"]

    def test_http_requests(self, browsing):
        assert {r["host"] for r in browsing.http_requests} == {
            "intranet.contoso.com",
            "legacy.contoso.com",
        }


class TestPortScanDetection:
    def test_port_scan_is_found(self):
        analysis = analysis_of("port_scan.pcap")
        assert "port scan" in kinds(analysis)

    def test_scan_evidence_names_the_source_and_target(self):
        finding = next(f for f in analysis_of("port_scan.pcap").findings if f.kind == "port scan")
        assert finding.evidence["source"] == "10.20.9.99"
        assert finding.evidence["destination"] == "10.20.1.50"
        assert finding.evidence["port_count"] >= 15

    def test_normal_browsing_is_not_a_scan(self, browsing):
        assert "port scan" not in kinds(browsing)
        assert "host sweep" not in kinds(browsing)

    def test_threshold_is_configurable(self):
        assert "port scan" not in kinds(analysis_of("port_scan.pcap", scan_port_threshold=500))


class TestHostSweepDetection:
    def test_sweep_is_found(self):
        analysis = analysis_of("host_sweep.pcap")
        assert "host sweep" in kinds(analysis)

    def test_sweep_names_the_port(self):
        finding = next(f for f in analysis_of("host_sweep.pcap").findings if f.kind == "host sweep")
        assert finding.evidence["port"] == 445
        assert finding.evidence["host_count"] >= 15

    def test_browsing_is_not_a_sweep(self, browsing):
        assert "host sweep" not in kinds(browsing)


class TestBeaconDetection:
    def test_beacon_is_found(self):
        assert "possible beaconing" in kinds(analysis_of("beacon.pcap"))

    def test_beacon_reports_the_interval(self):
        finding = next(
            f for f in analysis_of("beacon.pcap").findings if f.kind == "possible beaconing"
        )
        assert 55 <= finding.evidence["mean_interval_seconds"] <= 65
        assert finding.evidence["destination"] == "198.51.100.23"

    def test_irregular_traffic_in_the_same_capture_is_not_flagged(self):
        beacons = [f for f in analysis_of("beacon.pcap").findings if f.kind == "possible beaconing"]
        # The browsing to 93.184.216.34 in the same capture is deliberately irregular.
        assert all(f.evidence["destination"] != "93.184.216.34" for f in beacons)

    def test_browsing_capture_has_no_beacon(self, browsing):
        assert "possible beaconing" not in kinds(browsing)

    def test_jitter_threshold_is_configurable(self):
        assert "possible beaconing" not in kinds(analysis_of("beacon.pcap", beacon_max_jitter=0.0))


class TestCleartextCredentials:
    def test_form_post_over_http_is_reported(self, browsing):
        assert "form post over cleartext HTTP" in kinds(browsing)


class TestOutputFormats:
    def test_json_is_valid_and_complete(self, browsing):
        payload = json.loads(json.dumps(to_dict(browsing)))
        assert payload["summary"]["packets"] == 15
        assert payload["flows"] and payload["hosts"] and payload["dns"]

    def test_csv_has_a_header_and_one_row_per_flow(self, browsing):
        rows = to_csv(browsing).strip().splitlines()
        assert rows[0].startswith("source_ip,source_port")
        assert len(rows) == len(browsing.flows) + 1

    def test_markdown_sections(self, browsing):
        markdown = to_markdown(browsing, "browsing.pcap")
        for heading in (
            "## Summary",
            "## Findings",
            "## Hosts",
            "## Top flows by volume",
            "## DNS",
            "## TLS server names",
            "## HTTP requests",
            "## Timeline",
        ):
            assert heading in markdown

    def test_markdown_on_a_capture_with_no_findings(self):
        analysis = analysis_of("host_sweep.pcap")
        assert to_markdown(analysis, "x.pcap")


class TestCli:
    def test_report(self, capsys):
        assert main(["report", str(FIXTURES / "browsing.pcap")]) == 0
        assert "## Findings" in capsys.readouterr().out

    def test_report_json(self, capsys):
        assert main(["report", str(FIXTURES / "browsing.pcap"), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["summary"]["packets"] == 15

    def test_flows_csv(self, capsys):
        assert main(["flows", str(FIXTURES / "browsing.pcap")]) == 0
        assert "source_ip,source_port" in capsys.readouterr().out

    def test_timeline(self, capsys):
        assert main(["timeline", str(FIXTURES / "browsing.pcap")]) == 0
        assert "dns query" in capsys.readouterr().out

    def test_missing_file(self):
        assert main(["report", "/nonexistent.pcap"]) == 2

    def test_unreadable_capture_exits_cleanly(self, tmp_path, capsys):
        path = tmp_path / "bad.pcap"
        path.write_bytes(b"garbage" * 10)
        assert main(["report", str(path)]) == 2
        assert "error:" in capsys.readouterr().err
