"""Aggregation of decoded packets into the views an analyst actually looks at."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from netriage.capture import Packet
from netriage.decode import (
    DNS_TYPES,
    PROTO_TCP,
    PROTO_UDP,
    TCP_ACK,
    TCP_SYN,
    Decoded,
    decode,
    parse_dns,
    parse_http_request,
    parse_tls_sni,
)

WELL_KNOWN_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5985: "winrm",
    5986: "winrm-https",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass
class Flow:
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    transport: str
    packets: int = 0
    bytes: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    flags: set[str] = field(default_factory=set)
    timestamps: list[datetime] = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.transport,
        )

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def service(self) -> str:
        for port in (self.destination_port, self.source_port):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]
        return ""


@dataclass
class Finding:
    kind: str
    severity: str
    summary: str
    evidence: dict


@dataclass
class Analysis:
    packet_count: int = 0
    decoded_count: int = 0
    undecoded_count: int = 0
    truncated_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    flows: list[Flow] = field(default_factory=list)
    hosts: dict[str, dict] = field(default_factory=dict)
    dns_queries: list[dict] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    tls_names: list[dict] = field(default_factory=list)
    protocol_counts: Counter = field(default_factory=Counter)
    port_counts: Counter = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds()


def analyse(
    packets: list[Packet],
    *,
    scan_port_threshold: int = 15,
    scan_host_threshold: int = 15,
    beacon_min_events: int = 6,
    beacon_max_jitter: float = 0.15,
) -> Analysis:
    result = Analysis(packet_count=len(packets))
    flows: dict[tuple, Flow] = {}
    hosts: dict[str, dict] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "peers": set(),
            "ports_offered": set(),
            "ports_contacted": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )
    syn_targets: dict[str, set[tuple[str, int]]] = defaultdict(set)
    answered: set[tuple[str, str, int]] = set()

    for packet in packets:
        if packet.truncated:
            result.truncated_count += 1
        if result.first_seen is None or packet.timestamp < result.first_seen:
            result.first_seen = packet.timestamp
        if result.last_seen is None or packet.timestamp > result.last_seen:
            result.last_seen = packet.timestamp

        decoded = decode(packet)
        if decoded is None or decoded.source_ip is None:
            result.undecoded_count += 1
            continue
        result.decoded_count += 1
        result.protocol_counts[decoded.transport] += 1

        _record_host(hosts, decoded.source_ip, decoded, packet, sending=True)
        _record_host(hosts, decoded.destination_ip, decoded, packet, sending=False)

        if decoded.destination_port is not None:
            result.port_counts[(decoded.transport, decoded.destination_port)] += 1

        flow = _flow_for(flows, decoded)
        flow.packets += 1
        flow.bytes += packet.original_length
        flow.timestamps.append(packet.timestamp)
        if flow.first_seen is None or packet.timestamp < flow.first_seen:
            flow.first_seen = packet.timestamp
        if flow.last_seen is None or packet.timestamp > flow.last_seen:
            flow.last_seen = packet.timestamp
        if decoded.flag_string:
            flow.flags.add(decoded.flag_string)

        if decoded.protocol == PROTO_TCP:
            syn_only = decoded.tcp_flags & TCP_SYN and not decoded.tcp_flags & TCP_ACK
            if syn_only:
                syn_targets[decoded.source_ip].add(
                    (decoded.destination_ip, decoded.destination_port)
                )
            elif decoded.tcp_flags & TCP_SYN and decoded.tcp_flags & TCP_ACK:
                answered.add((decoded.destination_ip, decoded.source_ip, decoded.source_port))

        _record_application(result, decoded, packet)

    result.flows = sorted(flows.values(), key=lambda f: f.bytes, reverse=True)
    result.hosts = {
        ip: {
            **data,
            "peers": sorted(data["peers"]),
            "ports_offered": sorted(data["ports_offered"]),
            "ports_contacted": sorted(data["ports_contacted"]),
        }
        for ip, data in sorted(hosts.items())
    }
    result.findings = _findings(
        result,
        syn_targets,
        answered,
        scan_port_threshold,
        scan_host_threshold,
        beacon_min_events,
        beacon_max_jitter,
    )
    return result


def _flow_for(flows: dict[tuple, Flow], decoded: Decoded) -> Flow:
    key = (
        decoded.source_ip,
        decoded.source_port,
        decoded.destination_ip,
        decoded.destination_port,
        decoded.transport,
    )
    if key not in flows:
        flows[key] = Flow(
            decoded.source_ip,
            decoded.source_port,
            decoded.destination_ip,
            decoded.destination_port,
            decoded.transport,
        )
    return flows[key]


def _record_host(hosts, ip, decoded: Decoded, packet: Packet, *, sending: bool) -> None:
    entry = hosts[ip]
    entry["packets"] += 1
    entry["bytes"] += packet.original_length
    peer = decoded.destination_ip if sending else decoded.source_ip
    if peer:
        entry["peers"].add(peer)
    if sending and decoded.destination_port is not None:
        entry["ports_contacted"].add(decoded.destination_port)
    if not sending and decoded.destination_port is not None:
        entry["ports_offered"].add(decoded.destination_port)
    if entry["first_seen"] is None or packet.timestamp < entry["first_seen"]:
        entry["first_seen"] = packet.timestamp
    if entry["last_seen"] is None or packet.timestamp > entry["last_seen"]:
        entry["last_seen"] = packet.timestamp


def _record_application(result: Analysis, decoded: Decoded, packet: Packet) -> None:
    if not decoded.payload:
        return

    if decoded.protocol == PROTO_UDP and 53 in (decoded.source_port, decoded.destination_port):
        message = parse_dns(decoded.payload)
        if message:
            for question in message.questions:
                result.dns_queries.append(
                    {
                        "timestamp": packet.timestamp.isoformat(),
                        "client": decoded.source_ip
                        if not message.is_response
                        else decoded.destination_ip,
                        "server": decoded.destination_ip
                        if not message.is_response
                        else decoded.source_ip,
                        "name": question.name,
                        "type": DNS_TYPES.get(question.qtype, str(question.qtype)),
                        "is_response": message.is_response,
                        "rcode": message.rcode,
                        "answers": [
                            f"{DNS_TYPES.get(a.rtype, a.rtype)} {a.value}" for a in message.answers
                        ],
                    }
                )
        return

    if decoded.protocol != PROTO_TCP:
        return

    request = parse_http_request(decoded.payload)
    if request:
        result.http_requests.append(
            {
                "timestamp": packet.timestamp.isoformat(),
                "source_ip": decoded.source_ip,
                "destination_ip": decoded.destination_ip,
                "destination_port": decoded.destination_port,
                **request,
            }
        )
        return

    name = parse_tls_sni(decoded.payload)
    if name:
        result.tls_names.append(
            {
                "timestamp": packet.timestamp.isoformat(),
                "source_ip": decoded.source_ip,
                "destination_ip": decoded.destination_ip,
                "destination_port": decoded.destination_port,
                "server_name": name,
            }
        )


def _findings(
    result: Analysis,
    syn_targets,
    answered,
    port_threshold: int,
    host_threshold: int,
    beacon_min_events: int,
    beacon_max_jitter: float,
) -> list[Finding]:
    findings: list[Finding] = []

    for source, targets in syn_targets.items():
        destinations = {ip for ip, _ in targets}
        unanswered = [t for t in targets if (source, t[0], t[1]) not in answered]

        # Many ports on one host is a port scan; one port across many hosts is a sweep looking for
        # a service. They are different behaviours and worth separating in the report.
        by_host = defaultdict(set)
        for ip, port in targets:
            by_host[ip].add(port)
        for destination, ports in by_host.items():
            if len(ports) >= port_threshold:
                findings.append(
                    Finding(
                        "port scan",
                        "high",
                        f"{source} sent SYN to {len(ports)} ports on {destination}",
                        {
                            "source": source,
                            "destination": destination,
                            "port_count": len(ports),
                            "ports": sorted(ports)[:40],
                            "unanswered": len([t for t in unanswered if t[0] == destination]),
                        },
                    )
                )

        by_port = defaultdict(set)
        for ip, port in targets:
            by_port[port].add(ip)
        for port, ips in by_port.items():
            if len(ips) >= host_threshold:
                findings.append(
                    Finding(
                        "host sweep",
                        "high",
                        f"{source} sent SYN to port {port} on {len(ips)} hosts",
                        {
                            "source": source,
                            "port": port,
                            "host_count": len(ips),
                            "hosts": sorted(ips)[:40],
                        },
                    )
                )

        if len(destinations) >= host_threshold and len(unanswered) >= len(targets) * 0.8:
            findings.append(
                Finding(
                    "unanswered connection attempts",
                    "notable",
                    f"{source} attempted {len(targets)} connections, {len(unanswered)} unanswered",
                    {"source": source, "attempted": len(targets), "unanswered": len(unanswered)},
                )
            )

    findings.extend(_beacon_findings(result, beacon_min_events, beacon_max_jitter))

    failures = defaultdict(int)
    for query in result.dns_queries:
        if query["is_response"] and query["rcode"] == 3:
            failures[query["client"]] += 1
    for client, count in failures.items():
        if count >= 20:
            findings.append(
                Finding(
                    "high NXDOMAIN rate",
                    "notable",
                    f"{client} received {count} NXDOMAIN responses",
                    {"client": client, "count": count},
                )
            )

    plaintext_credentials = [
        request
        for request in result.http_requests
        if request["method"] == "POST" and "urlencoded" in request.get("content_type", "")
    ]
    if plaintext_credentials:
        findings.append(
            Finding(
                "form post over cleartext HTTP",
                "notable",
                f"{len(plaintext_credentials)} form submission(s) sent without TLS",
                {"requests": [f"{r['host']}{r['uri']}" for r in plaintext_credentials[:10]]},
            )
        )

    return sorted(findings, key=lambda f: {"high": 0, "notable": 1, "info": 2}[f.severity])


def _beacon_findings(result: Analysis, min_events: int, max_jitter: float) -> list[Finding]:
    """Flag repeated contact at a suspiciously regular interval.

    Automated check-ins produce evenly spaced connections. Human-driven traffic does not. The
    measure is the coefficient of variation of the inter-arrival gaps: standard deviation over
    mean, which is scale-free, so a 30-second beacon and an hourly one are judged the same way.

    The interval is measured between the starts of successive connections, not between packets.
    Measuring packets makes the gaps alternate between the milliseconds inside one connection and
    the minutes between connections, which produces enormous variance and hides every beacon.
    """
    findings: list[Finding] = []
    by_pair: dict[tuple, list[datetime]] = defaultdict(list)
    for flow in result.flows:
        if flow.first_seen is None:
            continue
        # Only the initiating direction counts, or each check-in is recorded twice.
        if flow.destination_port is None or (
            flow.source_port is not None and flow.source_port < flow.destination_port
        ):
            continue
        by_pair[(flow.source_ip, flow.destination_ip, flow.destination_port)].append(
            flow.first_seen
        )

    for (source, destination, port), times in by_pair.items():
        if len(times) < min_events:
            continue
        ordered = sorted(times)
        gaps = [(b - a).total_seconds() for a, b in zip(ordered, ordered[1:], strict=False)]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < min_events - 1:
            continue
        mean = statistics.fmean(gaps)
        if mean <= 0:
            continue
        jitter = statistics.pstdev(gaps) / mean
        if jitter <= max_jitter:
            findings.append(
                Finding(
                    "possible beaconing",
                    "high",
                    f"{source} contacted {destination}:{port} {len(ordered)} times at "
                    f"a mean interval of {mean:.1f}s with {jitter * 100:.1f}% jitter",
                    {
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "connections": len(ordered),
                        "mean_interval_seconds": round(mean, 2),
                        "jitter_ratio": round(jitter, 4),
                    },
                )
            )
    return findings
