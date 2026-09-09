"""Rendering of an analysis as JSON, CSV or a Markdown report."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter

from netriage.analysis import WELL_KNOWN_PORTS, Analysis, Flow


def _flow_row(flow: Flow) -> dict:
    return {
        "source_ip": flow.source_ip,
        "source_port": flow.source_port,
        "destination_ip": flow.destination_ip,
        "destination_port": flow.destination_port,
        "transport": flow.transport,
        "service": flow.service,
        "packets": flow.packets,
        "bytes": flow.bytes,
        "duration_seconds": round(flow.duration_seconds, 3),
        "flags": "".join(sorted({c for f in flow.flags for c in f})),
        "first_seen": flow.first_seen.isoformat() if flow.first_seen else None,
        "last_seen": flow.last_seen.isoformat() if flow.last_seen else None,
    }


def to_dict(analysis: Analysis) -> dict:
    return {
        "summary": {
            "packets": analysis.packet_count,
            "decoded": analysis.decoded_count,
            "undecoded": analysis.undecoded_count,
            "truncated": analysis.truncated_count,
            "first_seen": analysis.first_seen.isoformat() if analysis.first_seen else None,
            "last_seen": analysis.last_seen.isoformat() if analysis.last_seen else None,
            "duration_seconds": round(analysis.duration_seconds, 3),
            "hosts": len(analysis.hosts),
            "flows": len(analysis.flows),
        },
        "findings": [
            {"kind": f.kind, "severity": f.severity, "summary": f.summary, "evidence": f.evidence}
            for f in analysis.findings
        ],
        "flows": [_flow_row(f) for f in analysis.flows],
        "hosts": {
            ip: {
                "packets": data["packets"],
                "bytes": data["bytes"],
                "peer_count": len(data["peers"]),
                "peers": data["peers"][:50],
                "ports_offered": data["ports_offered"][:50],
                "ports_contacted": data["ports_contacted"][:50],
                "first_seen": data["first_seen"].isoformat() if data["first_seen"] else None,
                "last_seen": data["last_seen"].isoformat() if data["last_seen"] else None,
            }
            for ip, data in analysis.hosts.items()
        },
        "dns": analysis.dns_queries,
        "http": analysis.http_requests,
        "tls": analysis.tls_names,
        "protocols": dict(analysis.protocol_counts),
        "top_ports": [
            {
                "transport": transport,
                "port": port,
                "service": WELL_KNOWN_PORTS.get(port, ""),
                "packets": count,
            }
            for (transport, port), count in analysis.port_counts.most_common(20)
        ],
    }


def to_csv(analysis: Analysis) -> str:
    buffer = io.StringIO()
    rows = [_flow_row(f) for f in analysis.flows]
    fieldnames = (
        list(_flow_row(analysis.flows[0]).keys())
        if analysis.flows
        else [
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "transport",
            "service",
            "packets",
            "bytes",
            "duration_seconds",
            "flags",
            "first_seen",
            "last_seen",
        ]
    )
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def to_markdown(analysis: Analysis, source: str, *, top: int = 15) -> str:
    lines = [
        f"# Capture triage: {source}",
        "",
        "## Summary",
        "",
        f"- Packets: {analysis.packet_count} ({analysis.decoded_count} decoded, "
        f"{analysis.undecoded_count} not decoded, {analysis.truncated_count} truncated)",
        f"- Window: {analysis.first_seen.isoformat() if analysis.first_seen else 'n/a'} to "
        f"{analysis.last_seen.isoformat() if analysis.last_seen else 'n/a'} "
        f"({analysis.duration_seconds:.1f}s)",
        f"- Hosts: {len(analysis.hosts)}   Flows: {len(analysis.flows)}",
        f"- Protocols: {', '.join(f'{k} {v}' for k, v in analysis.protocol_counts.most_common())}",
        "",
        "## Findings",
        "",
    ]
    if analysis.findings:
        lines += ["| Severity | Finding | Detail |", "| --- | --- | --- |"]
        lines += [f"| {f.severity} | {f.kind} | {f.summary} |" for f in analysis.findings]
    else:
        lines.append("No scanning, beaconing or cleartext-credential patterns were detected.")

    lines += [
        "",
        "## Hosts",
        "",
        "| Address | Packets | Bytes | Peers | Ports contacted |",
        "| --- | --- | --- | --- | --- |",
    ]
    ordered_hosts = sorted(analysis.hosts.items(), key=lambda kv: kv[1]["bytes"], reverse=True)
    for ip, data in ordered_hosts[:top]:
        ports = ", ".join(str(p) for p in data["ports_contacted"][:8])
        suffix = "..." if len(data["ports_contacted"]) > 8 else ""
        lines.append(
            f"| {ip} | {data['packets']} | {data['bytes']} | "
            f"{len(data['peers'])} | {ports}{suffix} |"
        )

    lines += [
        "",
        "## Top flows by volume",
        "",
        "| Source | Destination | Proto | Service | Packets | Bytes | Duration | Flags |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for flow in analysis.flows[:top]:
        row = _flow_row(flow)
        lines.append(
            f"| {row['source_ip']}:{row['source_port']} | "
            f"{row['destination_ip']}:{row['destination_port']} | {row['transport']} | "
            f"{row['service']} | {row['packets']} | {row['bytes']} | "
            f"{row['duration_seconds']}s | {row['flags']} |"
        )

    if analysis.dns_queries:
        lines += ["", "## DNS", ""]
        names = Counter(q["name"] for q in analysis.dns_queries if not q["is_response"])
        lines += ["| Name | Queries | Type | Answers |", "| --- | --- | --- | --- |"]
        for name, count in names.most_common(top):
            record = next((q for q in analysis.dns_queries if q["name"] == name), {})
            responses = [q for q in analysis.dns_queries if q["name"] == name and q["is_response"]]
            answers = "; ".join(a for r in responses for a in r["answers"]) or (
                "NXDOMAIN" if any(r["rcode"] == 3 for r in responses) else ""
            )
            lines.append(f"| {name} | {count} | {record.get('type', '')} | {answers} |")

    if analysis.tls_names:
        lines += [
            "",
            "## TLS server names",
            "",
            "| Time | Client | Server | Name |",
            "| --- | --- | --- | --- |",
        ]
        for entry in analysis.tls_names[:top]:
            lines.append(
                f"| {entry['timestamp']} | {entry['source_ip']} | "
                f"{entry['destination_ip']}:{entry['destination_port']} | {entry['server_name']} |"
            )

    if analysis.http_requests:
        lines += [
            "",
            "## HTTP requests",
            "",
            "| Time | Client | Method | Host | URI | User-Agent |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for entry in analysis.http_requests[:top]:
            lines.append(
                f"| {entry['timestamp']} | {entry['source_ip']} | {entry['method']} | "
                f"{entry['host']} | {entry['uri']} | {entry['user_agent'][:40]} |"
            )

    lines += ["", "## Timeline", ""]
    for event in timeline(analysis)[:40]:
        lines.append(f"- {event['timestamp']}  {event['event']}: {event['detail']}")
    return "\n".join(lines) + "\n"


def timeline(analysis: Analysis) -> list[dict]:
    events: list[dict] = []
    for query in analysis.dns_queries:
        if query["is_response"]:
            continue
        events.append(
            {
                "timestamp": query["timestamp"],
                "event": "dns query",
                "detail": f"{query['client']} asked for {query['name']} ({query['type']})",
            }
        )
    for entry in analysis.http_requests:
        events.append(
            {
                "timestamp": entry["timestamp"],
                "event": "http request",
                "detail": f"{entry['source_ip']} {entry['method']} {entry['host']}{entry['uri']}",
            }
        )
    for entry in analysis.tls_names:
        events.append(
            {
                "timestamp": entry["timestamp"],
                "event": "tls client hello",
                "detail": f"{entry['source_ip']} -> {entry['server_name']}",
            }
        )
    for finding in analysis.findings:
        events.append(
            {
                "timestamp": analysis.first_seen.isoformat() if analysis.first_seen else "",
                "event": finding.kind,
                "detail": finding.summary,
            }
        )
    return sorted(events, key=lambda e: e["timestamp"])


def to_json(analysis: Analysis) -> str:
    return json.dumps(to_dict(analysis), indent=2)
