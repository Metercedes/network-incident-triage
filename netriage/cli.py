"""Command line entry point.

netriage report CAPTURE.pcap          Markdown triage report
netriage report CAPTURE.pcap --json   the same analysis as JSON
netriage flows CAPTURE.pcap           flow table as CSV
netriage timeline CAPTURE.pcap        investigation timeline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netriage.analysis import analyse
from netriage.capture import CaptureError, read_capture
from netriage.report import timeline, to_csv, to_json, to_markdown


def _analysis(args: argparse.Namespace):
    packets = read_capture(args.path)
    return analyse(
        packets,
        scan_port_threshold=args.scan_ports,
        scan_host_threshold=args.scan_hosts,
        beacon_min_events=args.beacon_events,
        beacon_max_jitter=args.beacon_jitter,
    )


def cmd_report(args: argparse.Namespace) -> int:
    analysis = _analysis(args)
    output = to_json(analysis) if args.json else to_markdown(analysis, args.path.name)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(output, end="" if not args.json else "\n")
    return 0


def cmd_flows(args: argparse.Namespace) -> int:
    print(to_csv(_analysis(args)), end="")
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    events = timeline(_analysis(args))
    if args.json:
        print(json.dumps(events, indent=2))
        return 0
    for event in events:
        print(f"{event['timestamp']}  {event['event']}: {event['detail']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netriage", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text, func in (
        ("report", "Markdown or JSON triage report", cmd_report),
        ("flows", "flow table as CSV", cmd_flows),
        ("timeline", "investigation timeline", cmd_timeline),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("path", type=Path)
        command.add_argument("--json", action="store_true")
        command.add_argument("-o", "--output", type=Path)
        command.add_argument(
            "--scan-ports",
            type=int,
            default=15,
            help="distinct ports on one host before a port scan is reported",
        )
        command.add_argument(
            "--scan-hosts",
            type=int,
            default=15,
            help="distinct hosts on one port before a sweep is reported",
        )
        command.add_argument(
            "--beacon-events",
            type=int,
            default=6,
            help="minimum connections before beaconing is considered",
        )
        command.add_argument(
            "--beacon-jitter",
            type=float,
            default=0.15,
            help="maximum coefficient of variation of the interval",
        )
        command.set_defaults(func=func)

    args = parser.parse_args(argv)
    if not args.path.exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except CaptureError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
