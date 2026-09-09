# network-incident-triage

Reads a pcap or pcapng and produces the views an analyst opens first: host inventory, flow table,
DNS and TLS server names, HTTP request metadata, an investigation timeline, and findings for port
scans, host sweeps, beaconing and cleartext form posts. Output is Markdown, JSON or CSV.

The capture parser is written from the format specifications rather than wrapping a library, and
the test suite checks its output against tshark on every fixture: packet counts, timestamps, frame
lengths, addresses, ports, TCP flags, DNS names and answers, TLS server names, and HTTP hosts and
URIs all have to agree.

```
$ netriage report tests/fixtures/beacon.pcap

| Severity | Finding | Detail |
| --- | --- | --- |
| high | possible beaconing | 10.20.1.77 contacted 198.51.100.23:443 12 times at a mean interval of 60.2s with 2.0% jitter |
```

## Running it

Python 3.11 or newer, no dependencies outside the standard library.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

netriage report capture.pcap                 # Markdown report
netriage report capture.pcap --json          # the same analysis as JSON
netriage flows capture.pcap                  # flow table as CSV
netriage timeline capture.pcap               # DNS, HTTP, TLS and findings in time order
pytest                                       # 90 tests, 27 of them against tshark
```

Thresholds are arguments, because the right value depends on the network:

```bash
netriage report capture.pcap --scan-ports 30 --scan-hosts 50 \
                             --beacon-events 10 --beacon-jitter 0.05
```

## What it parses

**Containers.** Classic pcap in both byte orders and with microsecond or nanosecond timestamps,
and pcapng including the interface description block that defines timestamp resolution. Link types
Ethernet, Linux cooked capture, raw IP and BSD loopback.

**Network and transport.** IPv4 with fragmentation handling, IPv6 including the extension header
chain, VLAN and QinQ tags, TCP with flags, UDP, ICMP and ICMPv6.

**Application.** DNS queries and answers with compression-pointer following, TLS server names from
the ClientHello, and HTTP request metadata.

A decoder returns nothing rather than raising when a packet is short or malformed, because a
capture taken under load is full of those and a tool that stops on the first one is useless. The
counts of undecoded and truncated packets are reported in the summary instead.

## Findings

**Port scan and host sweep** are separated because they are different behaviours. Many ports on
one host is enumeration of a target; one port across many hosts is a search for a service. The
report gives the source, the target set, and how many attempts went unanswered.

**Beaconing** is measured as the coefficient of variation of the intervals between connection
starts: standard deviation over mean. That is scale-free, so a 30-second check-in and an hourly
one are judged the same way. Measuring between packets rather than between connections is the
obvious mistake here, and it hides every beacon, because the gaps then alternate between the
milliseconds inside one connection and the minutes between them.

**High NXDOMAIN rate** per client, which is what a domain generation algorithm looks like from the
resolver's side.

**Form posts over cleartext HTTP**, which are credentials on the wire.

## Verification

`tests/test_against_tshark.py` runs tshark over the same fixtures and compares what both tools
read. This exists because writing a packet decoder means deciding what every byte means, and being
confidently wrong is easy: a wrong IHL, an ignored VLAN tag, or a misread data offset all produce
plausible output that is quietly incorrect.

The tests are skipped if tshark is not installed, so the suite runs anywhere, but CI installs
tshark and runs them.

## Test captures

The five fixtures in `tests/fixtures/` are built byte by byte by `scripts/generate_captures.py`,
not recorded. Nothing here is anyone's traffic. Building them means each scenario contains exactly
the behaviour a test needs: the beacon capture has irregular browsing to a second host alongside
the regular check-ins, so the tests can assert the heuristic distinguishes them.

Every capture is checked to open cleanly in tshark, which is also what confirms they are
well-formed rather than merely parseable by this code.

## Sample output

`docs/example-browsing-report.md` and `docs/example-beacon-report.md` are the full reports for two
fixtures, regenerated in CI so they cannot drift from what the code produces.

## Limitations

- No TCP stream reassembly. HTTP and TLS metadata are read from the first packet of a request, so
  a request split across segments is missed. Adding reassembly would mean tracking sequence
  numbers and handling retransmission and overlap, which is a different size of problem.
- HTTP parsing covers plaintext only. For TLS, the server name from the ClientHello is all that is
  available without decryption, and that is usually enough for triage.
- The beaconing heuristic finds regular intervals. An implant with deliberate randomised jitter
  will not be caught by it, and a poorly written backup agent will be.
- Findings are leads, not verdicts. A port scan finding on a vulnerability scanner's subnet is
  correct and uninteresting.
- Whole captures are loaded into memory. That is fine for the sizes a triage tool sees and wrong
  for a multi-gigabyte capture.
