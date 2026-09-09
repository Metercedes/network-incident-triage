# Capture triage: beacon.pcap

## Summary

- Packets: 43 (43 decoded, 0 not decoded, 0 truncated)
- Window: 2026-03-02T09:00:00+00:00 to 2026-03-02T09:11:01.850000+00:00 (661.9s)
- Hosts: 3   Flows: 31
- Protocols: tcp 43

## Findings

| Severity | Finding | Detail |
| --- | --- | --- |
| high | possible beaconing | 10.20.1.77 contacted 198.51.100.23:443 12 times at a mean interval of 60.2s with 2.0% jitter |

## Hosts

| Address | Packets | Bytes | Peers | Ports contacted |
| --- | --- | --- | --- | --- |
| 10.20.1.77 | 43 | 3282 | 2 | 443 |
| 198.51.100.23 | 36 | 2904 | 1 | 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007... |
| 93.184.216.34 | 7 | 378 | 1 |  |

## Top flows by volume

| Source | Destination | Proto | Service | Packets | Bytes | Duration | Flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10.20.1.77:50000 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50001 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50002 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50003 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50004 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50005 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50006 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50007 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50008 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50009 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50010 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 10.20.1.77:50011 | 198.51.100.23:443 | tcp | https | 2 | 188 | 0.05s | APS |
| 198.51.100.23:443 | 10.20.1.77:50000 | tcp | https | 1 | 54 | 0.0s | AS |
| 10.20.1.77:51000 | 93.184.216.34:443 | tcp | https | 1 | 54 | 0.0s | S |
| 10.20.1.77:51001 | 93.184.216.34:443 | tcp | https | 1 | 54 | 0.0s | S |

## TLS server names

| Time | Client | Server | Name |
| --- | --- | --- | --- |
| 2026-03-02T09:00:00.050000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:01:00.950000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:02:01.850000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:03:00.050000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:04:00.950000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:05:01.850000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:06:00.050000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:07:00.950000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:08:01.850000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:09:00.050000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:10:00.950000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |
| 2026-03-02T09:11:01.850000+00:00 | 10.20.1.77 | 198.51.100.23:443 | update.cdn-sync.top |

## Timeline

- 2026-03-02T09:00:00+00:00  possible beaconing: 10.20.1.77 contacted 198.51.100.23:443 12 times at a mean interval of 60.2s with 2.0% jitter
- 2026-03-02T09:00:00.050000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:01:00.950000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:02:01.850000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:03:00.050000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:04:00.950000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:05:01.850000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:06:00.050000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:07:00.950000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:08:01.850000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:09:00.050000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:10:00.950000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
- 2026-03-02T09:11:01.850000+00:00  tls client hello: 10.20.1.77 -> update.cdn-sync.top
