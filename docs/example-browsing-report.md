# Capture triage: browsing.pcap

## Summary

- Packets: 15 (15 decoded, 0 not decoded, 0 truncated)
- Window: 2026-03-02T09:00:00+00:00 to 2026-03-02T09:00:03+00:00 (3.0s)
- Hosts: 5   Flows: 11
- Protocols: tcp 9, udp 6

## Findings

| Severity | Finding | Detail |
| --- | --- | --- |
| notable | form post over cleartext HTTP | 1 form submission(s) sent without TLS |

## Hosts

| Address | Packets | Bytes | Peers | Ports contacted |
| --- | --- | --- | --- | --- |
| 10.20.1.15 | 15 | 1402 | 4 | 53, 80, 443 |
| 10.20.1.1 | 6 | 500 | 1 | 51514, 51515, 51516 |
| 93.184.216.34 | 5 | 460 | 1 | 49200 |
| 151.101.1.140 | 3 | 238 | 1 | 49201 |
| 10.20.1.50 | 1 | 204 | 1 |  |

## Top flows by volume

| Source | Destination | Proto | Service | Packets | Bytes | Duration | Flags |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10.20.1.15:49200 | 93.184.216.34:80 | tcp | http | 3 | 309 | 0.03s | APS |
| 10.20.1.15:49202 | 10.20.1.50:80 | tcp | http | 1 | 204 | 0.0s | AP |
| 10.20.1.15:49201 | 151.101.1.140:443 | tcp | https | 2 | 184 | 0.03s | APS |
| 93.184.216.34:80 | 10.20.1.15:49200 | tcp | http | 2 | 151 | 0.06s | APS |
| 10.20.1.1:53 | 10.20.1.15:51514 | udp | dns | 1 | 96 | 0.0s |  |
| 10.20.1.1:53 | 10.20.1.15:51515 | udp | dns | 1 | 91 | 0.0s |  |
| 10.20.1.15:51514 | 10.20.1.1:53 | udp | dns | 1 | 80 | 0.0s |  |
| 10.20.1.15:51516 | 10.20.1.1:53 | udp | dns | 1 | 79 | 0.0s |  |
| 10.20.1.1:53 | 10.20.1.15:51516 | udp | dns | 1 | 79 | 0.0s |  |
| 10.20.1.15:51515 | 10.20.1.1:53 | udp | dns | 1 | 75 | 0.0s |  |
| 151.101.1.140:443 | 10.20.1.15:49201 | tcp | https | 1 | 54 | 0.0s | AS |

## DNS

| Name | Queries | Type | Answers |
| --- | --- | --- | --- |
| intranet.contoso.com | 1 | A | A 93.184.216.34 |
| cdn.example.net | 1 | A | A 151.101.1.140 |
| missing.contoso.com | 1 | A | NXDOMAIN |

## TLS server names

| Time | Client | Server | Name |
| --- | --- | --- | --- |
| 2026-03-02T09:00:01.080000+00:00 | 10.20.1.15 | 151.101.1.140:443 | cdn.example.net |

## HTTP requests

| Time | Client | Method | Host | URI | User-Agent |
| --- | --- | --- | --- | --- | --- |
| 2026-03-02T09:00:00.080000+00:00 | 10.20.1.15 | GET | intranet.contoso.com | /dashboard | Mozilla/5.0 (Windows NT 10.0; Win64; x64 |
| 2026-03-02T09:00:03+00:00 | 10.20.1.15 | POST | legacy.contoso.com | /login |  |

## Timeline

- 2026-03-02T09:00:00+00:00  dns query: 10.20.1.15 asked for intranet.contoso.com (A)
- 2026-03-02T09:00:00+00:00  form post over cleartext HTTP: 1 form submission(s) sent without TLS
- 2026-03-02T09:00:00.080000+00:00  http request: 10.20.1.15 GET intranet.contoso.com/dashboard
- 2026-03-02T09:00:01+00:00  dns query: 10.20.1.15 asked for cdn.example.net (A)
- 2026-03-02T09:00:01.080000+00:00  tls client hello: 10.20.1.15 -> cdn.example.net
- 2026-03-02T09:00:02+00:00  dns query: 10.20.1.15 asked for missing.contoso.com (A)
- 2026-03-02T09:00:03+00:00  http request: 10.20.1.15 POST legacy.contoso.com/login
