# Not-Just-Nmap 🔍

A multithreaded Python TCP port scanner that goes beyond "is the port open?". It grabs banners, **fingerprints the service and version**, matches versions against known CVEs, scores the overall risk of the host, and gives a heuristic OS guess, all with zero third-party dependencies.

> ⚠️ **Use responsibly.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. This project is for education and authorized security testing.

## Features

- **Fast concurrent scanning** with a configurable thread pool
- **Banner grabbing** for plain TCP services, plus HTTP/HTTPS header probing (TLS certificate is intentionally not verified, since we are fingerprinting, not trusting)
- **Service & version fingerprinting** via regex signatures (OpenSSH, Apache, nginx, ProFTPD, FileZilla, MySQL, PostgreSQL) with a port-based fallback
- **Numeric version comparison**, so `7.10` is correctly newer than `7.4`
- **CVE matching by version range**, not just exact strings
- **Risk scoring** where the worst finding dominates the score and is not diluted by harmless ports
- **Heuristic OS guess** from open-port combinations (and a TTL helper)
- **Confidence value** for every identification (banner match vs. port-only guess)
- **JSON export** of raw results
- Pure standard library, Python 3.8+

## How the fingerprinting works

```
 open port ──► banner grab ──► signature match ──► version parsed
                                     │                    │
                              (no match?)          range check vs CVE list
                                     ▼                    ▼
                          port-number fallback     risk = f(outdated?, CVEs?)
                          (confidence 0.6)         (confidence 0.9)
```

1. **Connect** to the port with a TCP connect scan (`open`, `closed` or `filtered` on timeout).
2. **Probe**: passive read for services that greet first (SSH, FTP, SMTP); a `HEAD /` request for HTTP; a TLS handshake plus `HEAD /` for HTTPS.
3. **Identify**: the banner is matched against regex signatures in `fingerprint.py`. A match yields the service, version and 0.9 confidence. If no signature matches, the port number decides (0.6 confidence).
4. **Assess**: the parsed version is compared numerically to an "outdated below" threshold and to CVE version ranges. Any CVE match raises the risk to at least `HIGH`.
5. **Aggregate**: `RiskAssessment` combines all open services into one score (`0.7 × worst + 0.3 × average`) and generates recommendations.

## Project structure

```
├── main.py          # CLI entry point (threading, port parsing, JSON export)
├── portscanner.py   # PortScanner class: connect scan, banner grabbing, report
├── fingerprint.py   # VulnerabilityDB, OSFingerprinter, RiskAssessment
└── README.md
```

## Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
python main.py --help
```

No `pip install` needed.

## Usage

```bash
# Default: ports 1-1000
python main.py 192.168.1.10

# Single port, custom ranges and lists
python main.py scanme.nmap.org -p 22
python main.py 192.168.1.10 -p 1-1024,3306,8080-8090

# More threads, shorter timeout, live output
python main.py 192.168.1.10 -p 1-65535 -w 300 -t 1 -v

# Save results
python main.py 192.168.1.10 --json results.json
```

| Option | Description | Default |
|---|---|---|
| `host` | IP address or hostname | required |
| `-p`, `--ports` | `80`, `1-1000`, `22,80,443` or mixed | `1-1000` |
| `-t`, `--timeout` | Socket timeout (seconds) | `2.0` |
| `-w`, `--workers` | Concurrent threads | `100` |
| `-v`, `--verbose` | Print each port as it is scanned | off |
| `--json FILE` | Save raw results as JSON | off |
| `--no-banner` | Hide the ASCII banner | off |

### Example output

```
SECURITY ASSESSMENT REPORT
======================================================================
Total ports scanned: 7
Open ports found:    3
Filtered/timed out:  0

  🟠 [   22] OpenSSH 7.2              [HIGH    ] (90% confidence)
           Banner: SSH-2.0-OpenSSH_7.2p2 Ubuntu
           Known CVEs: CVE-2018-15473

  🔴 [   23] Telnet                   [CRITICAL] (60% confidence)
           Banner: login:

  🟠 [ 8080] Apache httpd 2.4.49      [HIGH    ] (90% confidence)
           Banner: HTTP/1.1 200 OK | Server: Apache/2.4.49 (Unix)
           Known CVEs: CVE-2021-41773, CVE-2021-42013

  Overall Risk Level: 🔴 CRITICAL (Score: 95/100)

  Estimated OS: Likely Linux/Unix
```

## Using it as a library

```python
from portscanner import PortScanner

scanner = PortScanner(timeout=1.5)
scanner.scan_range("127.0.0.1", 1, 1024)
for r in scanner.get_open_ports():
    print(r["port"], r["service"], r["version"], r["risk"], r["cves"])
```

## Extending the fingerprint database

Add a signature to `VulnerabilityDB.SERVICE_SIGNATURES` in `fingerprint.py`:

```python
{
    "pattern": r"Server:\s*lighttpd/(\d+(?:\.\d+)*)",
    "service": "lighttpd",
    "outdated_below": "1.4.60",
    "risk_current": "LOW",
    "risk_outdated": "MEDIUM",
    "cves": [
        # (CVE id, min version inclusive, max version exclusive, note)
        ("CVE-XXXX-YYYY", "1.4.0", "1.4.60", "description"),
    ],
}
```

> The bundled CVE list is a small illustrative sample. Verify entries against [NVD](https://nvd.nist.gov) and extend it for real-world use.

## Limitations

- Banner-based detection can be spoofed or hidden; version strings do not prove a host is vulnerable (distros backport patches without changing the version).
- CVE data is hand-curated and incomplete, not a replacement for a real vulnerability scanner.
- OS detection is a simple port/TTL heuristic, far less accurate than Nmap's TCP/IP stack fingerprinting.
- IPv4 and TCP connect scans only (no SYN/UDP scanning). Binary protocols such as MySQL's handshake are not yet parsed.

## Roadmap ideas

- [ ] Live NVD API lookups with caching
- [ ] UDP scanning and IPv6 support
- [ ] CIDR / multi-host scanning
- [ ] HTML/CSV report export
- [ ] Binary protocol parsers (MySQL, PostgreSQL, RDP)

## License

MIT (add a `LICENSE` file), or choose your own.