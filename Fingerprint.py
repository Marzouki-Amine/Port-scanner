#!/usr/bin/env python3
"""
Service Fingerprinting & Vulnerability Database

Maps banners and ports to services, versions, risk levels and known CVEs.

NOTE: The CVE data below is a small, hand-picked *illustrative* set.
Always verify against https://nvd.nist.gov before relying on it.
"""

import re
from typing import Dict, List, Optional, Tuple

Version = Tuple[int, ...]

RISK_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def parse_version(text: Optional[str]) -> Optional[Version]:
    """'7.2p2' -> (7, 2), '2.4.49' -> (2, 4, 49), 'abc' -> None."""
    if not text:
        return None
    m = re.match(r"\d+(?:\.\d+)*", text)
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def _pad(a: Version, b: Version) -> Tuple[Version, Version]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def version_in_range(v: Version, low: str, high_excl: str) -> bool:
    """True if low <= v < high_excl (numeric, not string, comparison)."""
    lo, hi = parse_version(low), parse_version(high_excl)
    a, lo = _pad(v, lo)
    a2, hi = _pad(v, hi)
    return lo <= a and a2 < hi


def max_risk(a: str, b: str) -> str:
    return a if RISK_ORDER.index(a) >= RISK_ORDER.index(b) else b


class VulnerabilityDB:
    """Lightweight service and vulnerability knowledge base."""

    # Each signature:
    #   pattern         regex run against the banner (first group(s) = version)
    #   service         display name
    #   outdated_below  versions below this are treated as outdated (optional)
    #   risk_current    risk for a current/unknown version
    #   risk_outdated   risk for an outdated version
    #   cves            list of (cve_id, min_version, max_version_exclusive, note)
    SERVICE_SIGNATURES = [
        {
            "pattern": r"SSH-2\.0-OpenSSH_(\d+(?:\.\d+)*)",
            "service": "OpenSSH",
            "outdated_below": "7.4",
            "risk_current": "LOW",
            "risk_outdated": "HIGH",
            "cves": [
                ("CVE-2018-15473", "0", "7.8", "username enumeration"),
                ("CVE-2015-5352", "0", "6.9", "X11 forwarding timeout bypass"),
            ],
        },
        {
            "pattern": r"Server:\s*Apache/(\d+(?:\.\d+)*)",
            "service": "Apache httpd",
            "outdated_below": "2.4.41",
            "risk_current": "LOW",
            "risk_outdated": "HIGH",
            "cves": [
                ("CVE-2021-41773", "2.4.49", "2.4.50", "path traversal / RCE"),
                ("CVE-2021-42013", "2.4.49", "2.4.51", "path traversal / RCE (incomplete fix)"),
            ],
        },
        {
            "pattern": r"Server:\s*nginx/(\d+(?:\.\d+)*)",
            "service": "nginx",
            "outdated_below": "1.20",
            "risk_current": "LOW",
            "risk_outdated": "MEDIUM",
            "cves": [
                ("CVE-2021-23017", "0.6.18", "1.20.1", "DNS resolver off-by-one"),
            ],
        },
        {
            "pattern": r"220.*FileZilla.*FTP.*Server",
            "service": "FileZilla FTP",
            "risk_current": "HIGH",  # plain-text FTP
            "risk_outdated": "HIGH",
            "cves": [],
        },
        {
            "pattern": r"220.*ProFTPD\s+(\d+(?:\.\d+)*)?",
            "service": "ProFTPD",
            "risk_current": "MEDIUM",
            "risk_outdated": "MEDIUM",
            "cves": [
                ("CVE-2015-3306", "1.3.5", "1.3.5.1", "mod_copy unauthenticated file copy (if module enabled)"),
            ],
        },
        {
            "pattern": r"MySQL Server (\d+(?:\.\d+)*)",
            "service": "MySQL",
            "outdated_below": "5.7",
            "risk_current": "HIGH",
            "risk_outdated": "CRITICAL",
            "cves": [],  # add your own verified entries here
        },
        {
            "pattern": r"PostgreSQL (\d+(?:\.\d+)*)",
            "service": "PostgreSQL",
            "outdated_below": "12.0",
            "risk_current": "LOW",
            "risk_outdated": "HIGH",
            "cves": [],  # add your own verified entries here
        },
    ]

    # Port -> (service, base risk) fallback
    DEFAULT_RISKS = {
        21: ("FTP", "HIGH"),
        22: ("SSH", "LOW"),
        23: ("Telnet", "CRITICAL"),
        25: ("SMTP", "MEDIUM"),
        53: ("DNS", "MEDIUM"),
        80: ("HTTP", "MEDIUM"),
        110: ("POP3", "HIGH"),
        143: ("IMAP", "HIGH"),
        389: ("LDAP", "HIGH"),
        443: ("HTTPS", "LOW"),
        445: ("SMB", "CRITICAL"),
        3306: ("MySQL", "HIGH"),
        3389: ("RDP", "CRITICAL"),
        5432: ("PostgreSQL", "HIGH"),
        5900: ("VNC", "CRITICAL"),
        8080: ("HTTP-Alt", "MEDIUM"),
        27017: ("MongoDB", "CRITICAL"),
    }

    @staticmethod
    def _port_fallback(port: int, result: Dict) -> Dict:
        if port in VulnerabilityDB.DEFAULT_RISKS:
            service, risk = VulnerabilityDB.DEFAULT_RISKS[port]
            result["service"] = service
            result["risk"] = risk
            result["confidence"] = 0.6
            result["details"] = "identified by port number only"
        return result

    @staticmethod
    def identify_service(port: int, banner: Optional[str]) -> Dict:
        """
        Identify a service from port + banner.

        Returns: {service, version, risk, confidence, cves, details}
        """
        result = {
            "service": None,
            "version": None,
            "risk": "UNKNOWN",
            "confidence": 0.0,
            "cves": [],
            "details": "",
        }

        if not banner:
            return VulnerabilityDB._port_fallback(port, result)

        for sig in VulnerabilityDB.SERVICE_SIGNATURES:
            match = re.search(sig["pattern"], banner, re.IGNORECASE)
            if not match:
                continue

            result["service"] = sig["service"]
            result["confidence"] = 0.9

            raw_version = next((g for g in match.groups() if g), None)
            version = parse_version(raw_version)
            risk = sig["risk_current"]

            if version:
                result["version"] = raw_version
                below = sig.get("outdated_below")
                if below and not version_in_range(version, "0", below):
                    pass  # up to date
                elif below:
                    risk = sig["risk_outdated"]
                    result["details"] = f"version older than {below}"

                for cve_id, low, high, _note in sig["cves"]:
                    if version_in_range(version, low, high):
                        result["cves"].append(cve_id)

                if result["cves"]:
                    risk = max_risk(risk, "HIGH")
            else:
                result["confidence"] = 0.7  # service known, version unknown

            result["risk"] = risk
            return result

        return VulnerabilityDB._port_fallback(port, result)


class OSFingerprinter:
    """
    Simplified OS guessing (educational). Real tools such as Nmap analyse
    TCP window size, DF flag, options ordering, timestamps, etc.
    """

    # Common initial TTL values
    INITIAL_TTLS = {
        32: "Older Windows / embedded",
        64: "Linux / Unix / macOS",
        128: "Windows",
        255: "Cisco / Solaris / network device",
    }

    # Ordered most-specific first. Compared as sets.
    COMMON_PATTERNS = [
        ({445, 139, 135, 389}, "Windows Domain Controller"),
        ({22, 80, 443, 3306}, "Linux Web Server (MySQL)"),
        ({22, 80, 443, 5432}, "Linux Web Server (PostgreSQL)"),
        ({445, 139, 135}, "Windows Server"),
        ({22, 80, 443}, "Linux Web Server"),
        ({3389}, "Windows Remote Desktop"),
        ({9200}, "Elasticsearch (likely Linux)"),
        ({5900}, "VNC Server (OS unknown)"),
        ({27017}, "MongoDB (any OS)"),
    ]

    @staticmethod
    def guess_os_from_ports(open_ports: List[int]) -> str:
        open_set = set(open_ports)

        for combo, label in OSFingerprinter.COMMON_PATTERNS:
            if combo == open_set:
                return f"{label} (high confidence)"
        for combo, label in OSFingerprinter.COMMON_PATTERNS:
            if combo.issubset(open_set):
                return f"{label} (probable)"

        if 445 in open_set or 139 in open_set or 135 in open_set:
            return "Likely Windows"
        if 22 in open_set and 3389 not in open_set:
            return "Likely Linux/Unix"
        return "Unknown"

    @staticmethod
    def guess_os_from_ttl(ttl: int) -> str:
        """Round the observed TTL up to the nearest common initial value."""
        if not 1 <= ttl <= 255:
            return "Unknown"
        for initial in sorted(OSFingerprinter.INITIAL_TTLS):
            if ttl <= initial:
                return OSFingerprinter.INITIAL_TTLS[initial]
        return "Unknown"


class RiskAssessment:
    """Turn per-port findings into an overall score and recommendations."""

    RISK_SCORES = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "UNKNOWN": 10}

    @staticmethod
    def calculate_score(open_ports: List[Dict]) -> Dict:
        if not open_ports:
            return {
                "overall_risk": "LOW",
                "score": 0,
                "critical_services": [],
                "recommendations": ["No open ports detected."],
            }

        scores, critical_services, recommendations = [], [], []

        for info in open_ports:
            risk = info.get("risk") or "UNKNOWN"
            service = info.get("service") or "Unknown service"
            port = info.get("port")
            scores.append(RiskAssessment.RISK_SCORES.get(risk, 10))

            if risk == "CRITICAL":
                critical_services.append(f"{service} (:{port})")
                recommendations.append(f"CRITICAL: {service} on port {port} should not be exposed; restrict or disable it")
            elif risk == "HIGH":
                recommendations.append(f"HIGH: {service} on port {port}, consider firewall rules or encrypted alternatives")

            if info.get("cves"):
                recommendations.append(
                    f"Patch {service} on port {port}: matches {', '.join(info['cves'])}"
                )

        # Weight the worst finding heavily so one critical service
        # is not hidden by many harmless ones.
        avg_score = sum(scores) / len(scores)
        score = round(0.7 * max(scores) + 0.3 * avg_score)

        if score >= 85:
            overall = "CRITICAL"
        elif score >= 65:
            overall = "HIGH"
        elif score >= 40:
            overall = "MEDIUM"
        else:
            overall = "LOW"

        if not recommendations:
            recommendations.append("No critical or high-risk services found.")

        return {
            "overall_risk": overall,
            "score": score,
            "critical_services": critical_services,
            "recommendations": recommendations,
        }


if __name__ == "__main__":
    tests = [
        ("SSH-2.0-OpenSSH_7.2p2 Ubuntu 4ubuntu2.8", 22),
        ("SSH-2.0-OpenSSH_7.10", 22),
        ("220 ProFTPD 1.3.5rc3 Server", 21),
        ("HTTP/1.1 200 OK\nServer: Apache/2.4.49 (Unix)", 80),
        ("", 3389),
    ]
    for banner, port in tests:
        r = VulnerabilityDB.identify_service(port, banner)
        print(f"{port:>5} {banner[:45]!r:50} -> {r['service']} {r['version']} "
              f"[{r['risk']}] {r['cves']}")