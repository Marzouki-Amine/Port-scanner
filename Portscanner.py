import re
import socket
import ssl
import threading
from typing import Dict, List, Optional

from Fingerprint import VulnerabilityDB, OSFingerprinter, RiskAssessment


RISK_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}


class PortScanner:
    """TCP connect scanner with banner grabbing and service fingerprinting."""

    # Common services and their default ports
    BANNER_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
    }

    HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
    TLS_PORTS = {443, 8443}

    def __init__(self, timeout: float = 2.0, verbose: bool = False):
        """
        Args:
            timeout: Socket timeout in seconds
            verbose: Print each port result as it is scanned
        """
        self.timeout = timeout
        self.verbose = verbose
        self.results: List[Dict] = []
        self._lock = threading.Lock()  # scan_port is safe to call from threads

    def _log(self, message: str):
        if self.verbose:
            with self._lock:
                print(message)

    def scan_port(self, host: str, port: int) -> Dict:
        """Scan a single port and fingerprint whatever is listening."""
        result = {
            "port": port,
            "status": "closed",
            "service": self.BANNER_PORTS.get(port),
            "version": None,
            "banner": None,
            "error": None,
            "risk": "UNKNOWN",
            "cves": [],
            "confidence": 0.0,
        }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((host, port))
            result["status"] = "open"

            banner = self._grab_banner(sock, port, host)
            result["banner"] = banner

            fp = VulnerabilityDB.identify_service(port, banner)
            result["service"] = fp["service"] or result["service"]
            result["version"] = fp.get("version")
            result["risk"] = fp["risk"]
            result["cves"] = fp["cves"]
            result["confidence"] = fp["confidence"]

            line = (f"[+] {host}:{port} OPEN | {result['service']} "
                    f"({result['risk']}) {RISK_ICONS.get(result['risk'], '')}")
            if banner:
                line += f" | {self._display_banner(banner)[:40]}"
            self._log(line)

        except socket.timeout:
            result["status"] = "filtered"
            result["error"] = "timeout"
            self._log(f"[-] {host}:{port} FILTERED (timeout)")

        except ConnectionRefusedError:
            self._log(f"[-] {host}:{port} CLOSED (refused)")

        except socket.gaierror as e:
            result["error"] = f"DNS error: {e}"
            self._log(f"[!] DNS error for {host}: {e}")

        except OSError as e:
            result["status"] = "filtered"
            result["error"] = str(e)
            self._log(f"[!] {host}:{port} socket error: {e}")

        finally:
            sock.close()

        with self._lock:
            self.results.append(result)
        return result

    # ------------------------------------------------------------------ banners

    @staticmethod
    def _clean(data: bytes) -> str:
        text = data.decode("utf-8", errors="ignore")
        # drop control characters but keep newlines
        return re.sub(r"[^\x20-\x7e\r\n]", "", text).replace("\r", "").strip()

    @staticmethod
    def _recv_headers(sock, limit: int = 8192) -> bytes:
        """Read until the end of HTTP headers, the limit, or a timeout."""
        data = b""
        try:
            while len(data) < limit and b"\r\n\r\n" not in data:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        return data

    def _http_probe(self, sock, host: str) -> Optional[str]:
        request = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: Not-Just-Nmap\r\nConnection: close\r\n\r\n")
        sock.sendall(request.encode())
        data = self._recv_headers(sock)
        return self._clean(data) or None

    def _grab_banner(self, sock: socket.socket, port: int, host: str) -> Optional[str]:
        """
        Get banner data from an open port.

        HTTP/HTTPS return the full header block (the 'Server:' header is
        what the fingerprinter needs). Other services return the first line.
        """
        try:
            sock.settimeout(1.0)

            if port in self.HTTP_PORTS:
                return self._http_probe(sock, host)

            if port in self.TLS_PORTS:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # we are fingerprinting, not trusting
                with context.wrap_socket(sock) as tls:
                    return self._http_probe(tls, host)

            data = sock.recv(1024)
            cleaned = self._clean(data)
            return cleaned.split("\n")[0] if cleaned else None

        except (socket.timeout, ssl.SSLError, OSError):
            return None

    @staticmethod
    def _display_banner(banner: str) -> str:
        """Short one-line form for reports (first line, plus Server header)."""
        lines = banner.split("\n")
        shown = lines[0]
        for line in lines[1:]:
            if line.lower().startswith("server:"):
                shown += f" | {line.strip()}"
                break
        return shown

    # ------------------------------------------------------------------ helpers

    def scan_range(self, host: str, start_port: int, end_port: int) -> List[Dict]:
        """Sequentially scan a port range (main.py uses threads instead)."""
        self.results = []
        print(f"\n[*] Starting scan on {host}")
        print(f"[*] Port range: {start_port}-{end_port}")
        print(f"[*] Timeout: {self.timeout}s\n")
        for port in range(start_port, end_port + 1):
            self.scan_port(host, port)
        self.results.sort(key=lambda r: r["port"])
        return self.results

    def get_open_ports(self) -> List[Dict]:
        return [r for r in self.results if r["status"] == "open"]

    def print_summary(self):
        """Print the security assessment report."""
        open_ports = sorted(self.get_open_ports(), key=lambda r: r["port"])
        filtered = sum(1 for r in self.results if r["status"] == "filtered")

        print("\n" + "=" * 70)
        print("SECURITY ASSESSMENT REPORT")
        print("=" * 70)

        if not self.results:
            print("No ports scanned.")
            return

        print(f"\nTotal ports scanned: {len(self.results)}")
        print(f"Open ports found:    {len(open_ports)}")
        print(f"Filtered/timed out:  {filtered}")

        if not open_ports:
            print("\nNo open ports found. Note: filtered ports may still hide "
                  "services behind a firewall.")
            print("\n" + "=" * 70 + "\n")
            return

        print("\n" + "─" * 70)
        print("OPEN SERVICES (with risk assessment):")
        print("─" * 70)

        for r in open_ports:
            service = r["service"] or "Unknown"
            if r.get("version"):
                service += f" {r['version']}"
            risk = r["risk"]
            banner = self._display_banner(r["banner"]) if r["banner"] else "(no banner)"

            print(f"\n  {RISK_ICONS.get(risk, '⚪')} [{r['port']:5d}] {service:<24} "
                  f"[{risk:<8}] ({r['confidence'] * 100:.0f}% confidence)")
            print(f"           Banner: {banner[:70]}")
            if r["cves"]:
                print(f"           Known CVEs: {', '.join(r['cves'])}")

        print("\n" + "─" * 70)
        print("RISK ASSESSMENT SUMMARY:")
        print("─" * 70)

        assessment = RiskAssessment.calculate_score(open_ports)
        overall = assessment["overall_risk"]
        print(f"\n  Overall Risk Level: {RISK_ICONS.get(overall, '⚪')} {overall} "
              f"(Score: {assessment['score']}/100)")

        if assessment["critical_services"]:
            print("\n  CRITICAL services detected:")
            for s in assessment["critical_services"]:
                print(f"     - {s}")

        print("\n  Recommendations:")
        for i, rec in enumerate(assessment["recommendations"], 1):
            print(f"     {i}. {rec}")

        print("\n" + "─" * 70)
        print("OS FINGERPRINTING (heuristic, based on open ports):")
        print("─" * 70)
        print(f"\n  Estimated OS: {OSFingerprinter.guess_os_from_ports([r['port'] for r in open_ports])}")

        print("\n" + "=" * 70 + "\n")