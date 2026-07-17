#!/usr/bin/env python3
"""
port_plus_banner.py

Hybrid recon tool: threaded port scan + automatic banner grab on every open port.
Combines the two core techniques — speed (threading) and intel (banners) —
into one pass. Perfect for initial foothold reconnaissance.

Legal use only. Authorized lab assessments only.
"""

import socket
import threading
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    port: int
    state: str          # "open" | "closed"
    banner: str | None  # truncated banner text if we got one


@dataclass
class HybridScanner:
    target: str
    start_port: int = 1
    end_port: int = 1024
    timeout: float = 1.0
    results: list[ScanResult] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # Per-thread throttle
    _MAX_CONCURRENT = 100

    def _scan_and_grab(self, port: int) -> None:
        """Check if port is open and, if so, grab its banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            # Port is open — now try to read the banner
            banner = None
            try:
                raw = sock.recv(1024)
                if raw:
                    banner = raw.decode(errors="ignore").strip()[:80]
            except socket.timeout:
                pass  # service didn't send a banner unprompted

            sock.close()

            with self._lock:
                self.results.append(ScanResult(port=port, state="open", banner=banner))

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # port closed/filtered

    def run(self) -> list[ScanResult]:
        """Scan the full port range with threading + banner grabbing."""
        print(f"[*] Hybrid scan on {self.target} ports {self.start_port}-{self.end_port}\n")
        threads: list[threading.Thread] = []

        for port in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self._scan_and_grab, args=(port,), daemon=True)
            threads.append(t)
            t.start()

            if len(threads) >= self._MAX_CONCURRENT:
                for t in threads:
                    t.join()
                threads.clear()
                print(".", end="", flush=True)

        for t in threads:
            t.join()

        self.results.sort(key=lambda r: r.port)
        return self.results


def main():
    target = input("Enter target: ").strip() or "scanme.nmap.org"
    start = input("Start port [1]: ").strip()
    end = input("End port [1024]: ").strip()
    s = int(start) if start else 1
    e = int(end) if end else 1024

    scanner = HybridScanner(target=target, start_port=s, end_port=e)
    results = scanner.run()

    open_ports = [r for r in results if r.state == "open"]
    print("\n")

    if not open_ports:
        print("[-] No open ports found.")
        return

    print(f"[+] {len(open_ports)} open port(s) found:\n")
    print(f"  {'PORT':>5}  {'BANNER'}")
    print(f"  {'----':>5}  {'------'}")
    for r in open_ports:
        banner_display = r.banner if r.banner else "(no banner — try sending a request)"
        print(f"  {r.port:>5}  {banner_display}")


if __name__ == "__main__":
    main()
