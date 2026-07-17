#!/usr/bin/env python3
"""
threaded_scanner.py

Multi-threaded TCP port scanner. Checks 1-1024 (or custom range) in parallel.
Threading makes this ~100x faster than a sequential scan — same technique
used by botnets like Mirai at internet scale.

Legal use only. Authorized lab assessments only.
"""

import socket
import threading
from dataclasses import dataclass, field


@dataclass
class Scanner:
    target: str
    start_port: int = 1
    end_port: int = 1024
    timeout: float = 0.5
    max_threads: int = 200
    open_ports: list[int] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _scan_port(self, port: int) -> None:
        """Attempt a TCP connection to a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            with self._lock:
                self.open_ports.append(port)
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    def run(self) -> list[int]:
        """Scan the port range using a thread pool."""
        threads: list[threading.Thread] = []
        for port in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self._scan_port, args=(port,), daemon=True)
            threads.append(t)
            t.start()

            # Throttle thread creation to avoid overwhelming the OS
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads.clear()

        for t in threads:
            t.join()

        self.open_ports.sort()
        return self.open_ports


def main():
    target = input("Enter target IP/hostname: ").strip() or "scanme.nmap.org"
    start = input("Start port [1]: ").strip()
    end = input("End port [1024]: ").strip()

    s = int(start) if start else 1
    e = int(end) if end else 1024

    print(f"\n[*] Scanning {target} ports {s}-{e} ...\n")
    scanner = Scanner(target=target, start_port=s, end_port=e)
    open_ports = scanner.run()

    if open_ports:
        print(f"[+] Open ports: {open_ports}")
    else:
        print("[-] No open ports found.")


if __name__ == "__main__":
    main()
