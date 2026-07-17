#!/usr/bin/env python3
"""
directory_fuzzer.py

Web directory & file brute-forcer. Discovers hidden endpoints, admin panels,
backup files, and misconfigurations on web servers. A staple tool in every
bug bounty hunter's arsenal.

Legal use only. Authorized lab assessments only.
"""

import socket
import sys
import threading
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ------------------- Minimal HTTP request (no external deps) -------------------

def http_get(host: str, port: int, path: str, timeout: float = 3.0) -> int | None:
    """
    Send an HTTP GET request and return the status code.
    Uses raw sockets so there are zero external dependencies.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        # Parse status line: "HTTP/1.1 200 OK"
        first_line = response.split("\r\n")[0]
        status_code = int(first_line.split(" ")[1])
        return status_code
    except Exception:
        return None


# ------------------------------- Wordlist -------------------------------------

# A compact built-in wordlist of common paths (no file dependency needed).
# Full SecLists can be swapped in by pointing to a file.
BUILTIN_WORDLIST = [
    "admin", "login", "wp-admin", "administrator", "backup", "config",
    "dashboard", "api", "v1", "v2", "graphql", "rest", "swagger",
    ".git/config", ".env", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "uploads", "images", "css", "js", "assets",
    "index.php", "index.html", "default.aspx",
]


@dataclass
class Fuzzer:
    target: str
    port: int = 80
    wordlist: list[str] = field(default_factory=lambda: BUILTIN_WORDLIST.copy())
    threads: int = 20
    found: list[tuple[str, int]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _check(self, path: str) -> None:
        code = http_get(self.target, self.port, f"/{path}")
        if code and code in (200, 204, 301, 302, 307, 401, 403):
            with self._lock:
                self.found.append((path, code))

    def run(self) -> list[tuple[str, int]]:
        print(f"[*] Fuzzing http://{self.target}:{self.port}/ with {len(self.wordlist)} paths\n")
        active = []
        for path in self.wordlist:
            t = threading.Thread(target=self._check, args=(path,), daemon=True)
            active.append(t)
            t.start()
            if len(active) >= self.threads:
                for t in active:
                    t.join()
                active.clear()
        for t in active:
            t.join()

        self.found.sort(key=lambda x: x[1])
        return self.found


def main():
    target = input("Enter target hostname: ").strip() or "scanme.nmap.org"
    port_input = input("Port [80]: ").strip()
    port = int(port_input) if port_input else 80
    wordlist_file = input("Wordlist file (blank for built-in 30 paths): ").strip()

    fuzzer = Fuzzer(target=target, port=port)
    if wordlist_file:
        try:
            with open(wordlist_file) as f:
                fuzzer.wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] File not found, using built-in wordlist.")

    results = fuzzer.run()
    if results:
        print("[+] Discovered paths:\n")
        for path, code in results:
            print(f"    {code}  /{path}")
    else:
        print("[-] No discoverable paths found (or server unreachable).")


if __name__ == "__main__":
    main()
