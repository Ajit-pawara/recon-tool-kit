#!/usr/bin/env python3
"""
banner_grabber.py

Connects to a target host on specified ports and reads the service banner.
The banner reveals the exact software and version running — critical intel
for CVE lookup and vulnerability assessment.

Legal use only. Authorized lab assessments only.
"""

import socket


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """
    Attempt to read a banner from the given IP and port.

    Args:
        ip:      Target IP address or hostname.
        port:    Target port number.
        timeout: Seconds to wait for a response.

    Returns:
        The banner string (truncated to 60 chars for display), or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def main():
    target = input("Enter target IP/hostname: ").strip() or "scanme.nmap.org"
    ports_input = input("Enter ports (comma-separated, default 22,80,21): ").strip()
    ports = [int(p.strip()) for p in ports_input.split(",")] if ports_input else [22, 80, 21]

    print(f"\n[*] Grabbing banners from {target} ...\n")
    for port in ports:
        banner = grab_banner(target, port)
        if banner:
            print(f"  [+] Port {port:>5}  =>  {banner[:60]}")
        else:
            print(f"  [-] Port {port:>5}  =>  No banner (closed/filtered/silent)")


if __name__ == "__main__":
    main()
