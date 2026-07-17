# Recon Tool Kit

A collection of lightweight, dependency-free Python tools for network reconnaissance and security assessments. Built for **authorized lab environments, CTFs, and bug bounty hunting** with explicit permission.

> **⚠️ LEGAL USE ONLY**
> These tools are intended solely for authorized security assessments,
> penetration testing engagements with written permission, and personal lab environments.
> Unauthorized scanning of systems you do not own or have explicit permission to test
> is illegal in most jurisdictions. The author assumes no liability for misuse.

---

## Tools

| # | Tool | What It Does | Recon Phase |
|---|------|-------------|-------------|
| 1 | **banner_grabber.py** | Connects to ports and reads service banners → identifies exact software + version for CVE lookup | Service Identification |
| 2 | **threaded_scanner.py** | Multi-threaded TCP port scanner (~100x faster than sequential) — same technique used by Mirai | Port Scanning |
| 3 | **directory_fuzzer.py** | Web directory brute-forcer that discovers hidden endpoints, admin panels, and backup files | Content Discovery |
| 4 | **port_plus_banner.py** | Hybrid tool — threaded port scan + automatic banner grabbing in a single pass | Port + Service |

---

## Quick Start

```bash
git clone https://github.com/<your-username>/recon-tool-kit.git
cd recon-tool-kit
```

All tools are **pure Python 3 with zero external dependencies** — just `socket` and `threading` from the standard library. Run any tool directly:

```bash
python3 banner_grabber.py
python3 threaded_scanner.py
python3 directory_fuzzer.py
python3 port_plus_banner.py
```

---

## Why These Tools Matter for Bug Bounty

1. **Subdomain enumeration** finds your targets.
2. **Port scanning** (threaded_scanner.py) finds what's exposed.
3. **Banner grabbing** (banner_grabber.py) identifies the exact service version → CVE lookup.
4. **Directory fuzzing** (directory_fuzzer.py) finds hidden attack surface.
5. **Combined scanning** (port_plus_banner.py) does it all in one pass.

This pipeline takes you from "I know a domain" to "I have a list of exploitable services."

---

## Example Workflow

```bash
# 1. Find what's alive
python3 threaded_scanner.py --target target.com

# 2. Identify versions on open ports
python3 banner_grabber.py --target target.com --ports 22,80,443

# 3. Discover hidden web paths
python3 directory_fuzzer.py --target target.com --port 80

# 4. Everything in one pass
python3 port_plus_banner.py --target target.com
```

---

## Roadmap

- [ ] Add `--output` flag for JSON/CSV export
- [ ] Add service fingerprinting (match banners to known signatures)
- [ ] Add HTTP response-based banner grabbing (send probe, read response)
- [ ] Add CIDR range scanning support
- [ ] Add colorized terminal output

---

## Resources

- [Nmap — the gold standard](https://nmap.org)
- [SecLists — wordlists for content discovery](https://github.com/danielmiessler/SecLists)
- [CVE Database](https://cve.mitre.org)
- [HackerOne](https://www.hackerone.com) / [Bugcrowd](https://www.bugcrowd.com) — bug bounty platforms

---

**Built for learning, authorized testing, and CTF competitions.**
