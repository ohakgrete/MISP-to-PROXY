#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import re
import sys
from typing import Dict, List, Set

import requests

# =========================
# CONFIGURATION
# =========================

# MISP connection
MISP_URL = "https://misp.local"      # Change if needed
MISP_API_KEY = "muudamind"          # Put your MISP API key here
MISP_VERIFY_SSL = False             # Set True if you have proper certs

# Log paths
SQUID_LOG = "/var/log/squid/url-only.log"
PIHOLE_LOG = "/var/log/pihole.log"

# How many days back to pull IoCs from MISP by default
DEFAULT_DAYS_BACK = 7


# =========================
# MISP HELPERS
# =========================


def extract_indicators_from_line(line: str):
    """
    Extract candidate URLs, domains and IPs from a log line.
    We keep this generic so it works for both Squid and Pi-hole logs.
    """
    urls = set()
    domains = set()
    ips = set()

    # URLs
    url_re = re.compile(r'https?://[^\s"]+')
    for match in url_re.findall(line):
        urls.add(match)

        # Also extract host from URL
        try:
            host = urlparse(match).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass

    # IPs
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for match in ip_re.findall(line):
        ips.add(match)

    # Domains / hostnames (very rough, but good enough to narrow candidates)
    # example.com, sub.example.co.uk etc.
    domain_re = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    for match in domain_re.findall(line):
        domains.add(match.lower())

    return urls, domains, ips


def search_logs_for_iocs(
    iocs: Dict[str, Set[str]],
    squid_lines: List[str],
    pihole_lines: List[str]
) -> Dict[str, Dict[str, List[str]]]:
    """
    Faster version: for each line, extract a few candidate indicators,
    then check membership in the IoC sets.
    """

    result: Dict[str, Dict[str, List[str]]] = {}

    def add_hit(key: str, source: str, line: str):
        if key not in result:
            result[key] = {"squid": [], "pihole": []}
        result[key][source].append(line.strip("\n"))

    # Normalised IoC sets
    ioc_domains = {d.lower() for d in iocs["domains"]}
    ioc_ips = set(iocs["ips"])
    ioc_urls = {u.lower() for u in iocs["urls"]}

    # --- Squid ---
    for line in squid_lines:
        urls, domains, ips = extract_indicators_from_line(line)

        for d in domains:
            if d in ioc_domains:
                add_hit(f"domain:{d}", "squid", line)

        for ip in ips:
            if ip in ioc_ips:
                add_hit(f"ip:{ip}", "squid", line)

        for u in urls:
            # exact URL match
            if u.lower() in ioc_urls:
                add_hit(f"url:{u}", "squid", line)

    # --- Pi-hole ---
    for line in pihole_lines:
        urls, domains, ips = extract_indicators_from_line(line)

        for d in domains:
            if d in ioc_domains:
                add_hit(f"domain:{d}", "pihole", line)

        for ip in ips:
            if ip in ioc_ips:
                add_hit(f"ip:{ip}", "pihole", line)

        for u in urls:
            if u.lower() in ioc_urls:
                add_hit(f"url:{u}", "pihole", line)

    return result
# =========================
# LOG PARSING
# =========================

def load_log_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        print(f"[!] Log file not found: {path}", file=sys.stderr)
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception as e:
        print(f"[!] Failed to read {path}: {e}", file=sys.stderr)
        return []


def search_logs_for_iocs(
    iocs: Dict[str, Set[str]],
    squid_lines: List[str],
    pihole_lines: List[str]
) -> Dict[str, Dict[str, List[str]]]:
    """
    Returns:
    {
      "domain:example.com": {
          "squid": [line1, line2, ...],
          "pihole": [line3, ...]
      },
      "ip:1.2.3.4": {...},
      "url:http://evil.com/path": {...}
    }
    """

    result: Dict[str, Dict[str, List[str]]] = {}

    def add_hit(key: str, source: str, line: str):
        if key not in result:
            result[key] = {"squid": [], "pihole": []}
        result[key][source].append(line.strip("\n"))

    # Pre-build simple regex maps to avoid partial-word noise
    domain_patterns = {
        d: re.compile(r"\b" + re.escape(d) + r"\b", re.IGNORECASE)
        for d in iocs["domains"]
    }
    ip_patterns = {
        ip: re.compile(r"\b" + re.escape(ip) + r"\b")
        for ip in iocs["ips"]
    }
    url_patterns = {
        u: re.compile(re.escape(u), re.IGNORECASE)
        for u in iocs["urls"]
    }

    # --- Squid ---
    for line in squid_lines:
        for d, pat in domain_patterns.items():
            if pat.search(line):
                add_hit(f"domain:{d}", "squid", line)
        for ip, pat in ip_patterns.items():
            if pat.search(line):
                add_hit(f"ip:{ip}", "squid", line)
        for u, pat in url_patterns.items():
            if pat.search(line):
                add_hit(f"url:{u}", "squid", line)

    # --- Pi-hole ---
    for line in pihole_lines:
        for d, pat in domain_patterns.items():
            if pat.search(line):
                add_hit(f"domain:{d}", "pihole", line)
        for ip, pat in ip_patterns.items():
            if pat.search(line):
                add_hit(f"ip:{ip}", "pihole", line)
        for u, pat in url_patterns.items():
            if pat.search(line):
                add_hit(f"url:{u}", "pihole", line)

    return result


# =========================
# REPORTING
# =========================

def print_report(
    matches: Dict[str, Dict[str, List[str]]],
    limit_per_ioc: int = 10
) -> None:
    if not matches:
        print("[+] No matches found in Squid or Pi-hole logs.")
        return

    print("\n================ RETROHUNT RESULTS ================\n")
    for ioc_key, sources in sorted(matches.items()):
        squid_hits = sources.get("squid", [])
        pihole_hits = sources.get("pihole", [])

        print(f"IoC: {ioc_key}")
        print(f"  Squid  : {len(squid_hits)} hits")
        print(f"  Pi-hole: {len(pihole_hits)} hits")

        def print_lines(label: str, lines: List[str]):
            if not lines:
                return
            print(f"  --- Sample {label} lines ---")
            for line in lines[:limit_per_ioc]:
                print(f"    {line}")
            if len(lines) > limit_per_ioc:
                print(f"    ... ({len(lines) - limit_per_ioc} more)")

        print_lines("Squid", squid_hits)
        print_lines("Pi-hole", pihole_hits)
        print("")


def write_json_report(matches: Dict[str, Dict[str, List[str]]], out_path: str) -> None:
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(matches, f, indent=2)
        print(f"[+] JSON report written to {out_path}")
    except Exception as e:
        print(f"[!] Failed to write JSON report: {e}", file=sys.stderr)


# =========================
# MAIN
# =========================

def parse_args():
    p = argparse.ArgumentParser(
        description="Retrohunt MISP IoCs in Squid and Pi-hole logs."
    )
    p.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS_BACK,
        help=f"How many days back to fetch IoCs from MISP (default: {DEFAULT_DAYS_BACK})"
    )
    p.add_argument(
        "--squid-log",
        default=SQUID_LOG,
        help=f"Path to Squid access log (default: {SQUID_LOG})"
    )
    p.add_argument(
        "--pihole-log",
        default=PIHOLE_LOG,
        help=f"Path to Pi-hole log (default: {PIHOLE_LOG})"
    )
    p.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write JSON report with all matches"
    )
    p.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max log lines per IoC per source to print to stdout (default: 10)"
    )
    return p.parse_args()


def main():
    args = parse_args()

    print(f"[+] Fetching IoCs from MISP (last {args.days} days)...")
    iocs = fetch_iocs_from_misp(args.days)
    print(
        f"[+] Got {len(iocs['domains'])} domains, "
        f"{len(iocs['ips'])} IPs, {len(iocs['urls'])} URLs from MISP."
    )

    print(f"[+] Loading Squid log from {args.squid_log}")
    squid_lines = load_log_lines(args.squid_log)

    print(f"[+] Loading Pi-hole log from {args.pihole_log}")
    pihole_lines = load_log_lines(args.pihole_log)

    print("[+] Searching logs for IoCs...")
    matches = search_logs_for_iocs(iocs, squid_lines, pihole_lines)

    print_report(matches, limit_per_ioc=args.limit)

    if args.json_out:
        write_json_report(matches, args.json_out)


if __name__ == "__main__":
    main()
