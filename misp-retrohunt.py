#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from typing import Dict, List, Set
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import urllib3

# Disable HTTPS warnings if using verify=False for local/self-signed MISP
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# CONFIGURATION
# =========================

# MISP connection
MISP_URL = "https://misp.local"      # Change if needed
MISP_API_KEY = "muudamind"          # Put your MISP API key here
MISP_VERIFY_SSL = False             # Set True if you have proper certs

# Log paths
SQUID_LOG = "/var/log/squid/url-only.log"
PIHOLE_LOG = "/var/log/pihole/pihole.log"

# How many days back to pull IoCs from MISP by default
DEFAULT_DAYS_BACK = 7


# =========================
# MISP HELPERS
# =========================

def fetch_iocs_from_misp(days_back: int) -> Dict[str, Set[str]]:
    """
    Fetch ONLY domains/hostnames and URLs from MISP.
    Returns a dict with sets: {"domains": set(), "urls": set(), "ips": set()}
    (ips is kept as an empty set only so other code doesn't break).
    """
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    since_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")

    payload = {
        "returnFormat": "json",
        "type": ["domain", "hostname", "url"],  # no ip-src / ip-dst
        "published": True,
        "date_from": since_date,
    }

    url = MISP_URL.rstrip("/") + "/attributes/restSearch"
    try:
        resp = requests.post(url, headers=headers, json=payload,
                             verify=MISP_VERIFY_SSL, timeout=60)
        resp.raise_for_status()
    except Exception as e:
        print(f"[!] Error talking to MISP: {e}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    attributes = data.get("response", {}).get("Attribute", [])
    domains: Set[str] = set()
    urls: Set[str] = set()

    for attr in attributes:
        atype = attr.get("type")
        value = attr.get("value", "").strip()
        if not value:
            continue

        if atype in ("domain", "hostname"):
            domains.add(value.lower())
        elif atype == "url":
            urls.add(value)

    # ips kept for compatibility, but always empty
    return {
        "domains": domains,
        "urls": urls,
        "ips": set(),
    }


# =========================
# INDICATOR EXTRACTION / LOG SEARCH
# =========================

def extract_indicators_from_line(line: str):
    """
    Extract candidate URLs and domains/hostnames from a log line.
    We intentionally ignore IPs here.
    """
    urls = set()
    domains = set()

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

    # Domains / hostnames (rough, but good enough)
    # example.com, sub.example.co.uk etc.
    domain_re = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    for match in domain_re.findall(line):
        domains.add(match.lower())

    return urls, domains


def search_logs_for_iocs(
    iocs: Dict[str, Set[str]],
    squid_lines: List[str],
    pihole_lines: List[str]
) -> Dict[str, Dict[str, List[str]]]:
    """
    Faster version: for each line, extract candidate URLs/domains,
    then check membership in the IoC sets.

    Returns:
    {
      "domain:example.com": {
          "squid": [line1, line2, ...],
          "pihole": [line3, ...]
      },
      "url:http://evil.com/path": {...}
    }
    """

    result: Dict[str, Dict[str, List[str]]] = {}

    def add_hit(key: str, source: str, line: str):
        if key not in result:
            result[key] = {"squid": [], "pihole": []}
        result[key][source].append(line.strip("\n"))

    # Normalised IoC sets
    ioc_domains = {d.lower() for d in iocs["domains"]}
    ioc_urls = {u.lower() for u in iocs["urls"]}

    # --- Squid ---
    for line in squid_lines:
        urls, domains = extract_indicators_from_line(line)

        for d in domains:
            if d in ioc_domains:
                add_hit(f"domain:{d}", "squid", line)

        for u in urls:
            if u.lower() in ioc_urls:
                add_hit(f"url:{u}", "squid", line)

    # --- Pi-hole ---
    for line in pihole_lines:
        urls, domains = extract_indicators_from_line(line)

        for d in domains:
            if d in ioc_domains:
                add_hit(f"domain:{d}", "pihole", line)

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
        f"[+] Got {len(iocs['domains'])} domains/hostnames, "
        f"{len(iocs['urls'])} URLs from MISP."
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
    
