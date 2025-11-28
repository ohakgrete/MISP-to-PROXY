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
MISP_API_KEY = "muudamind"          # <-- replace and DO NOT commit real key
MISP_VERIFY_SSL = False             # Set True if you have proper certs

# Log paths
SQUID_LOG = "/var/log/squid/url-only.log"
PIHOLE_LOG = "/var/log/pihole/pihole.log"

# How many days back to pull IoCs from MISP by default
DEFAULT_DAYS_BACK = 7

# Limit how many attributes we push per event (to avoid insane events)
MAX_ATTRIBUTES_PER_EVENT = 500

# =========================
# REGEX (compiled once)
# =========================

URL_RE = re.compile(r'https?://[^\s"]+')
DOMAIN_RE = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
DEVICE_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# =========================
# MISP HELPERS
# =========================

def misp_headers() -> Dict[str, str]:
    return {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def fetch_iocs_from_misp(days_back: int) -> Dict[str, Set[str]]:
    """
    Fetch ONLY domains/hostnames and URLs from MISP.
    Returns a dict with sets: {"domains": set(), "urls": set(), "ips": set()}
    (ips is kept as an empty set only so other code doesn't break).
    """
    since_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")

    payload = {
        "returnFormat": "json",
        "type": ["domain", "hostname", "url"],  # no ip-src / ip-dst
        "published": True,
        "date_from": since_date,
    }

    url = MISP_URL.rstrip("/") + "/attributes/restSearch"
    try:
        resp = requests.post(
            url,
            headers=misp_headers(),
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=60,
        )
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

    return {
        "domains": domains,
        "urls": urls,
        "ips": set(),  # kept for compatibility, unused
    }


def create_misp_event(info: str) -> str:
    """
    Create a new MISP event and return its event_id (string).
    """
    event_data = {
        "Event": {
            "info": info,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "distribution": 0,       # Your organisation only (adjust if needed)
            "threat_level_id": 2,    # Medium (1=High, 2=Medium, 3=Low, 4=Undefined)
            "analysis": 2,           # Completed
        }
    }

    url = MISP_URL.rstrip("/") + "/events/add"
    try:
        resp = requests.post(
            url,
            headers=misp_headers(),
            json=event_data,
            verify=MISP_VERIFY_SSL,
            timeout=60,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"[!] Failed to create MISP event: {e}", file=sys.stderr)
        return ""

    try:
        event_id = str(resp.json()["Event"]["id"])
    except Exception:
        print("[!] Unexpected MISP response when creating event.", file=sys.stderr)
        return ""

    print(f"[+] Created MISP event with ID {event_id}")
    return event_id


def add_attribute_to_event(
    event_id: str,
    attr_type: str,
    value: str,
    category: str,
    to_ids: bool,
    comment: str,
) -> bool:
    """
    Add a single attribute to a given MISP event.
    attr_type: 'domain', 'url', 'ip-src', 'text', ...
    category: typically 'Network activity' for IoCs
    """
    attr_data = {
        "Attribute": {
            "type": attr_type,
            "category": category,
            "to_ids": to_ids,
            "value": value,
            "comment": comment,
        }
    }

    url = MISP_URL.rstrip("/") + f"/attributes/add/{event_id}"
    try:
        resp = requests.post(
            url,
            headers=misp_headers(),
            json=attr_data,
            verify=MISP_VERIFY_SSL,
            timeout=60,
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"[!] Failed to add attribute to event {event_id}: {e}", file=sys.stderr)
        return False

def push_matches_to_misp(matches: Dict[str, Dict[str, List[str]]]) -> None:
    """
    Create a MISP event and add attributes for each matched IoC + source device info.
    IoCs use correct type/category (domain/url + Network activity).
    """
    if not matches:
        print("[+] No matches to push to MISP.")
        return

    info = f"Retrohunt matches from Squid/Pi-hole ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})"
    event_id = create_misp_event(info)
    if not event_id:
        print("[!] Cannot push matches to MISP (no event_id).")
        return

    attr_count = 0
    # avoid spamming duplicate attributes
    seen_attrs = set()  # (ioc_type, value, source_name, device_info)

    for ioc_key, sources in matches.items():
        # ioc_key is like "domain:example.com" or "url:https://evil.com/..."
        if ":" in ioc_key:
            ioc_type, raw_value = ioc_key.split(":", 1)
        else:
            ioc_type, raw_value = "text", ioc_key

        raw_value = raw_value.strip()

        # Map to real MISP attr type + category + to_ids
        if ioc_type == "domain":
            attr_type = "domain"
            category = "Network activity"
            to_ids = True
        elif ioc_type == "url":
            attr_type = "url"
            category = "Network activity"
            to_ids = True
        else:
            # fallback for anything unexpected
            attr_type = "text"
            category = "External analysis"
            to_ids = False

        for source_name in ("squid", "pihole"):
            lines = sources.get(source_name, [])
            for line in lines:
                if attr_count >= MAX_ATTRIBUTES_PER_EVENT:
                    print(f"[!] Reached MAX_ATTRIBUTES_PER_EVENT ({MAX_ATTRIBUTES_PER_EVENT}), stopping.")
                    return

                # Extract device IPs from the log line (best-effort "source device info")
                device_ips = set(DEVICE_IP_RE.findall(line))
                device_info = ", ".join(sorted(device_ips)) if device_ips else "unknown-device"

                # dedup by (ioc_type, raw_value, source, device_info)
                dedup_key = (attr_type, raw_value, source_name, device_info)
                if dedup_key in seen_attrs:
                    continue
                seen_attrs.add(dedup_key)

                comment = f"source={source_name}, device={device_info} | {line.strip()}"
                if len(comment) > 500:
                    comment = comment[:500] + " ..."

                if add_attribute_to_event(event_id, attr_type, raw_value, category, to_ids, comment):
                    attr_count += 1

    print(f"[+] Pushed {attr_count} IoC attributes into MISP event {event_id}")

# =========================
# INDICATOR EXTRACTION / LOG SEARCH
# =========================

def extract_indicators_from_line(line: str):
    """
    Extract candidate URLs and domains/hostnames from a log line.
    We intentionally ignore IPs here (IPs are only used as device info).
    """
    urls = set()
    domains = set()

    # URLs
    for match in URL_RE.findall(line):
        urls.add(match)

        # Also extract host from URL
        try:
            host = urlparse(match).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass

    # Domains / hostnames (rough, but good enough)
    for match in DOMAIN_RE.findall(line):
        domains.add(match.lower())

    return urls, domains


def search_logs_for_iocs(
    iocs: Dict[str, Set[str]],
    squid_lines: List[str],
    pihole_lines: List[str]
) -> Dict[str, Dict[str, List[str]]]:
    """
    For each line, extract candidate URLs/domains, then check membership in the IoC sets.

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

    # NEW: push matches into a MISP event with source device info
    push_matches_to_misp(matches)


if __name__ == "__main__":
    main()
