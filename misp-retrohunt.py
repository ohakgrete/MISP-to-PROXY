#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import gzip
import glob
from typing import Dict, List, Set
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# CONFIGURATION
# =========================

# MISP connection
MISP_URL = "https://misp.local"      # Change if needed
MISP_API_KEY = "MuudaMind"          # <-- replace and DO NOT commit real key
MISP_VERIFY_SSL = False             # Set True if you have proper certs

# Log paths
SQUID_LOG = "/var/log/squid/url-only.log"
PIHOLE_LOG = "/var/log/pihole/pihole.log"

DEFAULT_DAYS_BACK = 7
MAX_ATTRIBUTES_PER_EVENT = 500

# =========================
# REGEX
# =========================

URL_RE = re.compile(r'https?://[^\s"]+')
DOMAIN_RE = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

PIHOLE_QUERY_RE = re.compile(
    r'^(?P<mon>\w{3})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+'
    r'.*dnsmasq\[\d+\]:\s*query\[[A-Z]+\]\s+'
    r'(?P<domain>\S+)\s+from\s+(?P<client>\S+)'
)

# =========================
# LOG LOADING WITH ROTATION
# =========================

def load_rotated_logs(base_path: str) -> List[str]:
    """Load .log, .log.1, .log.2.gz automatically."""
    log_dir = os.path.dirname(base_path)
    base_name = os.path.basename(base_path)

    pattern = os.path.join(log_dir, base_name + "*")
    files = sorted(glob.glob(pattern))

    all_lines = []

    for fpath in files:
        try:
            if fpath.endswith(".gz"):
                with gzip.open(fpath, "rt", encoding="utf-8", errors="ignore") as f:
                    all_lines.extend(f.readlines())
            else:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_lines.extend(f.readlines())
        except Exception as e:
            print(f"[!] Failed to read {fpath}: {e}", file=sys.stderr)

    return all_lines

def load_pihole_logs() -> List[str]:
    lines = []

    candidates = [
        "/var/log/pihole/pihole.log",
        "/var/log/pihole/pihole.log.1",
    ]

    # include compressed logs if present
    for num in range(2, 10):
        gz = f"/var/log/pihole/pihole.log.{num}.gz"
        if os.path.exists(gz):
            candidates.append(gz)

    for path in candidates:
        if not os.path.exists(path):
            continue

        try:
            if path.endswith(".gz"):
                import gzip
                with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
                    lines.extend(f.readlines())
            else:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines.extend(f.readlines())
        except Exception as e:
            print(f"[!] Failed to read {path}: {e}")

    return lines


# =========================
# MISP HELPERS
# =========================

def misp_headers():
    return {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

def fetch_iocs_from_misp(days_back: int) -> Dict[str, Set[str]]:
    """Fetch ONLY domains/hostnames and URLs from MISP (last N days)."""
    since_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%d"
    )

    payload = {
        "returnFormat": "json",
        "type": ["domain", "hostname", "url"],
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

    return {"domains": domains, "urls": urls}


def create_misp_event(info: str) -> str:
    event_data = {
        "Event": {
            "info": info,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "distribution": 0,
            "threat_level_id": 2,
            "analysis": 2,
        }
    }
    try:
        resp = requests.post(
            MISP_URL.rstrip("/") + "/events/add",
            headers=misp_headers(),
            json=event_data,
            verify=MISP_VERIFY_SSL
        )
        resp.raise_for_status()
        return str(resp.json()["Event"]["id"])
    except Exception as e:
        print(f"[!] Failed creating MISP event: {e}")
        return ""


def add_attribute(event_id, attr_type, value, category, to_ids, comment) -> bool:
    data = {
        "Attribute": {
            "type": attr_type,
            "category": category,
            "to_ids": to_ids,
            "value": value,
            "comment": comment
        }
    }
    try:
        resp = requests.post(
            MISP_URL.rstrip("/") + f"/attributes/add/{event_id}",
            headers=misp_headers(),
            json=data,
            verify=MISP_VERIFY_SSL
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"[!] Failed adding attribute to event {event_id}: {e}")
        return False


# =========================
# PARSERS
# =========================

def parse_squid_line(line: str):
    stripped = line.strip().strip('"')
    parts = stripped.split(" ", 4)
    if len(parts) < 4:
        return None

    ts_str, ip, user, method = parts[:4]
    payload = parts[4] if len(parts) >= 5 else ""

    try:
        ts_iso = datetime.fromtimestamp(float(ts_str), timezone.utc).isoformat()
    except:
        ts_iso = "unknown"

    return {
        "timestamp": ts_iso,
        "ip": ip,
        "method": method,
        "payload": payload
    }


def parse_pihole_line(line: str):
    m = PIHOLE_QUERY_RE.match(line.strip())
    if not m:
        # DEBUG: Show every DNS query line that the regex fails to parse
        if "query[" in line:
            print("[DEBUG] PIHOLE MISSED:", line.strip())
        return None

    year = datetime.now().year
    try:
        dt = datetime.strptime(
            f"{year} {m.group('mon')} {m.group('day')} "
            f"{m.group('hour')}:{m.group('minute')}:{m.group('second')}",
            "%Y %b %d %H:%M:%S"
        )
        ts_iso = dt.isoformat()
    except:
        ts_iso = "unknown"

    return {
        "timestamp": ts_iso,
        "domain": m.group("domain").lower(),
        "client": m.group("client")
    }

# =========================
# IoC EXTRACTION
# =========================

def extract_squid_indicators(line: str):
    parsed = parse_squid_line(line)
    if not parsed:
        return set(), set(), None

    urls = set()
    domains = set()

    payload = parsed["payload"]
    method = parsed["method"]

    # CONNECT www.evil.com:443
    if method == "CONNECT" and "://" not in payload:
        domains.add(payload.split(":")[0].lower())

    # URLs
    for match in URL_RE.findall(payload):
        urls.add(match)
        try:
            h = urlparse(match).hostname
            if h:
                domains.add(h.lower())
        except:
            pass

    # Plain domains
    for match in DOMAIN_RE.findall(payload):
        domains.add(match.lower())

    return urls, domains, parsed


def extract_pihole_indicators(line: str):
    parsed = parse_pihole_line(line)
    if not parsed:
        return None, None, None

    dom = parsed["domain"]
    return set(), {dom}, parsed


# =========================
# SEARCH
# =========================

def search_logs(iocs, squid_lines, pihole_lines):
    results = {}

    def hit(ioc_key, source, line):
        results.setdefault(ioc_key, {"squid": [], "pihole": []})
        results[ioc_key][source].append(line)

    ioc_domains = {d.lower() for d in iocs["domains"]}
    ioc_urls = {u.lower() for u in iocs["urls"]}

    # ---- Squid ----
    for line in squid_lines:
        urls, domains, parsed = extract_squid_indicators(line)
        if not parsed:
            continue

        for d in domains:
            if d in ioc_domains:
                hit(f"domain:{d}", "squid", line)

        for u in urls:
            if u.lower() in ioc_urls:
                hit(f"url:{u}", "squid", line)

    # ---- Pi-hole ----
    for line in pihole_lines:
        urls, domains, parsed = extract_pihole_indicators(line)
        if not parsed:
            continue

        for d in domains:
            if d in ioc_domains:
                hit(f"domain:{d}", "pihole", line)

    return results


# =========================
# PUSH TO TWO MISP EVENTS
# =========================

def push_results_to_misp(matches, days_back):
    if not matches:
        print("[+] No matches found, nothing to push.")
        return

    # --------------------------
    # Create 2 SEPARATE EVENTS
    # --------------------------
    squid_event = create_misp_event(
        f"Retrohunt Squid URL activity (last {days_back} days)"
    )
    pihole_event = create_misp_event(
        f"Retrohunt Pi-hole DNS activity (last {days_back} days)"
    )

    if not squid_event or not pihole_event:
        print("[!] Cannot continue without both events.")
        return

    squid_count = 0
    pihole_count = 0

    for key, sources in matches.items():
        ioc_type, value = key.split(":", 1)

        # --------------------------
        # SQUID EVENT
        # --------------------------
        if sources["squid"]:
            squid_hits = []
            for ln in sources["squid"]:
                p = parse_squid_line(ln)
                if not p:
                    continue
                squid_hits.append(f"- time={p['timestamp']}, ip={p['ip']}")

            comment = f"source=squid\nIoC={value}\nhits:\n" + "\n".join(squid_hits)

            if add_attribute(
                squid_event,
                "url" if ioc_type == "url" else "domain",
                value,
                "Network activity",
                True,
                comment
            ):
                squid_count += 1

        # --------------------------
        # PI-HOLE EVENT
        # --------------------------
        if sources["pihole"]:
            dns_hits = []
            for ln in sources["pihole"]:
                p = parse_pihole_line(ln)
                if not p:
                    continue
                dns_hits.append(
                    f"- time={p['timestamp']}, client={p['client']}, domain={p['domain']}"
                )

            comment = f"source=pihole\nIoC={value}\nhits:\n" + "\n".join(dns_hits)

            if add_attribute(
                pihole_event,
                "domain",
                 value,
                "Network activity",   # valid MISP category
                True,
                comment
            ):
                pihole_count += 1


    print(f"[+] Added {squid_count} attributes to Squid event {squid_event}")
    print(f"[+] Added {pihole_count} attributes to Pi-hole event {pihole_event}")


# =========================
# MAIN
# =========================

def parse_args():
    p = argparse.ArgumentParser("Retrohunt")
    p.add_argument("--days", type=int, default=DEFAULT_DAYS_BACK)
    return p.parse_args()


def main():
    args = parse_args()

    print(f"[+] Fetching IoCs from last {args.days} days…")
    iocs = fetch_iocs_from_misp(args.days)

    print("[+] Loading rotated Squid logs…")
    squid_lines = load_rotated_logs(SQUID_LOG)

    print("[+] Loading rotated Pi-hole logs…")
    pihole_lines = load_pihole_logs()

    print("[+] Searching logs for IoCs…")
    matches = search_logs(iocs, squid_lines, pihole_lines)

    print("[+] Pushing results into 2 MISP events…")
    push_results_to_misp(matches, args.days)


if __name__ == "__main__":
    main()
