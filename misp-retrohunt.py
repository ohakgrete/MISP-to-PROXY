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
MISP_API_KEY = "changeMe"          # <-- replace and DO NOT commit real key
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

# Pi-hole dnsmasq query line, e.g.:
# Nov 29 19:55:25 dnsmasq[49424]: query[A] api.x.com from 127.0.0.1
PIHOLE_QUERY_RE = re.compile(
    r'^(?P<mon>\w{3})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+'
    r'.*dnsmasq\[\d+\]:\s+query\[[^\]]+\]\s+'
    r'(?P<domain>\S+)\s+from\s+(?P<client>\S+)'
)


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

    return {"domains": domains, "urls": urls, "ips": set()}


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


# =========================
# SQUID PARSING
# =========================

def parse_squid_line(line: str):
    """
    Parse url-only.log lines like:
    "1764357156.840 127.0.0.1 - GET https://api.x.com/1.1/graphql/..."
    Returns dict or None.
    """
    stripped = line.strip().strip('"')
    parts = stripped.split(" ", 4)
    if len(parts) < 4:
        return None

    ts_str = parts[0]         # 1764357156.840
    client_ip = parts[1]      # 127.0.0.1
    user = parts[2]           # username or '-'
    method = parts[3]         # GET / POST / CONNECT / ...
    rest = parts[4] if len(parts) >= 5 else ""

    iso_time = None
    try:
        ts_float = float(ts_str)
        iso_time = datetime.fromtimestamp(ts_float, timezone.utc).isoformat()
    except Exception:
        pass

    return {
        "timestamp_str": ts_str,
        "timestamp_iso": iso_time,
        "client_ip": client_ip,
        "user": user,
        "method": method,
        "payload": rest,
    }



# =========================
# PI-HOLE PARSING
# =========================

def parse_pihole_line(line: str):
    """
    Parse pihole.log dnsmasq query lines like:
    Nov 29 19:55:25 dnsmasq[49424]: query[A] api.x.com from 127.0.0.1
    """
    m = PIHOLE_QUERY_RE.match(line.strip())
    if not m:
        return None

    mon = m.group("mon")
    day = int(m.group("day"))
    hour = int(m.group("hour"))
    minute = int(m.group("minute"))
    second = int(m.group("second"))
    domain = m.group("domain")
    client = m.group("client")

    year = datetime.now().year
    try:
        dt = datetime.strptime(
            f"{year} {mon} {day:02d} {hour:02d}:{minute:02d}:{second:02d}",
            "%Y %b %d %H:%M:%S",
        )
        ts_iso = dt.isoformat()
    except Exception:
        ts_iso = None

    return {
        "timestamp_iso": ts_iso,
        "domain": domain,
        "client": client,
    }

def extract_indicators_from_line(line: str, source: str):
    """
    Extract candidate URLs and domains/hostnames from a log line.

    - For squid: parse url-only line, use the payload, and treat
      CONNECT host:443 as a domain.
    - For pihole: ONLY use dnsmasq *query* lines (no reply/cached),
      parsed via parse_pihole_line().
    """
    urls: Set[str] = set()
    domains: Set[str] = set()

    text = line

    if source == "squid":
        parsed = parse_squid_line(line)
        if parsed:
            text = parsed["payload"]

            # CONNECT host:443 -> treat host as domain
            if parsed["method"] == "CONNECT" and text and "://" not in text:
                host = text.split(":", 1)[0]
                domains.add(host.lower())

    elif source == "pihole":
        # Only count real "query[...]" lines
        parsed = parse_pihole_line(line)
        if not parsed:
            # reply/forwarded/cached lines: ignore completely
            return urls, domains

        dom = parsed["domain"].lower()
        domains.add(dom)
        # we only care about the domain, there are no URLs in DNS
        text = dom

    # URLs (for squid payload; for pihole, text is just the domain)
    for match in URL_RE.findall(text):
        u = match.strip()
        if not u:
            continue
        urls.add(u)
        try:
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass

    # Bare domains / hostnames (for squid payload)
    # For pihole, text is already just the domain, so this is harmless
    for match in DOMAIN_RE.findall(text):
        domains.add(match.lower())

    return urls, domains

# =========================
# SEARCH
# =========================
def search_logs_for_iocs(
    iocs: Dict[str, Set[str]],
    squid_lines: List[str],
    pihole_lines: List[str],
) -> Dict[str, Dict[str, List[str]]]:
    """
    Returns:
    {
      "domain:example.com": {"squid":[...], "pihole":[...}},
      "url:https://evil":  {"squid":[...], "pihole":[...]},
      ...
    }

    - Squid: matches BOTH domain and url IoCs (as before)
    - Pi-hole: matches domain IoCs (no URLs in DNS)
    """

    result: Dict[str, Dict[str, List[str]]] = {}

    def add_hit(key: str, source: str, line: str):
        if key not in result:
            result[key] = {"squid": [], "pihole": []}
        result[key][source].append(line.strip("\n"))

    # Normalised IoC sets
    ioc_domains = {d.lower() for d in iocs["domains"]}
    ioc_urls = {u.lower() for u in iocs["urls"]}

    # --- Squid: domains + URLs ---
    for line in squid_lines:
        urls, domains = extract_indicators_from_line(line, "squid")

        for d in domains:
            if d in ioc_domains:
                add_hit(f"domain:{d}", "squid", line)

        for u in urls:
            if u.lower() in ioc_urls:
                add_hit(f"url:{u}", "squid", line)

    # --- Pi-hole: domains (no URLs in DNS) ---
    for line in pihole_lines:
        urls, domains = extract_indicators_from_line(line, "pihole")

        for d in domains:
            if d in ioc_domains:
                add_hit(f"domain:{d}", "pihole", line)

    return result


# =========================
# PUSH MATCHES TO MISP
# =========================

def push_matches_to_misp(
    matches: Dict[str, Dict[str, List[str]]],
    days_back: int,
) -> None:
    """
    For each IoC:

      - URL IoCs:
          * Aggregate all Squid hits (time + IP)
          * ONE attribute: type=url, category=Network activity, source=squid

      - Domain IoCs:
          * Aggregate all Squid hits (time + IP)
            -> ONE attribute: type=domain, category=Network activity, source=squid
          * Aggregate all Pi-hole query hits (time + client)
            -> ONE attribute: type=domain, category=DNS query, source=pihole

    This gives you all activity with timestamps & IPs/clients, without
    hitting MISP duplicate-attribute 403s.
    """
    if not matches:
        print("[+] No Squid or Pi-hole matches to push to MISP.")
        return

    info = (
        f"Retrohunt matches from Squid/Pi-hole "
        f"(last {days_back} days IoCs, {datetime.now(timezone.utc).strftime('%Y-%m-%d')})"
    )
    event_id = create_misp_event(info)
    if not event_id:
        print("[!] Cannot push matches to MISP (no event_id).")
        return

    attr_count = 0

    for ioc_key, sources in matches.items():
        if ":" in ioc_key:
            ioc_type, raw_value = ioc_key.split(":", 1)
        else:
            ioc_type, raw_value = "text", ioc_key
        raw_value = raw_value.strip()

        # ---------- URL IoCs -> only Squid ----------
        if ioc_type == "url":
            squid_hits = []
            for line in sources.get("squid", []):
                parsed = parse_squid_line(line)
                if not parsed:
                    continue
                ts = parsed["timestamp_iso"] or "unknown-time"
                ip = parsed["client_ip"] or "unknown-ip"
                squid_hits.append((ts, ip))

            if squid_hits:
                if attr_count >= MAX_ATTRIBUTES_PER_EVENT:
                    print(
                        f"[!] Reached MAX_ATTRIBUTES_PER_EVENT "
                        f"({MAX_ATTRIBUTES_PER_EVENT}), stopping."
                    )
                    return

                comment_lines = [
                    f"source=squid, IoC={raw_value}",
                    "hits:",
                ]
                for ts, ip in squid_hits:
                    comment_lines.append(f"- time={ts}, ip={ip}")
                comment = "\n".join(comment_lines)
                if len(comment) > 5000:
                    comment = comment[:5000] + "\n... (truncated)"

                if add_attribute_to_event(
                    event_id,
                    "url",
                    raw_value,
                    "Network activity",
                    True,
                    comment,
                ):
                    attr_count += 1

        # ---------- Domain IoCs -> Squid + Pi-hole ----------
        elif ioc_type == "domain":
            # --- Squid side ---
            squid_hits = []
            for line in sources.get("squid", []):
                parsed = parse_squid_line(line)
                if not parsed:
                    continue
                ts = parsed["timestamp_iso"] or "unknown-time"
                ip = parsed["client_ip"] or "unknown-ip"
                squid_hits.append((ts, ip))

            if squid_hits:
                if attr_count >= MAX_ATTRIBUTES_PER_EVENT:
                    print(
                        f"[!] Reached MAX_ATTRIBUTES_PER_EVENT "
                        f"({MAX_ATTRIBUTES_PER_EVENT}), stopping."
                    )
                    return

                comment_lines = [
                    f"source=squid, IoC={raw_value}",
                    "hits:",
                ]
                for ts, ip in squid_hits:
                    comment_lines.append(f"- time={ts}, ip={ip}")
                comment = "\n".join(comment_lines)
                if len(comment) > 5000:
                    comment = comment[:5000] + "\n... (truncated)"

                if add_attribute_to_event(
                    event_id,
                    "domain",
                    raw_value,
                    "Network activity",
                    True,
                    comment,
                ):
                    attr_count += 1

            # --- Pi-hole side (DNS queries only) ---
            pihole_hits = []
            for line in sources.get("pihole", []):
                parsed = parse_pihole_line(line)
                if not parsed:
                    continue
                ts = parsed["timestamp_iso"] or "unknown-time"
                client = parsed["client"]
                dom = parsed["domain"].lower()
                pihole_hits.append((ts, client, dom))

            if pihole_hits:
                if attr_count >= MAX_ATTRIBUTES_PER_EVENT:
                    print(
                        f"[!] Reached MAX_ATTRIBUTES_PER_EVENT "
                        f"({MAX_ATTRIBUTES_PER_EVENT}), stopping."
                    )
                    return

                comment_lines = [
                    f"source=pihole, IoC={raw_value}",
                    "hits:",
                ]
                for ts, client, dom in pihole_hits:
                    comment_lines.append(
                        f"- time={ts}, client={client}, domain={dom}"
                    )
                comment = "\n".join(comment_lines)
                if len(comment) > 5000:
                    comment = comment[:5000] + "\n... (truncated)"

                # category=DNS query to avoid duplicate (type+value+category) with Squid attr
                if add_attribute_to_event(
                    event_id,
                    "domain",
                    raw_value,
                    "DNS query",
                    True,
                    comment,
                ):
                    attr_count += 1

        # other IoC types ignored for now

    print(f"[+] Pushed {attr_count} IoC attributes into MISP event {event_id}")

# =========================
# LOG PARSING / REPORTING
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


def print_report(matches: Dict[str, Dict[str, List[str]]], limit_per_ioc: int = 10) -> None:
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

    push_matches_to_misp(matches, args.days)


if __name__ == "__main__":
    main()
