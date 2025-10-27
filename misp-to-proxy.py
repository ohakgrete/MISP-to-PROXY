#!/usr/bin/env python3
import os, re, sys, requests
from urllib.parse import urlparse
import idna

# ---- EDIT THESE ----
MISP_BASE = "https://misp.local"  
MISP_API_KEY = "PASTE_YOUR_API_KEY"  # Please get API key from your MISP istance
VERIFY_SSL = False                    # set True if MISP has valid TLS
OUT_DIR = "/opt/misp-proxy/lists"
DOMAIN_FILE = os.path.join(OUT_DIR, "misp_blocked_domains.txt")
URL_REGEX_FILE = os.path.join(OUT_DIR, "misp_blocked_url_regex.txt")
# --------------------

# Silence "InsecureRequestWarning" if VERIFY_SSL is False
if not VERIFY_SSL:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

HEADERS = {"Accept": "application/json", "Authorization": MISP_API_KEY}

def fetch_attributes():
    """
    Fetch attributes from MISP.
    We try the attributes REST search. Result may be:
      - dict with "response"
      - list of dicts
      - list of strings (one IoC per element)
    """
    url = MISP_BASE.rstrip("/") + "/attributes/restSearch/download"
    payload = {"returnFormat": "json", "type": ["domain", "hostname", "url", "domain|ip"]}
    try:
        r = requests.post(url, headers=HEADERS, json=payload, verify=VERIFY_SSL, timeout=90)
        r.raise_for_status()
    except Exception as e:
        print("MISP fetch error:", e)
        return []

    # Try JSON first
    try:
        j = r.json()
    except ValueError:
        # Fallback: treat as newline-delimited text
        text = r.text.strip()
        if not text:
            return []
        # split lines into list of strings
        return [line.strip() for line in text.splitlines() if line.strip()]

    if isinstance(j, dict) and "response" in j:
        return j["response"]
    return j  # could be list of dicts or list of strings

def normalize_domain(d):
    d = (d or "").strip().lower()
    d = re.sub(r'^\*\.', '', d)
    try:
        return idna.encode(d).decode('ascii')
    except Exception:
        return d

def infer_type_and_value(item):
    """
    Normalize different shapes into (typ, val).
    Returns typ in {"domain","url","domain|ip","hostname"} (or inferred) and the value string.
    """
    # Case 1: nested {"Attribute": {...}}
    if isinstance(item, dict) and "Attribute" in item and isinstance(item["Attribute"], dict):
        a = item["Attribute"]
        typ = (a.get("type") or "").lower()
        val = (a.get("value") or "").strip()
        return typ, val

    # Case 2: flat dict with type/value
    if isinstance(item, dict) and ("type" in item or "value" in item):
        typ = (item.get("type") or "").lower()
        val = (item.get("value") or "").strip()
        # If type missing, infer from value
        if not typ:
            typ = infer_type_from_value(val)
        return typ, val

    # Case 3: plain string -> infer
    if isinstance(item, str):
        val = item.strip()
        typ = infer_type_from_value(val)
        return typ, val

    # Unrecognized
    return "", ""

def infer_type_from_value(val):
    if not val:
        return ""
    # quick URL check
    try:
        p = urlparse(val)
        if p.scheme in ("http", "https") and p.netloc:
            return "url"
    except Exception:
        pass
    # domain|ip style
    if "|" in val and re.match(r'^[^|]+\|\d+\.\d+\.\d+\.\d+$', val):
        return "domain|ip"
    # If it looks like a hostname (contains a dot OR punycode prefix)
    if "." in val or val.startswith("xn--"):
        return "domain"  # good enough for blocking purposes
    return "hostname"

def build_lists(raw_items):
    domains = set()
    url_regexes = set()

    for item in raw_items:
        typ, val = infer_type_and_value(item)
        if not val:
            continue
        typ = (typ or "").lower()

        if typ in ("domain", "hostname", "domain|ip"):
            # For domain|ip, take the domain portion if present
            if typ == "domain|ip" and "|" in val:
                domain_part = val.split("|", 1)[0]
                domains.add(normalize_domain(domain_part))
            else:
                domains.add(normalize_domain(val))

        elif typ == "url":
            # Extract host + path and also add host to domain list
            try:
                p = urlparse(val)
                host = p.hostname
                if host:
                    host_n = normalize_domain(host)
                    domains.add(host_n)
                    path = (p.path or "/") + (("?" + p.query) if p.query else "")
                    # Anchor the regex: require the real host and the exact path seen
                    url_regexes.add(r"^https?://" + re.escape(host_n) + re.escape(path))
            except Exception:
                # Fall back: if it doesn't parse, try to treat as domain
                m = re.search(r'https?://([^/\s]+)', val)
                if m:
                    domains.add(normalize_domain(m.group(1)))

    # Convert to Squid suffix format (.domain) except IPs
    squid_domains = set()
    for d in domains:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
            squid_domains.add(d)
        else:
            squid_domains.add("." + d.lstrip("."))

    return sorted(squid_domains), sorted(url_regexes)

def write_files(domains, url_regexes):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(DOMAIN_FILE, "w") as f:
        if domains:
            f.write("\n".join(domains) + "\n")
    with open(URL_REGEX_FILE, "w") as f:
        if url_regexes:
            f.write("\n".join(url_regexes) + "\n")
    print("Wrote:", DOMAIN_FILE, URL_REGEX_FILE)

def reload_squid():
    try:
        import subprocess
        subprocess.check_call(["systemctl", "reload", "squid"])
        print("Squid reloaded.")
    except Exception as e:
        print("Squid reload failed:", e)

def main():
    items = fetch_attributes()
    print("Fetched", len(items), "attributes/items")
    domains, urls = build_lists(items)
    print("Built", len(domains), "domains and", len(urls), "url regexes")
    write_files(domains, urls)
    reload_squid()

if __name__ == "__main__":
    main()
