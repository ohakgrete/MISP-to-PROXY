#!/usr/bin/env python3
import os, re, sys, requests
from urllib.parse import urlparse, urlunparse
import idna

# ---- EDIT THESE ----
MISP_BASE = "https://misp.local"  
MISP_API_KEY = "PASTE_YOUR_API_KEY"  # Please get API key from your MISP istance
VERIFY_SSL = False                    # set True if MISP has valid TLS
OUT_DIR = "/opt/misp-proxy/lists"
DOMAIN_FILE = os.path.join(OUT_DIR, "misp_blocked_domains.txt")
URL_REGEX_FILE = os.path.join(OUT_DIR, "misp_blocked_url_regex.txt")
RELOAD_SQUID = True
# --------------------

if not VERIFY_SSL:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

HEADERS = {"Accept": "application/json", "Authorization": MISP_API_KEY}
URL_LIKE_RX = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IS_IPV6_LIKE = re.compile(r'^[0-9A-Fa-f:]+$')

# ----------------------------------------------------------------------

def fetch_urls_only():
    """Fetch only attributes of type=url from MISP."""
    urls = []

    try:
        j = requests.post(
            MISP_BASE.rstrip("/") + "/attributes/restSearch",
            headers=HEADERS,
            json={"returnFormat": "json", "type": "url"},
            verify=VERIFY_SSL, timeout=90
        ).json()
        resp = j.get("response", {})
        attr_list = []
        if isinstance(resp, dict) and "Attribute" in resp:
            attr_list = resp["Attribute"]
        elif isinstance(resp, list):
            for it in resp:
                if isinstance(it, dict) and "Attribute" in it:
                    attr_list.append(it["Attribute"])
                elif isinstance(it, dict):
                    attr_list.append(it)
        elif isinstance(j, dict) and "Attribute" in j:
            attr_list = j["Attribute"]
        for a in attr_list:
            if isinstance(a, dict) and (a.get("type") or "").lower() == "url":
                v = (a.get("value") or "").strip()
                if v:
                    urls.append(v)
    except Exception:
        pass

    # Fallback: download endpoint
    if not urls:
        r = requests.post(
            MISP_BASE.rstrip("/") + "/attributes/restSearch/download",
            headers=HEADERS,
            json={"returnFormat": "json", "type": ["url"]},
            verify=VERIFY_SSL, timeout=90
        )
        try:
            data = r.json()
            data = data.get("response", data)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "Attribute" in item:
                        a = item["Attribute"]
                        if (a.get("type") or "").lower() == "url":
                            v = (a.get("value") or "").strip()
                            if v:
                                urls.append(v)
                    elif isinstance(item, dict):
                        if (item.get("type") or "").lower() == "url":
                            v = (item.get("value") or "").strip()
                            if v:
                                urls.append(v)
                    elif isinstance(item, str):
                        if URL_LIKE_RX.search(item):
                            urls.append(item.strip())
        except ValueError:
            for line in (r.text or "").splitlines():
                line = line.strip()
                if line and URL_LIKE_RX.search(line):
                    urls.append(line)

    # Canonicalize & dedup
    out, seen = [], set()
    for u in urls:
        cu = canonical_url(u)
        if cu and cu not in seen:
            seen.add(cu)
            out.append(cu)
    return out

# ----------------------------------------------------------------------

def _safe_netloc(p):
    """
    Build a safe netloc without ever reading p.port (which can raise).
    Handles:
      - bracketed IPv6: [2001:db8::1] or [2001:db8::1]:8443
      - hostnames/IPv4 with optional single :port
      - malformed cases like host:4444:4444 -> ignore the bogus port
    """
    raw = p.netloc or ""
    host = (p.hostname or "").lower()
    if not host:
        return ""

    raw = raw.strip()

    # Bracketed IPv6 present in raw?
    if raw.startswith("[") and "]" in raw:
        end = raw.index("]")
        inside = raw[1:end].lower()
        after = raw[end+1:]  # maybe ":port" or empty
        m = re.fullmatch(r":(\d+)", after)
        if m:
            return f"[{inside}]:{m.group(1)}"
        return f"[{inside}]"

    # Not bracketed: hostname or IPv4, maybe with :port
    # Use rsplit once; accept only trailing numeric port. If not numeric (e.g. host:4444:4444), drop port.
    if ":" in raw:
        left, right = raw.rsplit(":", 1)
        if right.isdigit():
            # use canonical host (from p.hostname) to avoid mixed case or extra colons in 'left'
            return f"{host}:{right}"
        # malformed (multiple colons or non-numeric), ignore claimed port
        return host

    return host

def canonical_url(u: str) -> str:
    """Lowercase scheme/host, ensure path, and build netloc safely (no p.port)."""
    s = (u or "").strip().strip('\'"<>')
    if not s.lower().startswith(("http://", "https://")):
        return ""

    # First parse attempt
    try:
        p = urlparse(s)
    except Exception:
        return ""

    # If missing netloc or hostname, bail
    if not p.netloc or not (p.scheme and p.scheme.lower() in ("http", "https")):
        return ""

    scheme = p.scheme.lower()
    netloc = _safe_netloc(p)
    if not netloc:
        return ""

    path = p.path or "/"
    return urlunparse((scheme, netloc, path, p.params, p.query, p.fragment))

# ----------------------------------------------------------------------

def url_to_regexes(u: str):
    """Return exact + prefix regexes for one canonicalized URL."""
    if not u:
        return []
    try:
        p = urlparse(u)
    except Exception:
        return []
    host = (p.hostname or "").lower()
    if not host:
        return []
    path = p.path if p.path else "/"
    q = ("?" + p.query) if p.query else ""
    exact = r"^https?://" + re.escape(host) + re.escape(path + q) + r"$"
    prefix = r"^https?://" + re.escape(host) + re.escape(path) + r"(?:[?#].*)?$"
    return [exact, prefix]

# ----------------------------------------------------------------------

def write_url_regex_file(urls):
    bad = 0
    regexes = []
    for u in urls:
        rs = url_to_regexes(u)
        if rs:
            regexes.extend(rs)
        else:
            bad += 1

    # Deduplicate
    out, seen = [], set()
    for r in regexes:
        if r not in seen:
            seen.add(r)
            out.append(r)

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(URL_REGEX_FILE, "w") as f:
        f.write("\n".join(out) + ("\n" if out else ""))

    print(f"Wrote {len(out)} URL regexes -> {URL_REGEX_FILE}")
    if bad:
        print(f"Skipped {bad} malformed or unsupported URLs.")

# ----------------------------------------------------------------------

def reload_squid():
    global RELOAD_SQUID
    if not RELOAD_SQUID:
        return
    try:
        import subprocess
        subprocess.check_call(["systemctl", "reload", "squid"])
        print("Squid reloaded.")
    except Exception as e:
        print("Squid reload failed:", e)

# ----------------------------------------------------------------------

def main():
    urls = fetch_urls_only()
    print(f"Fetched {len(urls)} URL attributes")
    write_url_regex_file(urls)
    reload_squid()

if __name__ == "__main__":
    main()
