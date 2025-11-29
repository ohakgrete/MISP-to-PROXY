#!/usr/bin/env python3
import os, re, sys, requests
from urllib.parse import urlparse, urlunparse
import idna

# ---- EDIT THESE ----
MISP_BASE = "https://misp.local"  
MISP_API_KEY = "MuudaMindd"  # Please get API key from your MISP istance
VERIFY_SSL = False                    # set True if MISP has valid TLS
OUT_DIR = "/opt/misp-proxy/lists/"
# DOMAIN_FILE = os.path.join(OUT_DIR, "misp_blocked_domains.txt")
URL_REGEX_FILE = os.path.join(OUT_DIR, "misp_blocked_url_regex.txt")
RELOAD_SQUID = True

# --------------------------------------------

if not VERIFY_SSL:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

HEADERS = {"Accept": "application/json", "Authorization": MISP_API_KEY}
URL_LIKE_RX = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

# ------------------ FETCH -------------------

def fetch_urls_only():
    """Fetch only MISP attributes of type=url and return canonical URLs."""
    urls = []

    # Primary JSON endpoint
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

    # Fallback: download endpoint (JSON or text)
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
                    a = item.get("Attribute", item) if isinstance(item, dict) else None
                    if isinstance(a, dict) and (a.get("type") or "").lower() == "url":
                        v = (a.get("value") or "").strip()
                        if v:
                            urls.append(v)
                    elif isinstance(item, str) and URL_LIKE_RX.search(item):
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

# -------------- CANONICALIZATION ------------

def _safe_netloc(p):
    """
    Build a safe netloc without using p.port (which can raise on malformed).
    Handles:
      - [IPv6] or [IPv6]:port
      - host/IPv4 with optional single :port
      - drops bogus multi-colon ports in hostnames
    """
    raw = (p.netloc or "").strip()
    host = (p.hostname or "").lower()
    if not host:
        return ""

    # Bracketed IPv6?
    if raw.startswith("[") and "]" in raw:
        end = raw.index("]")
        inside = raw[1:end].lower()
        after = raw[end+1:]
        m = re.fullmatch(r":(\d+)", after)
        return f"[{inside}]:{m.group(1)}" if m else f"[{inside}]"

    # Host/IPv4: optional single :port
    if ":" in raw:
        left, right = raw.rsplit(":", 1)
        if right.isdigit():
            return f"{host}:{right}"
        return host
    return host

def canonical_url(u: str) -> str:
    s = (u or "").strip().strip('\'"<>')
    if not s.lower().startswith(("http://", "https://")):
        return ""
    try:
        p = urlparse(s)
    except Exception:
        return ""
    if not p.netloc or p.scheme.lower() not in ("http", "https"):
        return ""
    scheme = p.scheme.lower()
    netloc = _safe_netloc(p)
    if not netloc:
        return ""
    path = p.path or "/"
    return urlunparse((scheme, netloc, path, p.params, p.query, p.fragment))

def _to_punycode(host: str) -> str:
    try:
        return idna.encode(host).decode("ascii")
    except Exception:
        return host

# -------- REGEX (Squid POSIX-ERE) ---------

FORBIDDEN_SUBSTR = [
    '(?:', '(?=', '(?!', '(?<', '(?P<',  # PCRE groups/lookarounds
    '\\K', '\\R', '\\X',                 # PCRE escapes as literals
]
RE_BACKREF = re.compile(r'\\[1-9]')                      # \1..\9
RE_HEXUNI  = re.compile(r'(\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\p\{)')

def url_to_regexes(u: str):
    """
    Build POSIX-ERE safe regexes for Squid url_regex:
      - exact:   ^https?://host[:port]/path(?:query)?$
      - prefix:  ^https?://host[:port]/path([?#].*)?$
    We can't use (?: ), so use capturing group ([?#].*)?
    """
    try:
        p = urlparse(u)
    except Exception:
        return []
    host = (p.hostname or "").lower()
    if not host:
        return []

    host = _to_punycode(host)
    # include :port if present and numeric in netloc
    port = ""
    raw = (p.netloc or "")
    if raw.startswith("[") and "]" in raw:
        end = raw.index("]")
        after = raw[end+1:]
        m = re.fullmatch(r":(\d+)", after)
        if m:
            port = ":" + m.group(1)
        # host already is without brackets; re-add brackets for regex host part
        host_expr = r"\[" + re.escape((host if host else "").strip("[]")) + r"\]"
    else:
        # normal netloc
        if ":" in raw:
            _, right = raw.rsplit(":", 1)
            if right.isdigit():
                port = ":" + right
        host_expr = re.escape(host)

    path = p.path if p.path else "/"
    q = ("?" + p.query) if p.query else ""

    scheme_prefix = r"^https?://"
    exact  = scheme_prefix + host_expr + re.escape(port) + re.escape(path + q) + r"$"
    prefix = scheme_prefix + host_expr + re.escape(port) + re.escape(path) + r"([?#].*)?$"
    return [exact, prefix]

def _looks_posix_safe(s: str) -> bool:
    if any(tok in s for tok in FORBIDDEN_SUBSTR):
        return False
    if RE_BACKREF.search(s):
        return False
    if RE_HEXUNI.search(s):
        return False
    if not s or s in ("*", "+", "?") or s.startswith("^*"):
        return False
    return True

def _posix_clean(lines):
    out = []
    for ln in lines:
        if not ln:
            continue
        ln = ln.replace("\r", "")
        ln = "".join(ch for ch in ln if ch.isprintable()).strip()
        if not ln:
            continue
        # normalize legacy artifacts
        ln = ln.replace(r"\://", "://").replace("(?:", "(")
        if _looks_posix_safe(ln):
            out.append(ln)
    return out

# --------------- WRITE & RELOAD ---------------

def write_url_regex_file(urls):
    regs = []
    for u in urls:
        regs.extend(url_to_regexes(u))

    # Dedup preserve order
    seen, ordered = set(), []
    for r in regs:
        if r not in seen:
            seen.add(r)
            ordered.append(r)

    ordered = _posix_clean(ordered)

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(URL_REGEX_FILE, "w", newline="\n") as f:
        f.write("\n".join(ordered) + ("\n" if ordered else ""))

    print(f"Wrote {len(ordered)} URL regexes -> {URL_REGEX_FILE}")

def reload_squid():
    if not RELOAD_SQUID:
        return
    try:
        import subprocess
        # Validate config first
        subprocess.check_call(["squid", "-k", "parse"])
        # Reload if active; else restart
        is_active = (subprocess.call(["systemctl", "is-active", "--quiet", "squid"]) == 0)
        if is_active:
            subprocess.check_call(["systemctl", "reload", "squid"])
            print("Squid parsed OK and reloaded.")
        else:
            subprocess.check_call(["systemctl", "restart", "squid"])
            print("Squid parsed OK and restarted (was inactive).")
    except Exception as e:
        print("Squid parse/reload/restart failed:", e)

# -------------------- MAIN -------------------

def main():
    urls = fetch_urls_only()
    print(f"Fetched {len(urls)} URL attributes")
    write_url_regex_file(urls)
    reload_squid()

if __name__ == "__main__":
    main()
