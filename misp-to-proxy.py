#!/usr/bin/env python3
import os
import re
import sys
import socket
import requests
from urllib.parse import urlparse, urlunparse

# ---- EDIT THESE ----
MISP_BASE = "https://misp.local"
MISP_API_KEY = "muudamind"  # Please get API key from your MISP instance
VERIFY_SSL = False

OUT_DIR = "/opt/misp-proxy/lists/"
URL_REGEX_FILE = os.path.join(OUT_DIR, "misp_blocked_url_regex.txt")

RELOAD_SQUID = True

# ==========================================================
# AUTO WHITELIST HOSTS (MISP + LOCAL)
# ==========================================================

WL_HOSTS = set()

try:
    misp_host = urlparse(MISP_BASE).hostname
    if misp_host:
        WL_HOSTS.add(misp_host.lower())

        # Resolve misp.local → include all mapped IPs
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(misp_host, None, fam)
                for (_, _, _, _, sockaddr) in infos:
                    WL_HOSTS.add(sockaddr[0])
            except Exception:
                pass
except Exception:
    pass

# Always whitelist localhost
WL_HOSTS.update({"127.0.0.1", "::1", "localhost"})

print("[INFO] Whitelist hosts:", WL_HOSTS)

# ==========================================================
# NETWORK SETTINGS
# ==========================================================

if not VERIFY_SSL:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

HEADERS = {"Accept": "application/json", "Authorization": MISP_API_KEY}
URL_LIKE_RX = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

# ==========================================================
# WHITELIST LOGIC
# ==========================================================

def is_whitelisted(url: str) -> bool:
    """Return True if URL belongs to MISP or local hostname."""
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if host in WL_HOSTS:
            return True

        # Direct calls back to the MISP instance itself
        if url.startswith(MISP_BASE.rstrip("/") + "/"):
            return True

    except Exception:
        pass

    return False

# ==========================================================
# CANONICALIZATION
# ==========================================================

def _safe_netloc(p):
    raw = (p.netloc or "")
    host = (p.hostname or "").lower()

    if not host:
        return ""

    # IPv6
    if raw.startswith("[") and "]" in raw:
        inside = raw[1:raw.index("]")].lower()
        after = raw[raw.index("]") + 1 :]
        if after.startswith(":") and after[1:].isdigit():
            return f"[{inside}]:{after[1:]}"
        return f"[{inside}]"

    # IPv4 / hostname with optional :port
    if ":" in raw:
        _, right = raw.rsplit(":", 1)
        if right.isdigit():
            return f"{host}:{right}"

    return host

def canonical_url(u: str) -> str:
    """
    Normalize URL into a consistent form:
      - lowercased scheme/host
      - ensure path at least '/'
    """
    s = (u or "").strip().strip('"\'<>')
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

# ==========================================================
# WARNINGLIST FETCHING  (EXACT URL WHITELIST ONLY)
# ==========================================================

def fetch_warninglist_url_whitelist() -> set:
    """
    Fetch enabled warninglists from MISP and return a set of
    *canonical* URLs that should be WHITELISTED for the proxy.

    IMPORTANT:
      - We only keep entries that look like full URLs (http/https).
      - Plain domains like "neti.ee" are IGNORED here (they do NOT
        affect Squid at all).
    """
    wl_urls = set()

    print("[INFO] Fetching warninglists from MISP...")

    try:
        r = requests.get(
            MISP_BASE.rstrip("/") + "/warninglists/index.json",
            headers=HEADERS,
            verify=VERIFY_SSL,
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        wlists = data.get("Warninglists", [])
    except Exception as e:
        print("[WARN] Could not fetch warninglists:", e)
        return wl_urls

    enabled_ids = []
    for item in wlists:
        w = item.get("Warninglist", {})
        enabled_val = w.get("enabled")
        if enabled_val is True or str(enabled_val).lower() == "true":
            wid = w.get("id")
            if wid:
                enabled_ids.append(wid)

    print(f"[INFO] Warninglists: {len(enabled_ids)} enabled")

    for wid in enabled_ids:
        try:
            wr = requests.get(
                MISP_BASE.rstrip("/") + f"/warninglists/view/{wid}.json",
                headers=HEADERS,
                verify=VERIFY_SSL,
                timeout=60,
            )
            wr.raise_for_status()
            wdata = wr.json()
        except Exception as e:
            print(f"[WARN] Failed to fetch warninglist {wid}: {e}")
            continue

        wobj = wdata.get("Warninglist", {})
        entries = wobj.get("WarninglistEntry", []) or []

        for entry in entries:
            raw_val = entry.get("value", "")
            if not raw_val:
                continue

            val = raw_val.strip()
            lv = val.lower()

            # *** ONLY keep full URLs in the whitelist ***
            if not (lv.startswith("http://") or lv.startswith("https://")):
                # This is likely a bare domain (e.g. neti.ee); ignore for proxy
                continue

            cu = canonical_url(lv)
            if not cu:
                continue

            if is_whitelisted(cu):
                # e.g. URLs back to MISP itself
                print("[WL-local] Skipping self/localhost URL from warninglist:", cu)
                continue

            wl_urls.add(cu.lower())

    print(f"[INFO] Warninglist URL whitelist contains {len(wl_urls)} URLs")
    return wl_urls

# ==========================================================
# FETCH MISP URLs (with warninglist + whitelist)
# ==========================================================

def fetch_urls_only(wl_url_whitelist: set):
    """
    Fetch URL attributes from MISP and apply:
      - canonicalization
      - local whitelist (MISP + localhost)
      - WARNINGLIST FILTER:
          * skip if canonical URL is an exact match in wl_url_whitelist

    Domain-only warninglist entries have NO effect here.
    """
    urls = []

    # Primary REST endpoint
    try:
        j = requests.post(
            MISP_BASE.rstrip("/") + "/attributes/restSearch",
            headers=HEADERS,
            json={"returnFormat": "json", "type": "url"},
            verify=VERIFY_SSL,
            timeout=90,
        ).json()

        resp = j.get("response", {})
        attr_list = []

        if isinstance(resp, dict) and "Attribute" in resp:
            attr_list = resp["Attribute"]
        elif isinstance(resp, list):
            for it in resp:
                if isinstance(it, dict) and "Attribute" in it:
                    attr_list.extend(it["Attribute"])
                elif isinstance(it, dict):
                    attr_list.append(it)

        for a in attr_list:
            if isinstance(a, dict) and a.get("type", "").lower() == "url":
                v = (a.get("value") or "").strip()
                if v:
                    urls.append(v)

    except Exception as e:
        print("[WARN] Primary REST fetch failed:", e)

    # Fallback to /download
    if not urls:
        try:
            r = requests.post(
                MISP_BASE.rstrip("/") + "/attributes/restSearch/download",
                headers=HEADERS,
                json={"returnFormat": "json", "type": ["url"]},
                verify=VERIFY_SSL,
                timeout=90,
            )

            try:
                data = r.json()
                resp = data.get("response", data)
                if isinstance(resp, list):
                    for item in resp:
                        a = item.get("Attribute", item)
                        if isinstance(a, dict) and a.get("type", "").lower() == "url":
                            val = (a.get("value") or "").strip()
                            if val:
                                urls.append(val)
            except ValueError:
                for line in r.text.splitlines():
                    if URL_LIKE_RX.search(line):
                        urls.append(line.strip())

        except Exception as e:
            print("[ERROR] Fallback fetch failed:", e)

    # Canonicalize + filters
    out = []
    seen = set()

    for u in urls:
        cu = canonical_url(u)
        if not cu:
            continue

        # 1) Local whitelist (MISP instance, localhost, etc.)
        if is_whitelisted(cu):
            print("[WL-local] Skipping whitelisted URL:", cu)
            continue

        cu_low = cu.lower()

        # 2) Warninglist URL whitelist: exact URL match only
        if cu_low in wl_url_whitelist:
            print("[WL-warninglist] Skipping URL (exact URL match):", cu)
            continue

        if cu not in seen:
            seen.add(cu)
            out.append(cu)

    return out

# ==========================================================
# MAKE POSIX ERE REGEXES FOR SQUID
# ==========================================================

FORBIDDEN_SUBSTR = ["(?:", "(?=", "(?!", "(?<", "(?P<", "\\K", "\\R", "\\X"]
RE_BACKREF = re.compile(r"\\[1-9]")
RE_HEXUNI = re.compile(r"(\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\p\{)")

def url_to_regexes(u: str):
    try:
        p = urlparse(u)
    except Exception:
        return []

    host = (p.hostname or "").lower()
    if not host:
        return []

    path = p.path or "/"
    q = ("?" + p.query) if p.query else ""

    host_expr = re.escape(host)

    raw = p.netloc
    port = ""
    if ":" in raw:
        _, right = raw.rsplit(":", 1)
        if right.isdigit():
            port = ":" + right

    scheme_prefix = r"^https?://"
    exact = scheme_prefix + host_expr + re.escape(port) + re.escape(path + q) + "$"
    prefix = scheme_prefix + host_expr + re.escape(port) + re.escape(path) + r"([?#].*)?$"

    return [exact, prefix]

def _looks_posix_safe(s):
    if any(t in s for t in FORBIDDEN_SUBSTR):
        return False
    if RE_BACKREF.search(s):
        return False
    if RE_HEXUNI.search(s):
        return False
    return True

def _posix_clean(lines):
    out = []
    for ln in lines:
        ln = ln.strip().replace("\r", "")
        if not ln:
            continue
        if _looks_posix_safe(ln):
            out.append(ln)
    return out

# ==========================================================
# WRITE REGEX + RELOAD SQUID
# ==========================================================

def write_url_regex_file(urls):
    regs = []

    for u in urls:
        regs.extend(url_to_regexes(u))

    seen, cleaned = set(), []
    for r in regs:
        if r not in seen:
            seen.add(r)
            cleaned.append(r)

    cleaned = _posix_clean(cleaned)

    os.makedirs(OUT_DIR, exist_ok=True)

    # Overwrite old list → old URLs are cleared
    with open(URL_REGEX_FILE, "w") as f:
        f.write("\n".join(cleaned) + ("\n" if cleaned else ""))

    print(f"[OK] Wrote {len(cleaned)} regexes → {URL_REGEX_FILE}")

def reload_squid():
    if not RELOAD_SQUID:
        return

    import subprocess

    try:
        subprocess.check_call(["squid", "-k", "parse"])
        subprocess.check_call(["systemctl", "reload", "squid"])
        print("[OK] Squid config validated + reloaded")
    except Exception as e:
        print("[ERROR] Failed to reload Squid:", e)

# ==========================================================
# MAIN
# ==========================================================

def main():
    wl_url_whitelist = fetch_warninglist_url_whitelist()
    urls = fetch_urls_only(wl_url_whitelist)
    print("[INFO] Fetched", len(urls), "URL IoCs after warninglist/whitelist filters")

    write_url_regex_file(urls)
    reload_squid()

if __name__ == "__main__":
    main()
