#!/usr/bin/env python3
"""
End-to-end test script for the MISP → Pi-hole → Squid → retrohunt pipeline,
including explicit false-positive / warninglist tests.

What it does:
1. Creates a MISP test event with:
   - synthetic "malicious" domains + URLs (should be blocked),
   - benign domains + URLs that are present in a MISP warninglist
     (should be suppressed by warninglists and NOT blocked).
2. Calls misp-to-pihole.py and misp-to-proxy.py to update enforcement.
3. Generates nslookup and curl traffic for ALL indicators.
4. Prints a simple BLOCKED / ALLOWED summary per IoC.
5. Optionally runs misp-retrohunt.py.

Adjust:
- MISP_URL, MISP_KEY
- DNS_SERVER, PROXY
- Paths to your scripts
"""

import os
import sys
import time
import json
import random
import string
import subprocess
from typing import List, Tuple

import requests

# ----------------- CONFIG: ADAPT TO YOUR ENVIRONMENT -----------------

MISP_URL = "https://misp.local"          # no trailing slash
MISP_KEY = "changeMe"          # <-- put your key back here
MISP_VERIFY_SSL = False                  # set True if you have proper TLS

DNS_SERVER = "127.0.0.1"                 # Pi-hole / dnsmasq IP inside VM
PROXY = "http://127.0.0.1:3128"          # Squid forward proxy address

MISP_TO_PIHOLE_PATH = "/home/user/Documents/misp-to-pihole.py"
MISP_TO_PROXY_PATH = "/home/user/Documents/misp-to-proxy.py"
MISP_RETROHUNT_PATH = "/home/user/Documents/misp-retrohunt.py"

RUN_MISP_TO_PIHOLE = True
RUN_MISP_TO_PROXY = True
RUN_RETROHUNT = True

# Benign IoCs that are ALSO in your warninglist in MISP.
# These should appear in the test event, but be SUPPRESSED before enforcement.
WARNINGLIST_TEST_DOMAINS = [
    "benign-test1.local",
]
WARNINGLIST_TEST_URLS = [
    "http://benign-test1.local/",
]

# ---------------------------------------------------------------------


def misp_headers():
    return {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def random_token(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def generate_malicious_iocs() -> Tuple[List[str], List[str]]:
    """
    Generate a small set of synthetic malicious domains and URLs.
    """
    token = random_token()
    base_domains = [
        f"{token}-alpha.test",
        f"{token}-beta.example",
        f"{token}-gamma.localdomain",
    ]

    urls = [
        f"http://{base_domains[0]}/malware/index.html",
        f"http://{base_domains[1]}/phishing/login.php",
        f"http://{base_domains[2]}/payload/dropper.bin",
    ]

    return base_domains, urls


def create_misp_event(
    malicious_domains: List[str],
    malicious_urls: List[str],
    benign_domains: List[str],
    benign_urls: List[str],
) -> int:
    """
    Create a MISP test event with:
      - malicious domains/URLs (to be blocked),
      - benign domains/URLs (present in warninglists, should be suppressed in enforcement).
    """
    body = {
        "Event": {
            "info": "[TEST] CTI pipeline validation with warninglist FP test",
            "distribution": 0,          # your org only
            "threat_level_id": 3,       # low
            "analysis": 0,              # initial
            "published": False,
            "Attribute": [],
        }
    }

    for d in malicious_domains:
        body["Event"]["Attribute"].append({
            "type": "domain",
            "category": "Network activity",
            "value": d,
            "to_ids": True,
            "comment": "synthetic-malicious-test",
        })

    for u in malicious_urls:
        body["Event"]["Attribute"].append({
            "type": "url",
            "category": "Network activity",
            "value": u,
            "to_ids": True,
            "comment": "synthetic-malicious-test",
        })

    for d in benign_domains:
        body["Event"]["Attribute"].append({
            "type": "domain",
            "category": "Network activity",
            "value": d,
            "to_ids": True,
            "comment": "benign-test-warninglist",
        })

    for u in benign_urls:
        body["Event"]["Attribute"].append({
            "type": "url",
            "category": "Network activity",
            "value": u,
            "to_ids": True,
            "comment": "benign-test-warninglist",
        })

    resp = requests.post(
        f"{MISP_URL}/events/add",
        headers=misp_headers(),
        data=json.dumps(body),
        verify=MISP_VERIFY_SSL,
    )
    resp.raise_for_status()
    data = resp.json()

    event_id = int(data["Event"]["id"])
    total_attrs = len(body["Event"]["Attribute"])
    print(f"[+] Created MISP test event {event_id} with {total_attrs} attributes:")
    print(f"    - {len(malicious_domains)} malicious domains")
    print(f"    - {len(malicious_urls)} malicious URLs")
    print(f"    - {len(benign_domains)} benign domains (warninglist)")
    print(f"    - {len(benign_urls)} benign URLs (warninglist)")
    return event_id


def run_subprocess(cmd: List[str]) -> subprocess.CompletedProcess:
    """Run a subprocess and return its result, printing output."""
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    print(f"[+] Exit code: {result.returncode}")
    return result


def update_pi_hole_and_proxy() -> None:
    """
    Call misp-to-pihole.py and misp-to-proxy.py if present.
    """
    if RUN_MISP_TO_PIHOLE and os.path.isfile(MISP_TO_PIHOLE_PATH):
        run_subprocess(["python3", MISP_TO_PIHOLE_PATH])

    if RUN_MISP_TO_PROXY and os.path.isfile(MISP_TO_PROXY_PATH):
        run_subprocess(["python3", MISP_TO_PROXY_PATH])


def test_dns_blocking(malicious_domains: List[str], benign_domains: List[str]) -> None:
    """
    For each domain, run nslookup and classify as BLOCKED vs ALLOWED.
    BLOCKED = answer contains 0.0.0.0 or ::.
    """
    print("[*] Testing DNS behaviour (Pi-hole)...")

    def check(domain: str) -> bool:
        result = run_subprocess(["nslookup", domain, DNS_SERVER])
        out = result.stdout or ""
        blocked = ("0.0.0.0" in out) or ("\nAddress: ::\n" in out)
        return blocked

    print("\n[DNS] Malicious domains:")
    for d in malicious_domains:
        blocked = check(d)
        status = "BLOCKED" if blocked else "ALLOWED"
        print(f"  {d}: {status}")

    print("\n[DNS] Benign (warninglist) domains:")
    for d in benign_domains:
        blocked = check(d)
        status = "BLOCKED" if blocked else "ALLOWED"
        print(f"  {d}: {status}")

    print()


def test_http_blocking(malicious_urls: List[str], benign_urls: List[str]) -> None:
    """
    For each URL, run curl via Squid and classify as BLOCKED vs ALLOWED.
    BLOCKED = HTTP status not in 2xx range OR Squid error page detected.
    """
    print("[*] Testing HTTP(S) behaviour via proxy (Squid)...")

    def check(url: str) -> bool:
        cmd = [
            "curl",
            "-x", PROXY,
            "-k",
            "-m", "10",
            "-sS",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            url,
        ]
        result = run_subprocess(cmd)
        status_text = (result.stdout or "").strip()
        blocked = True
        try:
            code = int(status_text)
            blocked = not (200 <= code < 300)
        except ValueError:
            blocked = True
        return blocked

    print("\n[HTTP] Malicious URLs:")
    for u in malicious_urls:
        blocked = check(u)
        status = "BLOCKED" if blocked else "ALLOWED"
        print(f"  {u}: {status}")

    print("\n[HTTP] Benign (warninglist) URLs:")
    for u in benign_urls:
        blocked = check(u)
        status = "BLOCKED" if blocked else "ALLOWED"
        print(f"  {u}: {status}")

    print()


def run_retrohunt() -> None:
    """
    Optionally run misp-retrohunt.py.
    """
    if RUN_RETROHUNT and os.path.isfile(MISP_RETROHUNT_PATH):
        print("[*] Running retrohunt script...")
        run_subprocess(["python3", MISP_RETROHUNT_PATH])
    else:
        print("[!] Retrohunt script not run (disabled or path not found).")


def main():
    print("[*] Generating synthetic malicious IoCs...")
    malicious_domains, malicious_urls = generate_malicious_iocs()
    print(f"[+] Malicious domains: {malicious_domains}")
    print(f"[+] Malicious URLs:    {malicious_urls}")

    print("[*] Using benign IoCs from warninglist:")
    print(f"    Benign domains: {WARNINGLIST_TEST_DOMAINS}")
    print(f"    Benign URLs:    {WARNINGLIST_TEST_URLS}")

    print("[*] Creating MISP test event...")
    event_id = create_misp_event(
        malicious_domains,
        malicious_urls,
        WARNINGLIST_TEST_DOMAINS,
        WARNINGLIST_TEST_URLS,
    )
    print(f"[+] Test event ID: {event_id}")

    print("[*] Updating Pi-hole and Squid from MISP (if enabled)...")
    update_pi_hole_and_proxy()

    print("[*] Waiting a few seconds for enforcement rules to apply...")
    time.sleep(5)

    # DNS + HTTP tests with per-IoC classification
    test_dns_blocking(malicious_domains, WARNINGLIST_TEST_DOMAINS)
    test_http_blocking(malicious_urls, WARNINGLIST_TEST_URLS)

    # Retrohunt over the logs containing these tests
    run_retrohunt()

    print("[+] Test pipeline (with warninglist FP test) completed.")


if __name__ == "__main__":
    main()
