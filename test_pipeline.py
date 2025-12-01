#!/usr/bin/env python3
"""
End-to-end test script for the MISP → Pi-hole → Squid → retrohunt pipeline.

What it does:
1. Creates a MISP test event with:
   - synthetic "malicious" domains + URLs
   - additional "false-positive" test domains + URLs that should be
     suppressed by MISP warninglists and NOT end up blocked.
2. Optionally calls your misp-to-pihole.py and misp-to-proxy.py to update blocklists.
3. Generates nslookup and curl traffic for those indicators.
4. Optionally calls misp-retrohunt.py so it can create a retrohunt result event.

Adjust:
- MISP_URL, MISP_KEY
- DNS_SERVER
- PROXY (host:port)
- Paths to your existing scripts.
- WARNINGLIST_TEST_DOMAINS / WARNINGLIST_TEST_URLS to match your warninglists.
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
MISP_KEY = "muudamind"
MISP_VERIFY_SSL = False                  # set True if you have proper TLS

DNS_SERVER = "127.0.0.1"                 # Pi-hole / dnsmasq IP inside VM
PROXY = "http://127.0.0.1:3128"          # Squid forward proxy address

# Paths to your existing scripts (used only to validate the prototype functional testing)
MISP_TO_PIHOLE_PATH = "/home/user/Documents/misp-to-pihole.py"
MISP_TO_PROXY_PATH = "/home/user/Documents/misp-to-proxy.py"
MISP_RETROHUNT_PATH = "/home/user/Documents/misp-retrohunt.py"

# Whether to automatically call the other scripts
RUN_MISP_TO_PIHOLE = True
RUN_MISP_TO_PROXY = True
RUN_RETROHUNT = True

# False-positive / warninglist test indicators.
# Fill these with domains/URLs that you know are covered by your MISP warninglists.
# They will be added to the test event with to_ids=true, but should be
# filtered out by misp-to-pihole.py / misp-to-proxy.py thanks to warninglists.
WARNINGLIST_TEST_DOMAINS = [
    # example:
    # "example.com",
]
WARNINGLIST_TEST_URLS = [
    # example:
    # "https://example.com/",
]

# ---------------------------------------------------------------------


def random_token(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def generate_test_iocs() -> Tuple[List[str], List[str]]:
    """
    Generate a small set of synthetic test domains and URLs.
    These are not real malicious indicators; they only exist to exercise the pipeline.
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
    wl_test_domains: List[str],
    wl_test_urls: List[str],
) -> int:
    """
    Create a MISP event with:
      - domain and URL attributes representing synthetic malicious IoCs
      - additional domain and URL attributes meant to be suppressed by
        warninglists (false-positive tests).
    Returns the created event ID.
    """
    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    event_body = {
        "Event": {
            "info": "[TEST] CTI-to-proxy & retrohunt pipeline validation (with warninglist FP test)",
            "distribution": 0,          # Your org only
            "threat_level_id": 3,       # low (1=high, 2=medium, 3=low, 4=undefined)
            "analysis": 0,              # 0=initial
            "published": False,
            "Attribute": [],
        }
    }

    # Malicious test domains
    for d in malicious_domains:
        event_body["Event"]["Attribute"].append({
            "type": "domain",
            "category": "Network activity",
            "value": d,
            "to_ids": True,
            "comment": "synthetic-malicious-test",
        })

    # Malicious test URLs
    for u in malicious_urls:
        event_body["Event"]["Attribute"].append({
            "type": "url",
            "category": "Network activity",
            "value": u,
            "to_ids": True,
            "comment": "synthetic-malicious-test",
        })

    # Warninglist false-positive test domains
    for d in wl_test_domains:
        event_body["Event"]["Attribute"].append({
            "type": "domain",
            "category": "Network activity",
            "value": d,
            "to_ids": True,
            "comment": "warninglist-fp-test",
        })

    # Warninglist false-positive test URLs
    for u in wl_test_urls:
        event_body["Event"]["Attribute"].append({
            "type": "url",
            "category": "Network activity",
            "value": u,
            "to_ids": True,
            "comment": "warninglist-fp-test",
        })

    resp = requests.post(
        f"{MISP_URL}/events/add",
        headers=headers,
        data=json.dumps(event_body),
        verify=MISP_VERIFY_SSL,
    )
    resp.raise_for_status()
    data = resp.json()

    event_id = int(data["Event"]["id"])
    print(f"[+] Created MISP test event with ID {event_id}")
    print(f"[+] Event contains {len(malicious_domains)} malicious domains, "
          f"{len(malicious_urls)} malicious URLs, "
          f"{len(wl_test_domains)} warninglist-test domains, "
          f"{len(wl_test_urls)} warninglist-test URLs.")
    return event_id


def run_subprocess(cmd: List[str]) -> None:
    """Helper to run a subprocess and print its command and exit code."""
    print(f"[CMD] {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        print(f"[+] Exit code: {result.returncode}")
    except Exception as exc:
        print(f"[!] Failed to run {' '.join(cmd)}: {exc}", file=sys.stderr)


def update_pi_hole_and_proxy() -> None:
    """
    Optionally call your misp-to-pihole.py and misp-to-proxy.py scripts.
    Adapt arguments to whatever you use in your environment.
    """
    if RUN_MISP_TO_PIHOLE and os.path.isfile(MISP_TO_PIHOLE_PATH):
        run_subprocess(["python3", MISP_TO_PIHOLE_PATH])

    if RUN_MISP_TO_PROXY and os.path.isfile(MISP_TO_PROXY_PATH):
        run_subprocess(["python3", MISP_TO_PROXY_PATH])


def generate_dns_traffic(domains: List[str]) -> None:
    """
    Run nslookup for each test domain so Pi-hole logs contain queries.
    """
    print("[*] Generating DNS test traffic...")
    for d in domains:
        cmd = ["nslookup", d, DNS_SERVER]
        run_subprocess(cmd)


def generate_http_traffic(urls: List[str]) -> None:
    """
    Run curl through the proxy for each test URL so Squid logs contain requests.
    """
    print("[*] Generating HTTP(S) test traffic via proxy...")
    for u in urls:
        cmd = [
            "curl",
            "-x", PROXY,
            "-k",          # skip TLS verification if needed
            "-m", "10",    # timeout
            "-sS",         # silent but show errors
            u,
        ]
        run_subprocess(cmd)


def run_retrohunt() -> None:
    """
    Optionally call your misp-retrohunt.py script.
    The retrohunt script is assumed to:
    - Read Pi-hole and Squid logs inside the VM
    - Compare them with current MISP indicators
    - Create a new MISP event with matches
    """
    if RUN_RETROHUNT and os.path.isfile(MISP_RETROHUNT_PATH):
        print("[*] Running retrohunt script...")
        run_subprocess(["python3", MISP_RETROHUNT_PATH])
    else:
        print("[!] Retrohunt script not run (disabled or path not found).")


def main():
    print("[*] Generating synthetic malicious IoCs...")
    malicious_domains, malicious_urls = generate_test_iocs()
    print(f"[+] Malicious domains: {malicious_domains}")
    print(f"[+] Malicious URLs:    {malicious_urls}")

    if WARNINGLIST_TEST_DOMAINS or WARNINGLIST_TEST_URLS:
        print("[*] Using additional warninglist false-positive test IoCs:")
        print(f"    Domains: {WARNINGLIST_TEST_DOMAINS}")
        print(f"    URLs:    {WARNINGLIST_TEST_URLS}")
    else:
        print("[*] No WARNINGLIST_TEST_* IoCs configured (you can add some in the script).")

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

    # Small delay so new rules are active (tweak as needed)
    print("[*] Waiting a few seconds for enforcement rules to apply...")
    time.sleep(5)

    # Generate traffic that should be seen by DNS + proxy.
    # We generate traffic for BOTH malicious + warninglist-test IoCs.
    all_domains = malicious_domains + WARNINGLIST_TEST_DOMAINS
    all_urls = malicious_urls + WARNINGLIST_TEST_URLS

    generate_dns_traffic(all_domains)
    generate_http_traffic(all_urls)

    # At this point, Pi-hole and Squid logs should contain the test entries.
    # Now run your retrohunt pipeline to see if it finds them.
    run_retrohunt()

    print("[+] Test pipeline completed.")


if __name__ == "__main__":
    main()
