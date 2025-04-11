#!/usr/bin/env python3
import dns.resolver
import time
import statistics
import random

# DNS servers to test
DNS_SERVERS = {
    "pihole_no_blocklist": "127.0.0.1",
    "pihole_with_blocklist": "127.0.0.1",
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8"
}

# Legitimate test domains
BASE_DOMAINS = [
    "example.com", "google.com", "facebook.com", "reddit.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "bbc.co.uk", "openai.com",
    "nasa.gov", "who.int", "cloudflare.com", "mozilla.org", "github.com",
    "stackoverflow.com", "python.org", "debian.org", "kernel.org", "gstatic.com"
]

# Blocked/malicious domains - use just if need to see if its blocking correctly, aslo might be not upto date
BLOCKED_DOMAINS = [
#    "arnoldhero.com", "ian0xzp6oekbdpk.com", "www.apple.internetdocss.com", "lawkimsun.ddns.net",
#    "systemalu.com", "apple-liret.com", "ftp.scroller.longmusic.com", "kingstonevikte.com",
#    "mirjamholleman.nl", "appl-0.com", "bl5kn4qkvkk.quiezeasycosmetic.net",
#    "he2woy3enyxde3lenyxg4zlu.stonepitsarcodessanguinea.info", "ocean.local-test.com",
#    "kremenchug-news.ru", "brokelimiteds.in", "iihf.eu", "cancelbuttondc.no-ip.biz",
#    "www.digitalinsight-ltd.com", "usedtextilemachinerylive.com", "qvwv0br1-p.thohjkuvat.net",
#    "trajectory-imperialist.lobelqq.xyz", "coliseum.cappedfhnc.xyz",
#    "p4k1ofg9upwpdjv01aa7j7f.bestdownloadsv.info", "bhetakwouno.info",
#    "4xx8i83bckyhlngflbx47pi.besthomemortgages.org",
#    "stormlakedemokratisk.montrealindependentgamesfestival.com", "yurigames.ddns.net",
#    "apple-ap.com", "zryh.info", "rumoney.xyz", "service-verify-v25.gq", "hou.thisisgoodstuffs.com",
#    "hashmonero.com", "gizg64dfnzqwiltumyys4zts.loveknotflankerback.net",
#    "k-ak.ageeymarketingmedve.com", "alsblueshelpt.nl", "gtc9871.com", "manoufdeances.com",
#    "blogdecachorros.com", "redhack007.duckdns.org", "ntc792.com", "netmailerplus.info",
#    "shell-create.ddns.net", "signin-appleid-usa.com", "koosawqartuho.ml", "ltlxlvazy.info",
#    "villabrih.com", "toudghacccam.com", "jrgs.sfcorporation.com", "phatrat.chickenkiller.com"
]

LOOPS = 60
DOMAINS_PER_LOOP = 10
SLEEP_BETWEEN_QUERIES = 0.015


def test_dns(server_ip, safe_domains, blocked_domains, loops, per_loop):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.timeout = 2
    resolver.lifetime = 2

    times = []
    print(f"Sending {loops * per_loop} queries to {server_ip}...\n")

    all_domains = safe_domains + blocked_domains

    for i in range(loops):
        sample = random.sample(all_domains, per_loop)
        for domain in sample:
            start = time.time()
            try:
                resolver.resolve(domain)
                elapsed = (time.time() - start) * 1000
                times.append(elapsed)
            except Exception as e:
                print(f"  [!] Failed {domain}: {e}")
                times.append(None)
            time.sleep(SLEEP_BETWEEN_QUERIES)

    successful = [t for t in times if t is not None]
    if not successful:
        return {"avg": None, "min": None, "max": None, "count": 0}

    return {
        "avg": statistics.mean(successful),
        "min": min(successful),
        "max": max(successful),
        "count": len(successful)
    }


def main():
    for label, ip in DNS_SERVERS.items():
        print(f"\n=== Testing {label.upper()} ({ip}) ===")
        stats = test_dns(ip, BASE_DOMAINS, BLOCKED_DOMAINS, LOOPS, DOMAINS_PER_LOOP)
        print(f"\n--- Results for {label} ---")
        print(f"  Queries: {stats['count']}")
        print(f"  Avg: {stats['avg']:.2f} ms")
        print(f"  Min: {stats['min']:.2f} ms")
        print(f"  Max: {stats['max']:.2f} ms")

        input("\nPress Enter to continue to the next DNS provider...\n")


if __name__ == "__main__":
    main()
