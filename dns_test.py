#!/usr/bin/env python3
import dns.resolver
import time
import statistics
import random
import requests
import psutil

# sudo apt install python3-psutil
# sudo apt install python3-dnspython

# DNS servers to test
DNS_SERVERS = {
    "pihole_no_blocklist": "127.0.0.1",
    "pihole_with_blocklist": "127.0.0.1",
}

TEST_DURATION_SECONDS = 300  # 5 minutes
SLEEP_BETWEEN_QUERIES = 0.02  # 20ms

STEVENBLACK_HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def fetch_test_domains():
    print("Downloading domain list from StevenBlack...")
    response = requests.get(STEVENBLACK_HOSTS_URL)
    lines = response.text.splitlines()

    domains = []
    for line in lines:
        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            parts = line.split()
            if len(parts) >= 2:
                domains.append(parts[1])
    print(f"Retrieved {len(domains)} domains.\n")
    return domains


def get_system_usage():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().used / (1024 * 1024)  # in MB
    return cpu, ram

def test_dns(server_ip, domains, duration_seconds):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.timeout = 2
    resolver.lifetime = 2

    times = []
    results = {"allowed": [], "blocked": [], "not_found": []}
    cpu_stats = []
    ram_stats = []

    end_time = time.time() + duration_seconds

    while time.time() < end_time:
        domain = random.choice(domains)
        start = time.time()
        elapsed = None
        category = "not_found"

        try:
            answer = resolver.resolve(domain)
            elapsed = (time.time() - start) * 1000  # in ms
            if answer.rrset:
                category = "allowed"
        except dns.resolver.NXDOMAIN:
            elapsed = (time.time() - start) * 1000
            category = "blocked"
        except Exception:
            category = "not_found"

        if category in ("allowed", "blocked") and elapsed is not None:
            times.append(elapsed)
        results[category].append((domain, elapsed))

        cpu, ram = get_system_usage()
        cpu_stats.append(cpu)
        ram_stats.append(ram)

        time.sleep(SLEEP_BETWEEN_QUERIES)

    successful = [t for t in times if t is not None]

    return {
        "avg": statistics.mean(successful) if successful else None,
        "min": min(successful) if successful else None,
        "max": max(successful) if successful else None,
        "stddev": statistics.stdev(successful) if len(successful) > 1 else 0,
        "count": len(successful),
        "allowed": len(results["allowed"]),
        "blocked": len(results["blocked"]),
        "not_found": len(results["not_found"]),
        "cpu_avg": statistics.mean(cpu_stats) if cpu_stats else None,
        "ram_avg": statistics.mean(ram_stats) if ram_stats else None,
    }

def main():
    domains = fetch_test_domains()
    for label, ip in DNS_SERVERS.items():
        print(f"\n=== Testing {label.upper()} ({ip}) ===")
        stats = test_dns(ip, domains, TEST_DURATION_SECONDS)

        print(f"\n--- Results for {label} ---")
        print(f"  Total Queries: {stats['count']}")
        print(f"  Avg Latency: {stats['avg']:.2f} ms")
        print(f"  Min Latency: {stats['min']:.2f} ms")
        print(f"  Max Latency: {stats['max']:.2f} ms")
        print(f"  Std Dev: {stats['stddev']:.2f} ms")
        print(f"  Allowed Domains: {stats['allowed']}")
        print(f"  Blocked Domains: {stats['blocked']}")
        print(f"  Failed/Not Resolved: {stats['not_found']}")
        print(f"  Avg CPU Usage: {stats['cpu_avg']:.2f} %")
        print(f"  Avg RAM Usage: {stats['ram_avg']:.2f} MB")

        input("\nPress Enter to continue to the next DNS provider...\n")


if __name__ == "__main__":
    main()
