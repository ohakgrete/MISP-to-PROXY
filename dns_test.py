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

# Benchmark settings
TEST_DURATION_SECONDS = 300  # 5 minutes per test
SLEEP_BETWEEN_QUERIES = 0.01  # 10ms pause

# Source: StevenBlack blocklist
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
    total_attempts = 0

    print(f"Running DNS test for {duration_seconds // 60} minutes...\n")
    end_time = time.time() + duration_seconds

    while time.time() < end_time:
        domain = random.choice(domains)
        total_attempts += 1
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
        "avg": statistics.mean(successful) if successful else 0,
        "min": min(successful) if successful else 0,
        "max": max(successful) if successful else 0,
        "stddev": statistics.stdev(successful) if len(successful) > 1 else 0,
        "count": len(successful),
        "attempted": total_attempts,
        "allowed": len(results["allowed"]),
        "blocked": len(results["blocked"]),
        "not_found": len(results["not_found"]),
        "cpu_avg": statistics.mean(cpu_stats) if cpu_stats else 0,
        "ram_avg": statistics.mean(ram_stats) if ram_stats else 0,
    }


def average_runs(results_list):
    def avg(values): return sum(values) / len(values) if values else 0

    return {
        "avg_latency": avg([r["avg"] for r in results_list]),
        "min_latency": min(r["min"] for r in results_list),
        "max_latency": max(r["max"] for r in results_list),
        "stddev": avg([r["stddev"] for r in results_list]),
        "allowed": sum(r["allowed"] for r in results_list),
        "blocked": sum(r["blocked"] for r in results_list),
        "not_found": sum(r["not_found"] for r in results_list),
        "attempted": sum(r["attempted"] for r in results_list),
        "count": sum(r["count"] for r in results_list),
        "cpu_avg": avg([r["cpu_avg"] for r in results_list]),
        "ram_avg": avg([r["ram_avg"] for r in results_list]),
    }


def print_summary(label, summary):
    print(f"\n=== SUMMARY FOR {label.upper()} ===")
    print(f"  Total Runs: 6")
    print(f"  Total Attempted Queries: {summary['attempted']}")
    print(f"  Successful Queries: {summary['count']}")
    print(f"  Avg Latency: {summary['avg_latency']:.2f} ms")
    print(f"  Min Latency: {summary['min_latency']:.2f} ms")
    print(f"  Max Latency: {summary['max_latency']:.2f} ms")
    print(f"  Std Dev (avg): {summary['stddev']:.2f} ms")
    print(f"  Allowed Domains: {summary['allowed']}")
    print(f"  Blocked Domains: {summary['blocked']}")
    print(f"  Failed/Not Resolved: {summary['not_found']}")
    print(f"  Avg CPU Usage: {summary['cpu_avg']:.2f} %")
    print(f"  Avg RAM Usage: {summary['ram_avg']:.2f} MB")


def main():
    domains = fetch_test_domains()

    for label, ip in DNS_SERVERS.items():
        print(f"\n=== BEGIN TESTS FOR {label.upper()} ({ip}) ===")
        results_list = []

        for i in range(6):
            print(f"\n--- Run {i+1}/6 for {label} ---")
            stats = test_dns(ip, domains, TEST_DURATION_SECONDS)
            print(f"  Run {i+1} Completed: {stats['count']} successes, {stats['blocked']} blocked, {stats['not_found']} failed.")
            results_list.append(stats)

        summary = average_runs(results_list)
        print_summary(label, summary)

        if label == "pihole_no_blocklist":
            input("\nPress Enter to begin tests for the blocked configuration...\n")


if __name__ == "__main__":
    main()
