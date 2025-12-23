#!/usr/bin/env python3
"""
sme_load_test.py

Simulate SME endpoints generating DNS + HTTPS traffic via Pi-hole and Squid.
Adds optional CPU/RAM load per endpoint, adjustable ramp-up, think time, and system monitoring.

Defaults:
  --devices 15

Examples:
  # 15 endpoints, light traffic, 10% bad IoCs, with monitoring
  sudo ./sme_load_test.py --devices 15 --requests 50 --bad-fraction 0.1 --monitor-interval 1

  # Stress: 100 endpoints, 200 requests each, add CPU/RAM pressure per endpoint
  sudo ./sme_load_test.py --devices 100 --requests 200 --cpu-load 20 --mem-mb 50 --monitor-interval 1

  # Use nslookup (heavier, but closest to your original)
  sudo ./sme_load_test.py --use-nslookup

Notes:
- For HTTPS we use curl through Squid.
- For DNS we can either:
    A) use Python UDP resolver to Pi-hole (fast)
    B) spawn nslookup (slower, but mimics your existing test)
"""

import argparse
import os
import random
import socket
import statistics
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

# --------- Targets ---------

GOOD_DOMAINS = [
    "www.wikipedia.org",
    "www.debian.org",
    "www.kernel.org",
    "www.python.org",
    "www.ripe.net",
]
GOOD_URLS = [
    "https://www.wikipedia.org/",
    "https://www.debian.org/",
    "https://www.kernel.org/",
    "https://www.python.org/",
    "https://www.ripe.net/",
]

BAD_DOMAIN_DEFAULT = "malicious.example.test"
BAD_URL_DEFAULT = "https://malicious.example.test/malware/test"


# --------- Stats ---------

@dataclass
class DeviceIdentity:
    device_id: int
    hostname: str
    mac: str
    user_agent: str


@dataclass
class DeviceStats:
    dns_latencies: List[float] = field(default_factory=list)
    dns_total: int = 0
    dns_blocked: int = 0

    http_latencies: List[float] = field(default_factory=list)
    http_total: int = 0
    http_blocked: int = 0

    good_dns_total: int = 0
    good_dns_blocked: int = 0
    bad_dns_total: int = 0
    bad_dns_blocked: int = 0

    good_http_total: int = 0
    good_http_blocked: int = 0
    bad_http_total: int = 0
    bad_http_blocked: int = 0

    errors: int = 0


# --------- Helpers ---------

def random_mac(rng: random.Random) -> str:
    # Locally administered MAC
    b = [0x02, rng.randrange(0, 256), rng.randrange(0, 256), rng.randrange(0, 256), rng.randrange(0, 256), rng.randrange(0, 256)]
    return ":".join(f"{x:02x}" for x in b)

def fmt_stats(values: List[float], label: str):
    if not values:
        print(f"{label}: no data\n")
        return
    avg = statistics.mean(values)
    min_v = min(values)
    max_v = max(values)
    p95 = None
    if len(values) >= 2:
        try:
            p95 = statistics.quantiles(values, n=20)[18]
        except Exception:
            p95 = None
    print(f"{label}:")
    print(f"  count = {len(values)}")
    print(f"  avg   = {avg*1000:.2f} ms")
    print(f"  min   = {min_v*1000:.2f} ms")
    print(f"  max   = {max_v*1000:.2f} ms")
    if p95 is not None:
        print(f"  p95   = {p95*1000:.2f} ms")
    print()

def read_proc_meminfo() -> Tuple[Optional[int], Optional[int]]:
    # returns (mem_total_kb, mem_available_kb)
    try:
        total = avail = None
        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
        return total, avail
    except Exception:
        return None, None

def read_proc_loadavg() -> Optional[Tuple[float, float, float]]:
    try:
        with open("/proc/loadavg", "r", encoding="utf-8", errors="ignore") as f:
            parts = f.read().strip().split()
        return (float(parts[0]), float(parts[1]), float(parts[2]))
    except Exception:
        return None

def read_proc_stat_cpu() -> Optional[Tuple[int, int]]:
    # returns (total_jiffies, idle_jiffies)
    try:
        with open("/proc/stat", "r", encoding="utf-8", errors="ignore") as f:
            line = f.readline()
        parts = line.split()
        if parts[0] != "cpu":
            return None
        vals = list(map(int, parts[1:]))
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        return total, idle
    except Exception:
        return None

def cpu_percent_over_interval(dt: float, prev: Tuple[int, int], cur: Tuple[int, int]) -> Optional[float]:
    try:
        total0, idle0 = prev
        total1, idle1 = cur
        dt_total = total1 - total0
        dt_idle = idle1 - idle0
        if dt_total <= 0:
            return None
        return 100.0 * (1.0 - (dt_idle / dt_total))
    except Exception:
        return None


# --------- DNS implementations ---------

def run_nslookup(dns_server: str, domain: str) -> Tuple[float, bool]:
    cmd = ["nslookup", domain, dns_server]
    t0 = time.monotonic()
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    t1 = time.monotonic()
    out = r.stdout or ""
    blocked = ("0.0.0.0" in out) or ("\nAddress: ::\n" in out)
    return t1 - t0, blocked

def run_udp_dns_query(dns_server: str, domain: str, timeout: float = 2.0) -> Tuple[float, bool]:
    """
    Lightweight UDP DNS A query. We treat reply with A=0.0.0.0 as blocked.
    This is not a full resolver; it's a minimal query for performance testing.
    """
    # Build minimal DNS query (A record)
    # Transaction ID
    tid = random.randrange(0, 65536)
    flags = 0x0100  # standard query, recursion desired
    qdcount = 1
    ancount = nscount = arcount = 0
    header = tid.to_bytes(2, "big") + flags.to_bytes(2, "big") + qdcount.to_bytes(2, "big") + ancount.to_bytes(2, "big") + nscount.to_bytes(2, "big") + arcount.to_bytes(2, "big")

    def enc_name(name: str) -> bytes:
        parts = name.strip(".").split(".")
        out = b""
        for p in parts:
            out += bytes([len(p)]) + p.encode("utf-8", "ignore")
        return out + b"\x00"

    qname = enc_name(domain)
    qtype = (1).to_bytes(2, "big")   # A
    qclass = (1).to_bytes(2, "big")  # IN
    packet = header + qname + qtype + qclass

    t0 = time.monotonic()
    blocked = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, 53))
        data, _ = sock.recvfrom(4096)
        t1 = time.monotonic()

        # Extremely naive answer parse: just search for 0.0.0.0 in RDATA of A records.
        # 0.0.0.0 bytes = 00 00 00 00
        if b"\x00\x00\x00\x00" in data:
            blocked = True
        return (t1 - t0), blocked
    except Exception:
        t1 = time.monotonic()
        return (t1 - t0), True  # treat failures as "blocked/unresolved" for safety
    finally:
        try:
            sock.close()
        except Exception:
            pass


# --------- HTTP via proxy ---------

def run_curl(proxy: str, url: str, user_agent: str, timeout_s: int = 10, verify_tls: bool = True) -> Tuple[float, bool]:
    """
    If verify_tls=True, curl will verify cert chain (you want this once CA is trusted).
    If verify_tls=False, use -k (original behavior).
    """
    cmd = [
        "curl",
        "-x", proxy,
        "-m", str(timeout_s),
        "-s",
        "-o", "/dev/null",
        "-A", user_agent,
        "-w", "%{http_code}",
    ]
    if not verify_tls:
        cmd.insert(1, "-k")
    cmd.append(url)

    t0 = time.monotonic()
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    t1 = time.monotonic()

    status = (r.stdout or "").strip()
    blocked = True
    try:
        code = int(status)
        blocked = not (200 <= code < 300)
    except ValueError:
        blocked = True
    return (t1 - t0), blocked


# --------- Load: CPU + RAM per device ---------

def cpu_burn(stop_event: threading.Event, target_util: float):
    """
    Burn CPU roughly at target_util percent of one core.
    target_util: 0..100
    """
    if target_util <= 0:
        return
    # Simple duty cycle loop
    period = 0.1  # seconds
    busy = period * (target_util / 100.0)
    idle = max(0.0, period - busy)
    while not stop_event.is_set():
        t_end = time.perf_counter() + busy
        while time.perf_counter() < t_end:
            pass
        if idle:
            time.sleep(idle)

def alloc_memory(megabytes: int) -> Optional[bytearray]:
    if megabytes <= 0:
        return None
    # Allocate and touch memory so it's committed
    b = bytearray(megabytes * 1024 * 1024)
    step = 4096
    for i in range(0, len(b), step):
        b[i] = (b[i] + 1) % 256
    return b


# --------- Device simulation ---------

def simulate_device(
    ident: DeviceIdentity,
    dns_server: str,
    proxy: str,
    bad_domain: str,
    bad_url: str,
    requests_per_device: int,
    bad_fraction: float,
    stats: DeviceStats,
    think_ms_min: int,
    think_ms_max: int,
    burst: int,
    use_nslookup: bool,
    curl_verify_tls: bool,
):
    rng = random.Random(ident.device_id * 1337 + int(time.time()))
    # Note: we don't actually change source IP/MAC at network level; this is "logical" identity for reporting/log analysis.

    for i in range(requests_per_device):
        use_bad = (rng.random() < bad_fraction)

        if use_bad and bad_domain and bad_url:
            domain = bad_domain
            url = bad_url
            is_good = False
        else:
            domain = rng.choice(GOOD_DOMAINS)
            url = rng.choice(GOOD_URLS)
            is_good = True

        try:
            # DNS
            if use_nslookup:
                dns_latency, dns_blocked = run_nslookup(dns_server, domain)
            else:
                dns_latency, dns_blocked = run_udp_dns_query(dns_server, domain)
            stats.dns_latencies.append(dns_latency)
            stats.dns_total += 1
            if dns_blocked:
                stats.dns_blocked += 1

            if is_good:
                stats.good_dns_total += 1
                if dns_blocked:
                    stats.good_dns_blocked += 1
            else:
                stats.bad_dns_total += 1
                if dns_blocked:
                    stats.bad_dns_blocked += 1

            # HTTPS via proxy
            http_latency, http_blocked = run_curl(proxy, url, ident.user_agent, verify_tls=curl_verify_tls)
            stats.http_latencies.append(http_latency)
            stats.http_total += 1
            if http_blocked:
                stats.http_blocked += 1

            if is_good:
                stats.good_http_total += 1
                if http_blocked:
                    stats.good_http_blocked += 1
            else:
                stats.bad_http_total += 1
                if http_blocked:
                    stats.bad_http_blocked += 1

        except Exception:
            stats.errors += 1

        # Think time + burstiness
        if burst > 1:
            if (i + 1) % burst == 0:
                # longer pause after a burst
                time.sleep(rng.uniform(0.2, 1.0))
        if think_ms_max > 0:
            ms = rng.randint(think_ms_min, think_ms_max) if think_ms_max >= think_ms_min else think_ms_min
            time.sleep(ms / 1000.0)


# --------- Monitoring thread ---------

def monitor_system(stop_event: threading.Event, interval_s: float):
    prev = read_proc_stat_cpu()
    time.sleep(interval_s)
    while not stop_event.is_set():
        cur = read_proc_stat_cpu()
        cpu_pct = None
        if prev and cur:
            cpu_pct = cpu_percent_over_interval(interval_s, prev, cur)
        prev = cur

        mem_total, mem_avail = read_proc_meminfo()
        mem_pct = None
        if mem_total and mem_avail:
            mem_pct = 100.0 * (1.0 - (mem_avail / mem_total))

        la = read_proc_loadavg()
        la_s = f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}" if la else "n/a"

        if cpu_pct is None:
            cpu_s = "n/a"
        else:
            cpu_s = f"{cpu_pct:.1f}%"
        if mem_pct is None:
            mem_s = "n/a"
        else:
            mem_s = f"{mem_pct:.1f}%"

        print(f"[MON] cpu={cpu_s} mem={mem_s} loadavg={la_s}", flush=True)
        time.sleep(interval_s)


# --------- Summary ---------

def print_summary(all_stats: List[DeviceStats], elapsed_s: float):
    all_dns = []
    all_http = []

    dns_total = dns_blocked = 0
    http_total = http_blocked = 0

    good_dns_total = good_dns_blocked = 0
    bad_dns_total = bad_dns_blocked = 0

    good_http_total = good_http_blocked = 0
    bad_http_total = bad_http_blocked = 0

    errors = 0

    for s in all_stats:
        all_dns.extend(s.dns_latencies)
        all_http.extend(s.http_latencies)
        dns_total += s.dns_total
        dns_blocked += s.dns_blocked
        http_total += s.http_total
        http_blocked += s.http_blocked

        good_dns_total += s.good_dns_total
        good_dns_blocked += s.good_dns_blocked
        bad_dns_total += s.bad_dns_total
        bad_dns_blocked += s.bad_dns_blocked

        good_http_total += s.good_http_total
        good_http_blocked += s.good_http_blocked
        bad_http_total += s.bad_http_total
        bad_http_blocked += s.bad_http_blocked

        errors += s.errors

    print("\n===== RUN SUMMARY =====")
    print(f"Elapsed: {elapsed_s:.2f}s")
    if elapsed_s > 0:
        print(f"Throughput (DNS):  {dns_total/elapsed_s:.2f} qps")
        print(f"Throughput (HTTP): {http_total/elapsed_s:.2f} rps")
    print(f"Errors: {errors}\n")

    print("===== DNS Performance =====\n")
    fmt_stats(all_dns, "DNS latency")
    if dns_total:
        print("DNS blocking summary:")
        print(f"  total queries       = {dns_total}")
        print(f"  blocked             = {dns_blocked} ({dns_blocked/dns_total*100:.2f}%)")
        print(f"  good queries        = {good_dns_total} (blocked: {good_dns_blocked})")
        print(f"  bad  queries        = {bad_dns_total} (blocked: {bad_dns_blocked})")
    print()

    print("===== HTTPS via Proxy Performance =====\n")
    fmt_stats(all_http, "HTTPS latency via Squid")
    if http_total:
        print("HTTPS blocking summary:")
        print(f"  total requests      = {http_total}")
        print(f"  blocked             = {http_blocked} ({http_blocked/http_total*100:.2f}%)")
        print(f"  good requests       = {good_http_total} (blocked: {good_http_blocked})")
        print(f"  bad  requests       = {bad_http_total} (blocked: {bad_http_blocked})")
    print()


# --------- Main ---------

def main():
    p = argparse.ArgumentParser(description="SME endpoint simulator for Pi-hole + Squid.")
    p.add_argument("--dns", default="127.0.0.1", help="Pi-hole DNS IP (default 127.0.0.1)")
    p.add_argument("--proxy", default="http://127.0.0.1:3128", help="Squid proxy URL")
    p.add_argument("--devices", type=int, default=15, help="Number of simulated endpoints (default 15)")
    p.add_argument("--requests", type=int, default=50, help="Request cycles per endpoint (default 50)")
    p.add_argument("--bad-fraction", type=float, default=0.0, help="Fraction of requests to bad IoC (0..1)")

    p.add_argument("--bad-domain", default=BAD_DOMAIN_DEFAULT, help="Bad domain (should be blocked)")
    p.add_argument("--bad-url", default=BAD_URL_DEFAULT, help="Bad URL (should be blocked)")

    p.add_argument("--think-ms-min", type=int, default=50, help="Min think time between cycles (ms)")
    p.add_argument("--think-ms-max", type=int, default=250, help="Max think time between cycles (ms)")
    p.add_argument("--burst", type=int, default=1, help="Do N cycles quickly, then longer pause (default 1=off)")

    p.add_argument("--ramp-up", type=float, default=0.0, help="Ramp up endpoints over N seconds (default 0)")
    p.add_argument("--use-nslookup", action="store_true", help="Use nslookup for DNS (slower, closer to original)")

    p.add_argument("--cpu-load", type=float, default=0.0, help="Approx CPU %% of ONE core to burn per endpoint (0..100)")
    p.add_argument("--mem-mb", type=int, default=0, help="MB of RAM to allocate per endpoint")

    p.add_argument("--monitor-interval", type=float, default=0.0, help="Print system CPU/mem every N seconds (0=off)")
    p.add_argument("--curl-verify-tls", action="store_true",
                   help="Verify TLS in curl (requires your Squid CA trusted). Default is -k (no verify).")

    args = p.parse_args()

    print("[*] SME load test config:")
    print(f"    dns              = {args.dns}")
    print(f"    proxy            = {args.proxy}")
    print(f"    devices          = {args.devices}")
    print(f"    requests/device  = {args.requests}")
    print(f"    bad-fraction     = {args.bad_fraction}")
    print(f"    think(ms)        = {args.think_ms_min}..{args.think_ms_max}")
    print(f"    burst            = {args.burst}")
    print(f"    ramp-up(s)       = {args.ramp_up}")
    print(f"    cpu-load/device  = {args.cpu_load}%")
    print(f"    mem-mb/device    = {args.mem_mb}")
    print(f"    dns mode         = {'nslookup' if args.use_nslookup else 'udp-minimal'}")
    print(f"    curl TLS verify  = {args.curl_verify_tls}")
    if args.monitor_interval > 0:
        print(f"    monitor interval = {args.monitor_interval}s")
    print()

    # Monitoring
    stop_mon = threading.Event()
    mon_thread = None
    if args.monitor_interval and args.monitor_interval > 0:
        mon_thread = threading.Thread(target=monitor_system, args=(stop_mon, args.monitor_interval), daemon=True)
        mon_thread.start()

    # Start devices
    threads = []
    stats_list: List[DeviceStats] = []
    stop_cpu = []
    mem_holders = []

    start = time.monotonic()

    for i in range(args.devices):
        rng = random.Random(i * 99991 + 7)
        ident = DeviceIdentity(
            device_id=i,
            hostname=f"sme-pc-{i:02d}",
            mac=random_mac(rng),
            user_agent=f"SME-Endpoint/{i} ({os.uname().sysname})",
        )

        # optional per-device mem load
        mem_holders.append(alloc_memory(args.mem_mb))

        # optional per-device cpu burn thread
        cpu_stop = threading.Event()
        stop_cpu.append(cpu_stop)
        if args.cpu_load and args.cpu_load > 0:
            threading.Thread(target=cpu_burn, args=(cpu_stop, args.cpu_load), daemon=True).start()

        s = DeviceStats()
        stats_list.append(s)

        t = threading.Thread(
            target=simulate_device,
            args=(
                ident,
                args.dns,
                args.proxy,
                args.bad_domain,
                args.bad_url,
                args.requests,
                args.bad_fraction,
                s,
                args.think_ms_min,
                args.think_ms_max,
                max(1, args.burst),
                args.use_nslookup,
                args.curl_verify_tls,
            ),
            daemon=True,
        )
        threads.append(t)

        # ramp-up control
        if args.ramp_up and args.ramp_up > 0 and args.devices > 1:
            delay = args.ramp_up / args.devices
            time.sleep(delay)

        t.start()

    for t in threads:
        t.join()

    end = time.monotonic()

    # Stop CPU burners + monitor
    for ev in stop_cpu:
        ev.set()
    stop_mon.set()

    elapsed = end - start
    print(f"[*] Load test completed in {elapsed:.2f} seconds.\n")
    print_summary(stats_list, elapsed)


if __name__ == "__main__":
    main()
