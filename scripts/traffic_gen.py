"""
Tiny traffic generator for local testing.

Examples
--------
# Baseline traffic — 1 req/s for 5 minutes from a single fake IP
python scripts/traffic_gen.py --rps 1 --duration 300 --xff 10.0.0.5

# Burst attack — 50 req/s for 30 seconds from a different fake IP
python scripts/traffic_gen.py --rps 50 --duration 30 --xff 203.0.113.66

# Rotate through several fake IPs (helps test the global anomaly path
# without any one IP getting banned)
python scripts/traffic_gen.py --rps 30 --duration 60 --rotate-xff 20

Notes
-----
Set --xff to make Nginx see a chosen client IP via X-Forwarded-For (only
trustworthy because nginx.conf trusts XFF from any source — fine for local
dev, not for production).
"""
import argparse
import random
import sys
import time
import urllib.error
import urllib.request


def main() -> int:
    """Run a simple request loop for testing detector thresholds locally.

    The script can send traffic from one synthetic X-Forwarded-For address or
    rotate through many addresses. It prints a summary of successful and failed
    requests so test runs can be compared with dashboard/Slack behavior.
    """
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost/", help="target URL")
    p.add_argument("--rps", type=float, default=1.0, help="requests per second")
    p.add_argument("--duration", type=int, default=60, help="seconds to run")
    p.add_argument("--xff", default=None,
                   help="single X-Forwarded-For value to send")
    p.add_argument("--rotate-xff", type=int, default=0,
                   help="rotate through N synthetic XFF IPs (overrides --xff)")
    args = p.parse_args()

    if args.rotate_xff > 0:
        ips = [f"198.51.100.{i+1}" for i in range(args.rotate_xff)]
    elif args.xff:
        ips = [args.xff]
    else:
        ips = [None]

    interval = 1.0 / args.rps if args.rps > 0 else 0
    end = time.time() + args.duration
    sent = ok = err = 0
    print(f"sending ~{args.rps} req/s to {args.url} for {args.duration}s "
          f"(xff pool: {len(ips)})")

    while time.time() < end:
        ip = random.choice(ips)
        req = urllib.request.Request(args.url)
        if ip:
            req.add_header("X-Forwarded-For", ip)
        try:
            urllib.request.urlopen(req, timeout=5).read()
            ok += 1
        except urllib.error.HTTPError:
            err += 1  # 4xx/5xx still counts as a request (and as an error)
        except Exception as e:  # noqa: BLE001
            err += 1
            if sent < 5:
                print("err:", e, file=sys.stderr)
        sent += 1
        if interval > 0:
            time.sleep(interval)

    print(f"done. sent={sent} ok={ok} err={err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
