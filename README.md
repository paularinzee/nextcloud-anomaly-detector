# Anomaly Detection Engine

A real-time HTTP anomaly-detection daemon that watches Nginx access logs in
front of a Nextcloud server, learns what normal traffic looks like from a
rolling 30-minute baseline, and reacts to deviations — banning aggressive
IPs via `iptables` and alerting Slack on global spikes.

> **Live grading endpoints**
>
> | What           | Where                                                          |
> | -------------- | -------------------------------------------------------------- |
> | Nextcloud (IP) | `http://16.16.137.81/`                                          |
> | Dashboard      | `https://devops.dh.credianlab.xyz/`                           |
> | Repo           | <https://github.com/paularinzee/nextcloud-anomaly-detector>         |


---

## Table of contents

1. [What this is](#what-this-is)
2. [Repository layout](#repository-layout)
3. [How the daemon works](#how-the-daemon-works)
   - [Sliding window](#sliding-window)
   - [Rolling baseline](#rolling-baseline)
   - [Detection logic](#detection-logic)
   - [Banning & backoff](#banning--backoff)
4. [Local setup (Windows / macOS / Linux dev)](#local-setup)
5. [Production deployment on a fresh VPS](#production-deployment)
6. [Testing the detection logic](#testing-the-detection-logic)
7. [Configuration reference](#configuration-reference)
8. [Required screenshots](#required-screenshots)
9. [Troubleshooting](#troubleshooting)
10. [Language choice](#language-choice)

---


## Repository layout

```
detector/
  main.py            # entrypoint — wires & runs the asyncio tasks
  monitor.py         # tails the Nginx JSON access log
  baseline.py        # 30-min rolling baseline + per-hour slots
  detector.py        # 60-s sliding windows + decision rule
  blocker.py         # iptables DROP + state persistence
  unbanner.py        # backoff release scheduler
  notifier.py        # Slack incoming-webhook client
  dashboard.py       # FastAPI dashboard (HTML + /api/state)
  config.yaml        # ALL thresholds live here
  requirements.txt
  Dockerfile
nginx/
  nginx.conf         # JSON logs + X-Forwarded-For trust
docs/
  architecture.png   # (you add this)
screenshots/         # (filled during the live run)
scripts/
  traffic_gen.py     # local traffic generator for testing
docker-compose.yml   # nginx + nextcloud + db + detector
.env.example
README.md
```

---

## How the daemon works

```
                 +-------------+
   Internet ---->|   Nginx     |---- proxy_pass ----> Nextcloud (PHP)
                 |  (JSON log) |
                 +------+------+
                        |  appends one JSON object per request
                        v
            +--------------------------+
            | volume: HNG-nginx-logs   |  (RW for nginx; RO for nextcloud + detector)
            +--------------------------+
                        |
                        v
              +---------+---------+
              |  detector daemon  |  (asyncio, Python)
              |                   |
              |  monitor    -- tails the log, parses JSON
              |    |
              |    v
              |  detector  -- per-IP & global sliding windows (deques)
              |    |             +---- baseline.effective() -> mean, stddev
              |    |             |
              |    v             v
              |  blocker  ---- iptables -I INPUT -s <ip> -j DROP
              |    |
              |    v
              |  notifier ---- Slack incoming webhook
              |
              |  dashboard ---- FastAPI on :8080  (refreshes every 3s)
              |  unbanner  ---- backoff release scheduler
              +-------------------+
```



---

## Local setup

This is the recommended development workflow on Windows / macOS / Linux.
Everything runs in Docker; no Python install required on the host.

### 1. Prerequisites

- Docker Desktop (or Docker Engine + Compose v2 on Linux)
- ~2 GB free RAM
- Port `80` and `8080` free on the host

### 2. Configure secrets

```bash
cp .env.example .env
# edit .env and set MYSQL_* passwords. SLACK_WEBHOOK_URL is optional —
# leave blank and alerts will be logged to stdout instead of posted.
```

### 3. Bring the stack up

```bash
docker compose up -d --build
docker compose ps
```

You should see four services running: `db`, `nextcloud`, `nginx`, `detector`.

### 4. Verify Nginx is serving and writing JSON logs

```bash
curl -s http://localhost/healthz   # -> "ok"
docker compose exec nginx tail -n 5 /var/log/nginx/hng-access.log
```

The log lines must look like:

```json
{
  "source_ip": "172.18.0.1",
  "timestamp": "2026-04-27T08:00:01+00:00",
  "method": "GET",
  "path": "/healthz",
  "status": 200,
  "response_size": 3,
  "user_agent": "curl/8.4.0",
  "xff": ""
}
```

### 5. Open the dashboard

<http://localhost:8080>

It should show 0 banned IPs, the floor baseline, and your recent
healthcheck request in the top-IPs panel.

### 6. Watch the detector logs

```bash
docker compose logs -f detector
```

> **About iptables in local dev**: the detector container has `NET_ADMIN`
> but is on a bridge network, so any `iptables -I` it issues only affects
> its own network namespace — it will NOT block traffic to Nginx. That's
> why `iptables_dry_run` defaults to `false` (we want the audit/Slack
> entries to be created), but the actual rule is harmless. For real
> enforcement you must move the detector to `network_mode: host` on a
> Linux VPS — see the next section.

---

## Production deployment

The dashboard is served at **`devops.hng.credianlab.xyz`**. Nextcloud
stays on the bare server IP per the spec. The compose files are already
wired for this — no manual edits required for the detector, nginx, or
the upstream port. You only edit `.env` and (optionally) the certbot
email.

### 1. Provision a VPS

- Linux (Ubuntu 22.04 / 24.04 LTS recommended)
- Minimum: 2 vCPU, 2 GB RAM
- Inbound firewall ports: `22`, `80`, `443`
- Note the public IP — call it `<SERVER_IP>` below.

### 2. Point DNS at the VPS

In your DNS provider for `credianlab.xyz`, create one A record:

```
devops.hng    A    <SERVER_IP>    (TTL 300)
```

If you're using Cloudflare and want it to terminate TLS for free, leave
the orange-cloud proxy **on** and skip the certbot step entirely.

### 3. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

### 4. Clone & configure

```bash
git clone https://github.com/paularinzee/nextcloud-anomaly-detector
cd nextcloud-anomaly-detector
cp .env.example .env
nano .env
```

In `.env`, set:

```env
MYSQL_ROOT_PASSWORD=<strong random>
MYSQL_PASSWORD=<strong random>
NEXTCLOUD_TRUSTED_DOMAINS=<SERVER_IP>
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### 5. Allowlist your SSH IP

Edit [`detector/config.yaml`](detector/config.yaml) and add your
workstation's public IP under `allowlist:` so you can never ban yourself.
Find it from your laptop with `curl ifconfig.me`.

```yaml
allowlist:
  - "127.0.0.1"
  - "::1"
  - "<YOUR_PUBLIC_IP>"
```

### 6. Bring the stack up (HTTP only, first time)

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose ps
```

The production override does two things automatically:

- Switches the detector to `network_mode: host` so its iptables rules
  apply to **real** inbound traffic (a bridge-network container can only
  rewrite its own namespace).
- Adds a one-shot `certbot` service (gated behind the `init` profile)
  ready for step 7.

You should now be able to reach:

- `http://16.16.137.81/` — Nextcloud setup wizard
- `http://devops.hng.credianlab.xyz/` — the live dashboard

### 7. Get a TLS certificate (skip if Cloudflare proxy is on)

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile init run --rm certbot
```

This issues a Let's Encrypt cert via the HTTP-01 challenge and writes it
into the `certbot-certs` volume that nginx already mounts read-only.

After it succeeds, **uncomment the TLS server block** at the bottom of
[`nginx/nginx.conf`](nginx/nginx.conf) (look for `# server { listen 443
ssl ...`), then reload nginx without restarting:

```bash
docker compose exec nginx nginx -t            # validate first
docker compose exec nginx nginx -s reload
```

`https://devops.dh.credianlab.xyz/` should now load with a valid cert.

> **Renewal**: rerun the `certbot` profile every ~60 days, then
> `nginx -s reload`. Or set up a cron job — see the
> [Renewing a cert](#renewing-a-cert) section below.

### 8. Smoke-test detection + enforcement

From a different machine (NOT your allowlisted SSH IP):

```bash
for i in $(seq 1 200); do curl -s -o /dev/null http://16.16.137.81/ ; done
```

Within ~10 s you should see:

- Slack ban notification
- The IP appear in the dashboard's "Banned IPs" panel
- `sudo iptables -L INPUT -n | grep DROP` show the offending IP

### Stopping and bringing it back

To **stop** the stack (keeps volumes + data):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml stop
```

To **start** it again (no rebuild, ~5 seconds):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml start
```

To **stop AND remove containers** (still keeps volumes):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml down
```

### Renewing a cert

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile init run --rm certbot renew
docker compose exec nginx nginx -s reload
```

Drop both lines into a weekly cron and you'll never deal with TLS again.

---

## Testing the detection logic

A small traffic generator lives at
[`scripts/traffic_gen.py`](scripts/traffic_gen.py). It sets
`X-Forwarded-For` so you can simulate many distinct clients from one
machine (Nginx is configured to trust XFF — see `nginx/nginx.conf`).

### A — establish a baseline

Let the stack idle for a couple of minutes, then trickle traffic in:

```bash
python scripts/traffic_gen.py --rps 1 --duration 300 --xff 10.0.0.5
```

Watch the dashboard. After ~30 s of samples, the **effective baseline**
mean should rise off the floor (`1.000`) toward your trickle rate.

### B — trip a per-IP ban (z-score path)

```bash
python scripts/traffic_gen.py --rps 50 --duration 30 --xff 203.0.113.66
```

Within ~2 s the detector should fire a ban on `203.0.113.66`:

- `docker compose logs -f detector` shows `IP anomaly 203.0.113.66 ...`
- Slack receives an `:no_entry: IP banned` message
- The audit log gets a `[ts] BAN 203.0.113.66 | per_ip rate=... | ... | duration=600s` line
- The dashboard shows 1 banned IP with release time

### C — trip a global anomaly (alert-only)

```bash
python scripts/traffic_gen.py --rps 30 --duration 60 --rotate-xff 30
```

30 distinct IPs each at 1 req/s = ~30 req/s globally, well above any
sane baseline. Each IP stays under its own per-IP threshold, but the
global rate fires:

- Slack receives a `:rotating_light: Global anomaly` alert
- The audit log gets a `GLOBAL_ALERT` line
- No ban happens (correct — the spec specifies global = alert only)

### D — watch the auto-unban

The first per-IP ban lasts 10 min. After that, the unbanner sweep should:

- Run `iptables -D ...` (visible with `docker compose logs detector`)
- Send `:white_check_mark: IP unbanned` to Slack
- Append an `UNBAN ...` row to the audit log

---

## Configuration reference

All knobs live in [`detector/config.yaml`](detector/config.yaml). The
defaults match the spec — you should only need to touch `allowlist`,
`slack_webhook_url`, and (in production) `iptables_dry_run`.

| Key                                 | Default                         | Meaning                                                                   |
| ----------------------------------- | ------------------------------- | ------------------------------------------------------------------------- |
| `window_seconds`                    | 60                              | Sliding-window length for current rate.                                   |
| `baseline_window_seconds`           | 1800                            | Rolling baseline window (30 min).                                         |
| `recalc_interval_seconds`           | 60                              | How often to recompute mean/stddev.                                       |
| `floor_mean` / `floor_stddev`       | 1.0 / 0.5                       | Cold-start floor (NOT a hardcoded baseline — replaced once data arrives). |
| `min_slot_samples`                  | 5                               | Recalc cycles needed in a hour-slot before it's preferred.                |
| `min_global_samples`                | 30                              | Per-second samples needed before global stats outrank the floor.          |
| `z_score_threshold`                 | 3.0                             | Anomaly if `(rate - mean) / stddev` exceeds this.                         |
| `rate_multiplier`                   | 5.0                             | Anomaly if `rate > N * mean`.                                             |
| `error_rate_multiplier`             | 3.0                             | If an IP's err rate ≥ N × baseline err mean → tightened.                  |
| `tightened_rate_multiplier`         | 3.0                             | Stricter multiplier used after error-surge tightening.                    |
| `ban_schedule_seconds`              | `[600, 1800, 7200]`             | 10 min → 30 min → 2 hr, then permanent.                                   |
| `unban_poll_seconds`                | 10                              | Sweep interval for releasing expired bans.                                |
| `iptables_dry_run`                  | `false`                         | Don't shell out to iptables (auto-true if binary missing).                |
| `iptables_chain`                    | `INPUT`                         | Chain to insert DROP rules into.                                          |
| `global_alert_cooldown_seconds`     | 30                              | Min seconds between Slack global alerts.                                  |
| `allowlist`                         | `[127.0.0.1, ::1]`              | IPs that are never banned. **Add your SSH IP here.**                      |
| `slack_webhook_url`                 | `""`                            | Slack incoming webhook. Override via `SLACK_WEBHOOK_URL` env var.         |
| `log_path`                          | `/var/log/nginx/hng-access.log` | Path the monitor tails.                                                   |
| `audit_log_path`                    | `/var/log/detector/audit.log`   | Where to write `BAN`/`UNBAN`/`BASELINE_RECALC` lines.                     |
| `state_path`                        | `/var/lib/detector/state.json`  | Persistent ban state.                                                     |
| `dashboard_host` / `dashboard_port` | `0.0.0.0` / `8080`              | Dashboard bind address.                                                   |

---

## Required screenshots

Capture and save into [`screenshots/`](screenshots/):

| File                     | What to capture                                                               |
| ------------------------ | ----------------------------------------------------------------------------- |
| `Tool-running.png`       | `docker compose logs -f detector` — daemon processing log lines.              |
| `Ban-slack.png`          | The `:no_entry: IP banned` message in your Slack channel.                     |
| `Unban-slack.png`        | The `:white_check_mark: IP unbanned` message.                                 |
| `Global-alert-slack.png` | The `:rotating_light: Global anomaly` message.                                |
| `Iptables-banned.png`    | `sudo iptables -L INPUT -n` showing the DROP rule for the banned IP.          |
| `Audit-log.png`          | `tail -n 50 audit.log` showing `BAN`, `UNBAN`, and `BASELINE_RECALC` lines.   |
| `Baseline-graph.png`     | The dashboard's baseline chart, showing at least two distinct hour-slot dots. |

To get `Baseline-graph.png` quickly, run the traffic generator at two
different rates across an hour boundary, or temporarily lower
`recalc_interval_seconds` to 5 s and let the stack run during the next
hour rollover.

---

## Troubleshooting

**Detector logs show "log file not present yet; retrying"**
Nginx hasn't created the file. Hit `curl http://localhost/` once and it'll
appear.

**`source_ip` in logs is the docker bridge address (`172.18.0.x`)**
You're testing with `curl http://localhost/` from the host. That IS the
real client IP from Nginx's perspective. To simulate other clients, use
`scripts/traffic_gen.py --xff <ip>`.

**Bans appear in audit log but `iptables -L` shows nothing on the host**
You're in dry-run mode, OR the detector is on a bridge network (not host).
See section 5 of [Production deployment](#production-deployment).

**Slack messages don't appear**
`SLACK_WEBHOOK_URL` not set, OR not exported to compose. Check
`docker compose exec detector env | grep SLACK`. The webhook URL must
start with `https://hooks.slack.com/services/...`.

**I banned myself**
SSH back in (different IP) or, on the VPS console:
`sudo iptables -F INPUT` (flushes all rules — only safe in dev).
Then add your IP to `allowlist:` in `config.yaml` and `docker compose
restart detector`.

**XFF spoofing**
Nginx only honors `X-Forwarded-For` from RFC1918 ranges + Cloudflare's
edge CIDRs (see [`nginx/nginx.conf`](nginx/nginx.conf)). If you front
the dashboard with a different CDN, add its CIDR to the
`set_real_ip_from` list — otherwise its requests will appear to come
from the proxy IP, not the real client, and the detector won't be able
to ban individual offenders.

---

## Language choice

Python — chosen for two reasons:

1. The standard library's `collections.deque` and `statistics` modules
   provide everything we need for the sliding window and the rolling
   baseline, with no external dependencies for the core algorithm. The
   only third-party packages are for HTTP I/O (`aiohttp`, `fastapi`,
   `uvicorn`) and process metrics (`psutil`).
2. `asyncio` lets the log tailer, detector, baseline recalc loop,
   unbanner, dashboard, and Slack notifier all live in a single process
   on one event loop — minimal moving parts, easy to reason about, easy
   to ship as a single container.

---
