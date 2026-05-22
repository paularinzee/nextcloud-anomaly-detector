"""
Anomaly detection — per-IP and global sliding windows + decision logic.

Sliding windows
---------------
Two deques of timestamps each cover the last `window_seconds` seconds
(default 60). On every event we append, then drop everything older than
`now - window_seconds`. The current rate (req/s) is `len(deque) / window`.

  * `_global` is one deque for ALL traffic.
  * `_per_ip[ip]` is one deque per source IP.
  * `_per_ip_err[ip]` tracks 4xx/5xx for that IP — used by the
    error-surge tightening rule.

Decision rule
-------------
Whichever fires first counts as an anomaly:

    z_score = (rate - baseline_mean) / baseline_stddev   > z_threshold
    rate > rate_multiplier * baseline_mean

Error-surge tightening
----------------------
If the IP's 4xx/5xx rate is >= `error_rate_multiplier` * baseline error
mean, we use a stricter `tightened_rate_multiplier` for that IP.

Allowlist & cooldown
--------------------
Allowlisted IPs are never banned. Global alerts are throttled to no more
than once per `global_alert_cooldown_seconds` so we don't spam Slack
during a sustained spike.
"""
import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime

log = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, cfg, baseline, blocker, notifier, audit):
        """Initialize sliding-window state and attach collaborator services.

        The detector receives normalized events from LogMonitor, compares rates
        against Baseline, asks Blocker to ban per-IP offenders, and asks Notifier
        to send Slack messages for global/per-IP anomalies.
        """
        self.window_s = int(cfg["window_seconds"])
        self.z_thresh = float(cfg["z_score_threshold"])
        self.rate_mult = float(cfg["rate_multiplier"])
        self.tight_mult = float(cfg["tightened_rate_multiplier"])
        self.err_mult = float(cfg["error_rate_multiplier"])
        self.allowlist = set(cfg.get("allowlist", []))
        self.global_cooldown = float(cfg.get("global_alert_cooldown_seconds", 30))
        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier
        self.audit = audit

        self._global: deque = deque()
        self._per_ip: dict = defaultdict(deque)
        self._per_ip_err: dict = defaultdict(deque)

        # for the dashboard
        self.recent_alerts: deque = deque(maxlen=50)
        self._last_global_alert = 0.0
        self._last_prune = time.time()
        self._prune_interval_s = 60

    # --- main loop ------------------------------------------------------

    async def run(self, queue: asyncio.Queue) -> None:
        """Consume access-log events forever and process each through the detector.

        Exceptions from one event are logged and isolated so a malformed record or
        transient dependency issue does not stop detection for later events.
        """
        while True:
            evt = await queue.get()
            try:
                await self._handle(evt)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.exception("handler error: %s", e)

    async def _handle(self, evt) -> None:
        """Update windows for one event and decide whether it is anomalous.

        This is the hot path. Order of operations:
          1. Drop banned-IP traffic so it never reaches the baseline.
          2. Record the request into the rolling baseline.
          3. Update global and per-IP sliding windows.
          4. Allowlisted IPs short-circuit before the per-IP rate check.
          5. Evaluate z-score and multiplier thresholds; fire alerts if tripped.
          6. Always check the global window and run periodic pruning.
        """
        ip = evt["ip"]
        status = evt["status"]
        now = time.time()

        # Skip banned IPs entirely so post-ban packets (e.g. on the bridge
        # network where iptables is in the container's own netns) don't
        # inflate the baseline and desensitize the detector to the next wave.
        if self.blocker.is_banned(ip):
            return

        # The baseline counts every legitimate request (allowlist included)
        # so it reflects total real traffic.
        self.baseline.record(status)

        # Global window
        self._global.append(now)
        self._evict(self._global, now)

        # Per-IP window
        ipw = self._per_ip[ip]
        ipw.append(now)
        self._evict(ipw, now)

        if status >= 400:
            ipe = self._per_ip_err[ip]
            ipe.append(now)
            self._evict(ipe, now)

        # Allowlist short-circuit (still updates global stats above).
        if ip in self.allowlist:
            self._maybe_global(now)
            return

        mean, stddev = self.baseline.effective()
        err_mean, _ = self.baseline.effective_error()

        ip_rate = len(ipw) / self.window_s
        ip_err_rate = (len(self._per_ip_err.get(ip, [])) / self.window_s)

        # Error-surge tightening
        mult = self.rate_mult
        tightened = False
        if err_mean > 0 and ip_err_rate >= self.err_mult * err_mean and ip_err_rate > 0:
            mult = self.tight_mult
            tightened = True

        z = (ip_rate - mean) / stddev if stddev > 0 else 0.0
        if z > self.z_thresh or ip_rate > mult * mean:
            cond = (
                f"per_ip z={z:.2f}>thresh={self.z_thresh}"
                if z > self.z_thresh
                else f"per_ip rate={ip_rate:.2f}>{mult:.1f}x mean({mean:.2f})"
            )
            if tightened:
                cond += " [error-surge tightened]"
            await self._fire_ip(ip, ip_rate, mean, stddev, cond)

        self._maybe_global(now, mean, stddev)
        self._maybe_prune(now)

    def _maybe_prune(self, now: float) -> None:
        """Drop dict entries for IPs whose windows are empty.

        Without this, a long run with rotating XFFs would accumulate millions
        of stale dict entries, since defaultdict only adds and never removes.
        """
        if now - self._last_prune < self._prune_interval_s:
            return
        self._last_prune = now
        for d in (self._per_ip, self._per_ip_err):
            for ip in list(d.keys()):
                self._evict(d[ip], now)
                if not d[ip]:
                    del d[ip]

    def _maybe_global(self, now: float, mean: float | None = None, stddev: float | None = None) -> None:
        """Check whether aggregate traffic is anomalous and throttle alerts.

        Global anomalies notify Slack and audit logs, but they do not ban an IP
        because no single source is responsible. Alerts are cooldown-limited to
        avoid repeated messages during one sustained spike.
        """
        if mean is None or stddev is None:
            mean, stddev = self.baseline.effective()
        g_rate = len(self._global) / self.window_s
        gz = (g_rate - mean) / stddev if stddev > 0 else 0.0
        if g_rate > self.rate_mult * mean or gz > self.z_thresh:
            if now - self._last_global_alert > self.global_cooldown:
                self._last_global_alert = now
                cond = (
                    f"global z={gz:.2f}>thresh={self.z_thresh}"
                    if gz > self.z_thresh
                    else f"global rate={g_rate:.2f}>{self.rate_mult:.1f}x mean({mean:.2f})"
                )
                # Schedule the notify so we don't block the hot loop on HTTP.
                asyncio.create_task(self._fire_global(g_rate, mean, stddev, cond))

    def _evict(self, dq: deque, now: float) -> None:
        """Remove timestamps that have aged out of the configured sliding window."""
        cutoff = now - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

    # --- handlers -------------------------------------------------------

    async def _fire_ip(self, ip, rate, mean, stddev, condition) -> None:
        """Handle a per-IP anomaly by banning, recording, auditing, and notifying.

        The blocker determines the correct backoff duration. The alert is also
        pushed into recent_alerts so the dashboard can show it immediately.
        """
        ts = datetime.now().isoformat(timespec="seconds")
        log.warning("IP anomaly %s: %s", ip, condition)
        ban_dur = await self.blocker.ban(ip, condition, rate, mean)
        self.recent_alerts.appendleft({
            "ts": ts, "kind": "per_ip", "ip": ip,
            "rate": rate, "baseline": mean, "condition": condition,
        })
        dur_str = "PERMANENT" if ban_dur < 0 else f"{ban_dur}s"
        self.audit.info(
            f"[{ts}] BAN {ip} | {condition} | rate={rate:.2f}"
            f" | baseline_mean={mean:.2f} stddev={stddev:.2f} | duration={dur_str}"
        )
        # Don't await Slack on the hot path — a slow webhook would push
        # the next event's processing past the 10-second SLA.
        asyncio.create_task(
            self.notifier.send_ban(ip, condition, rate, mean, ban_dur)
        )

    async def _fire_global(self, rate, mean, stddev, condition) -> None:
        """Record and notify on a whole-site traffic anomaly.

        Global alerts are informational: they warn operators that total traffic
        is abnormal, but they intentionally do not change iptables rules.
        """
        ts = datetime.now().isoformat(timespec="seconds")
        log.warning("GLOBAL anomaly: %s", condition)
        self.recent_alerts.appendleft({
            "ts": ts, "kind": "global", "ip": "GLOBAL",
            "rate": rate, "baseline": mean, "condition": condition,
        })
        self.audit.info(
            f"[{ts}] GLOBAL_ALERT GLOBAL | {condition} | rate={rate:.2f}"
            f" | baseline_mean={mean:.2f} stddev={stddev:.2f} | duration=N/A"
        )
        await self.notifier.send_global(condition, rate, mean)

    # --- dashboard accessors -------------------------------------------

    def global_rate(self) -> float:
        """Return current aggregate requests per second for dashboard display."""
        now = time.time()
        self._evict(self._global, now)
        return len(self._global) / self.window_s

    def top_ips(self, n: int = 10):
        """Return the busiest source IPs in the current sliding window.

        The result is a list of (ip, request_count) tuples sorted descending and
        capped to the requested dashboard limit.
        """
        now = time.time()
        items = []
        for ip, dq in self._per_ip.items():
            self._evict(dq, now)
            if dq:
                items.append((ip, len(dq)))
        items.sort(key=lambda x: -x[1])
        return items[:n]
