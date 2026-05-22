"""
iptables-based blocker with persistent state.

A ban inserts a DROP rule into the configured chain (default INPUT) for
the offending source IP. State is mirrored to a JSON file so a daemon
restart doesn't lose the ban schedule.

Backoff
-------
On each new ban for the same IP we step through `ban_schedule_seconds`
(default [600, 1800, 7200] = 10 min, 30 min, 2 hr). Once we've exhausted
the schedule, the next ban is permanent (`unban_at = None`).

Dry-run
-------
If `iptables_dry_run: true` in config, or if the iptables binary isn't
available (e.g. local Windows dev), we skip the subprocess call and just
log what we would have done. State and audit-log entries are still
written, so the rest of the system behaves identically.
"""
import asyncio
import json
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path
from threading import Lock

log = logging.getLogger("blocker")


class Blocker:
    def __init__(self, cfg, audit, notifier):
        """Create the ban manager and prepare persistent state storage.

        The blocker owns the in-memory ban table, mirrors it to state.json, and
        executes iptables mutations unless dry-run mode is enabled.
        """
        self.audit = audit
        self.notifier = notifier
        self.dry_run = bool(cfg.get("iptables_dry_run", False))
        self.chain = cfg.get("iptables_chain", "INPUT")
        self.schedule = list(cfg["ban_schedule_seconds"])
        self.state_path = Path(cfg["state_path"])
        self.allowlist = set(cfg.get("allowlist", []))
        self._lock = Lock()
        self.bans: dict = {}
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

    # --- state persistence ---------------------------------------------

    async def load_state(self) -> None:
        """Load previously persisted bans from disk after daemon startup.

        This lets the service remember active bans and escalation counts across
        container restarts without losing the unban schedule.
        """
        if not self.state_path.exists():
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                self.bans = data.get("bans", {})
            log.info("loaded %d bans from %s", len(self.bans), self.state_path)
        except Exception as e:  # noqa: BLE001
            log.warning("could not load state: %s", e)

    def _save_state(self) -> None:
        """Atomically write the current ban table to state.json.

        A temporary file is written first and then moved into place so crashes do
        not leave a partially written JSON file behind.
        """
        try:
            tmp = self.state_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"bans": self.bans}, f, indent=2)
            tmp.replace(self.state_path)
        except Exception as e:  # noqa: BLE001
            log.warning("could not save state: %s", e)

    # --- public API -----------------------------------------------------

    def is_banned(self, ip: str) -> bool:
        """Return True when the given IP currently has an active ban record."""
        with self._lock:
            rec = self.bans.get(ip)
            return bool(rec and rec.get("status") == "banned")

    def _next_duration(self, ban_count: int) -> int:
        """Return seconds for the next ban, or -1 for permanent."""
        if ban_count >= len(self.schedule):
            return -1
        return int(self.schedule[ban_count])

    async def ban(self, ip: str, condition: str, rate: float, baseline: float) -> int:
        """Ban an IP, persist the updated record, and install the DROP rule.

        The ban duration follows the configured backoff schedule. The returned
        value is the duration in seconds, or -1 when the new ban is permanent.
        Allowlisted IPs are ignored and return 0.
        """
        if ip in self.allowlist:
            log.info("skipping ban; %s is allowlisted", ip)
            return 0

        now = time.time()
        with self._lock:
            rec = self.bans.get(ip, {"first_banned_at": now, "ban_count": 0})
            count = rec.get("ban_count", 0)
            duration = self._next_duration(count)

            rec["ban_count"] = count + 1
            rec["last_banned_at"] = now
            rec["last_condition"] = condition
            rec["last_rate"] = rate
            rec["last_baseline"] = baseline
            rec["status"] = "banned"
            rec["unban_at"] = None if duration < 0 else now + duration
            self.bans[ip] = rec
            self._save_state()

        self._iptables_add(ip)
        log.info(
            "banned %s for %s (count=%d)",
            ip,
            "PERMANENT" if duration < 0 else f"{duration}s",
            rec["ban_count"],
        )
        return duration

    async def unban(self, ip: str) -> bool:
        """Release an active ban, persist state, remove iptables rules, and audit.

        Returns True only when the IP was actively banned and was transitioned to
        released. Missing or already released records are treated as no-ops.
        """
        with self._lock:
            rec = self.bans.get(ip)
            if not rec or rec.get("status") != "banned":
                return False
            rec["status"] = "released"
            rec["unban_at"] = None
            rec["last_unbanned_at"] = time.time()
            self._save_state()

        self._iptables_del(ip)
        ts = datetime.now().isoformat(timespec="seconds")
        self.audit.info(
            f"[{ts}] UNBAN {ip} | scheduled_release"
            f" | rate=N/A | baseline=N/A | duration=N/A"
        )
        log.info("unbanned %s", ip)
        return True

    def due_for_unban(self, now: float) -> list[str]:
        """IPs whose timed ban has expired and should be released."""
        with self._lock:
            return [
                ip
                for ip, r in self.bans.items()
                if r.get("status") == "banned"
                and r.get("unban_at") is not None
                and r["unban_at"] <= now
            ]

    def banned_list(self) -> list[dict]:
        """Return dashboard-friendly summaries of currently banned IPs."""
        with self._lock:
            return [
                {
                    "ip": ip,
                    "ban_count": r.get("ban_count", 0),
                    "last_condition": r.get("last_condition", ""),
                    "unban_at": r.get("unban_at"),
                }
                for ip, r in self.bans.items()
                if r.get("status") == "banned"
            ]

    # --- iptables -------------------------------------------------------

    def _iptables_add(self, ip: str) -> None:
        """Insert a DROP rule at the top of the configured iptables chain."""
        self._run(["iptables", "-I", self.chain, "1", "-s", ip, "-j", "DROP"])

    def _iptables_del(self, ip: str) -> None:
        """Remove DROP rules for an IP from the configured iptables chain."""
        # Loop in case multiple identical rules exist (defensive).
        for _ in range(5):
            r = self._run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                ok_codes=(0, 1, 2),
            )
            if r is None or r.returncode != 0:
                break

    def _run(self, cmd, ok_codes=(0,)):
        """Run an iptables command while honoring dry-run and accepted exit codes.

        If iptables is unavailable, the blocker falls back to dry-run mode so
        local development keeps working and the daemon does not crash.
        """
        if self.dry_run:
            log.info("[dry-run] %s", " ".join(cmd))
            return None
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode not in ok_codes:
                log.warning(
                    "iptables exit=%d cmd=%s stderr=%s",
                    r.returncode, " ".join(cmd), r.stderr.strip(),
                )
            return r
        except FileNotFoundError:
            log.warning("iptables binary not found; switching to dry-run mode")
            self.dry_run = True
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("iptables error: %s", e)
            return None
