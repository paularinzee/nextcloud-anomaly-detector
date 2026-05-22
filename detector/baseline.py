"""
Rolling baseline.

Idea
----
We treat traffic as a stream of per-second request counts. Every second we
push one (sec_epoch, count) tuple onto a deque, and we drop tuples older
than `baseline_window_seconds` (default 1800 = 30 min). The mean and
population stddev of those counts is our baseline.

Per-hour slots
--------------
Real traffic isn't stationary — 14:00 is busier than 03:00. So in addition
to the global rolling stats, we keep one slot per hour-of-day. Every recalc
cycle (default 60 s) we exponentially blend the global stats into the
current hour's slot. Once a slot has at least `min_slot_samples` cycles in
it, the detector prefers the slot's mean/stddev over the global ones —
that's how the "prefer the current hour's baseline when it has enough
data" rule is satisfied.

Cold start
----------
Before any window has accumulated enough samples, we fall back to the
configured floor (`floor_mean`, `floor_stddev`). These are NOT a hardcoded
baseline — they're a minimum so the detector still reacts to a burst that
arrives in the first few minutes after startup.

Idle handling
-------------
If no requests arrive for a while, `record()` never fires, so the per-second
counts wouldn't otherwise advance. We fix that by having every record() and
every recalc tick call `_catch_up()`, which back-fills any missing seconds
with zero counts.
"""
import asyncio
import json
import logging
import statistics
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from threading import Lock

log = logging.getLogger("baseline")


class Baseline:
    def __init__(self, cfg: dict, audit: logging.Logger):
        """Initialize rolling counters, cold-start floors, and hourly baseline slots.

        The baseline object is shared by the detector hot path and the dashboard,
        so mutable request counters are protected by a lock. Public fields such
        as global_mean/history are updated by the periodic recalculation loop.
        """
        self.window_s = int(cfg["baseline_window_seconds"])
        self.recalc_s = int(cfg["recalc_interval_seconds"])
        self.floor_mean = float(cfg["floor_mean"])
        self.floor_stddev = float(cfg["floor_stddev"])
        self.error_floor_mean = max(0.1, self.floor_mean * 0.1)
        self.error_floor_stddev = max(0.1, self.floor_stddev * 0.1)
        self.min_slot_samples = int(cfg.get("min_slot_samples", 5))
        self.min_global_samples = int(cfg.get("min_global_samples", 30))
        self.audit = audit

        self._lock = Lock()
        self._counts: deque = deque()         # (sec_epoch, count)
        self._error_counts: deque = deque()   # (sec_epoch, 4xx/5xx count)
        self._current_sec = int(time.time())
        self._sec_count = 0
        self._sec_err_count = 0

        # hour-of-day -> {mean, stddev, samples, error_mean, error_stddev}
        self.hourly: dict = defaultdict(self._empty_slot)
        self.global_mean = self.floor_mean
        self.global_stddev = self.floor_stddev
        self.error_mean = self.error_floor_mean
        self.error_stddev = self.error_floor_stddev

        # Persistent hour-slot state lives next to the blocker's state.json
        # so restarts don't throw away an hour of accumulated samples.
        state_dir = Path(cfg["state_path"]).parent
        self._slot_path = state_dir / "baseline_slots.json"
        self._load_slots()

        # for the dashboard chart — capped at ~4 h of recalc points
        self.history: deque = deque(maxlen=240)

    @staticmethod
    def _empty_slot() -> dict:
        return {
            "mean": 0.0,
            "stddev": 0.0,
            "samples": 0,
            "error_mean": 0.0,
            "error_stddev": 0.0,
        }

    def _load_slots(self) -> None:
        """Restore hourly slots from disk so restarts don't lose accumulated history."""
        if not self._slot_path.exists():
            return
        try:
            with open(self._slot_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for hour_str, slot in data.get("hourly", {}).items():
                merged = self._empty_slot()
                merged.update(slot)
                self.hourly[int(hour_str)] = merged
            log.info("loaded %d hour-slots from %s", len(self.hourly), self._slot_path)
        except Exception as e:  # noqa: BLE001
            log.warning("could not load baseline slots: %s", e)

    def _save_slots(self) -> None:
        """Atomically persist hourly slots."""
        try:
            self._slot_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._slot_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(
                    {"hourly": {str(h): s for h, s in self.hourly.items()}},
                    f, indent=2,
                )
            tmp.replace(self._slot_path)
        except Exception as e:  # noqa: BLE001
            log.warning("could not save baseline slots: %s", e)

    # --- ingest ---------------------------------------------------------

    def record(self, status: int) -> None:
        """Record one HTTP request into the current per-second bucket.

        The detector calls this for every parsed Nginx access-log event. It also
        tracks whether the response was a 4xx/5xx so error surges can tighten
        per-IP thresholds later.
        """
        now = int(time.time())
        with self._lock:
            self._catch_up(now)
            self._sec_count += 1
            if status >= 400:
                self._sec_err_count += 1

    def _catch_up(self, now: int) -> None:
        """Flush elapsed seconds into the rolling window and prune stale samples.

        Missing seconds are stored as zero-count buckets, which keeps the mean
        honest during idle periods instead of pretending time stopped.
        """
        while self._current_sec < now:
            self._counts.append((self._current_sec, self._sec_count))
            self._error_counts.append((self._current_sec, self._sec_err_count))
            self._sec_count = 0
            self._sec_err_count = 0
            self._current_sec += 1
        cutoff = now - self.window_s
        while self._counts and self._counts[0][0] < cutoff:
            self._counts.popleft()
        while self._error_counts and self._error_counts[0][0] < cutoff:
            self._error_counts.popleft()

    # --- compute --------------------------------------------------------

    def _snapshot(self) -> tuple[float, float, float, float, int]:
        """Return current request/error mean and stddev from stable snapshots.

        The method copies the deques while holding the lock, then computes stats
        outside the critical section. If there are not enough samples yet, it
        returns configured floor values so the detector has sane defaults.
        """
        with self._lock:
            self._catch_up(int(time.time()))
            counts = [c for _, c in self._counts]
            errs = [c for _, c in self._error_counts]
        if len(counts) >= 2:
            m = statistics.fmean(counts)
            s = statistics.pstdev(counts)
        else:
            m, s = self.floor_mean, self.floor_stddev
        if len(errs) >= 2:
            em = statistics.fmean(errs)
            es = statistics.pstdev(errs)
        else:
            em = self.error_floor_mean
            es = self.error_floor_stddev
        return m, s, em, es, len(counts)

    async def run(self) -> None:
        """Periodic recalc loop — runs forever, recomputing every recalc_interval_seconds."""
        while True:
            await asyncio.sleep(self.recalc_s)
            try:
                self._recalc_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.exception("recalc failed: %s", e)

    def _recalc_once(self) -> None:
        """Recompute global stats, blend them into the current hour slot, and audit.

        This is the single recalculation step used by the async loop. It updates
        dashboard history and emits an audit record with the effective baseline
        values seen at that point in time.
        """
        m, s, em, es, n = self._snapshot()

        # Apply floors so we never have a degenerate baseline.
        self.global_mean = max(self.floor_mean, m)
        self.global_stddev = max(self.floor_stddev, s)
        self.error_mean = max(self.error_floor_mean, em)
        self.error_stddev = max(self.error_floor_stddev, es)

        # Update the current hour-slot with an EWMA blend so the slot
        # tracks recent activity but isn't whipsawed by a single recalc.
        hour = datetime.now().hour
        slot = self.hourly[hour]
        alpha = 0.3
        if slot["samples"] == 0:
            slot["mean"] = self.global_mean
            slot["stddev"] = self.global_stddev
            slot["error_mean"] = self.error_mean
            slot["error_stddev"] = self.error_stddev
        else:
            slot["mean"] = (1 - alpha) * slot["mean"] + alpha * self.global_mean
            slot["stddev"] = (1 - alpha) * slot["stddev"] + alpha * self.global_stddev
            slot["error_mean"] = (
                (1 - alpha) * slot.get("error_mean", self.error_mean)
                + alpha * self.error_mean
            )
            slot["error_stddev"] = (
                (1 - alpha) * slot.get("error_stddev", self.error_stddev)
                + alpha * self.error_stddev
            )
        slot["samples"] += 1
        self._save_slots()

        ts = datetime.now().isoformat(timespec="seconds")
        self.history.append({
            "ts": ts,
            "mean": self.global_mean,
            "stddev": self.global_stddev,
            "hour": hour,
            "slot_mean": slot["mean"],
            "slot_stddev": slot["stddev"],
            "samples": n,
        })

        self.audit.info(
            f"[{ts}] BASELINE_RECALC GLOBAL"
            f" | condition=hour_slot={hour} samples={n}"
            f" | rate=N/A"
            f" | baseline=mean={self.global_mean:.3f} stddev={self.global_stddev:.3f}"
            f" slot_mean={slot['mean']:.3f} slot_stddev={slot['stddev']:.3f}"
            f" | duration=N/A"
        )
        log.info(
            "recalc: mean=%.3f stddev=%.3f (hour=%d slot_mean=%.3f samples=%d) error_mean=%.3f",
            self.global_mean, self.global_stddev, hour, slot["mean"], n, self.error_mean,
        )

    # --- consumers ------------------------------------------------------

    def effective(self) -> tuple[float, float]:
        """
        Best baseline available, in priority order:
          1. current hour's slot if it has >= min_slot_samples
          2. global rolling stats if the deque has >= min_global_samples
          3. configured floor
        """
        hour = datetime.now().hour
        slot = self.hourly.get(hour)
        if slot and slot["samples"] >= self.min_slot_samples:
            return (
                max(self.floor_mean, slot["mean"]),
                max(self.floor_stddev, slot["stddev"]),
            )
        with self._lock:
            n = len(self._counts)
        if n >= self.min_global_samples:
            return self.global_mean, self.global_stddev
        return self.floor_mean, self.floor_stddev

    def effective_error(self) -> tuple[float, float]:
        """Best error baseline available, in priority order:

          1. current hour's slot if it has >= min_slot_samples
          2. global rolling stats if the deque has >= min_global_samples
          3. configured error floor

        Mirrors `effective()` so error-surge tightening is protected from
        the cold-start case where one stray 401 trips the threshold.
        """
        hour = datetime.now().hour
        slot = self.hourly.get(hour)
        if slot and slot["samples"] >= self.min_slot_samples:
            return (
                max(self.error_floor_mean, slot.get("error_mean", self.error_mean)),
                max(self.error_floor_stddev, slot.get("error_stddev", self.error_stddev)),
            )
        with self._lock:
            n = len(self._error_counts)
        if n >= self.min_global_samples:
            return self.error_mean, self.error_stddev
        return self.error_floor_mean, self.error_floor_stddev
