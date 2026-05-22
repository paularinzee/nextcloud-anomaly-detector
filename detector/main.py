"""
Cloud anomaly-detection daemon — entrypoint.

Wires together the log monitor, rolling baseline, anomaly detector,
iptables blocker, unban scheduler, Slack notifier, and dashboard,
then runs them concurrently on a single asyncio event loop.
"""
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import yaml

from baseline import Baseline
from blocker import Blocker
from dashboard import Dashboard
from detector import AnomalyDetector
from monitor import LogMonitor
from notifier import SlackNotifier
from unbanner import Unbanner


def setup_logging(audit_path: str) -> logging.Logger:
    """Configure operational stdout logging plus a dedicated audit logger.

    Normal component logs go to stdout for `docker logs`. Audit entries are
    written to the configured audit file and mirrored to stdout so deployments
    have both persistent evidence and live visibility.
    """
    Path(audit_path).parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    if not root.handlers:
        root.setLevel(logging.INFO)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        root.addHandler(sh)

    audit = logging.getLogger("audit")
    audit.propagate = False
    audit.setLevel(logging.INFO)
    if not audit.handlers:
        afh = logging.FileHandler(audit_path)
        afh.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(afh)
        # Mirror the audit log to stdout too, so `docker logs` shows it.
        ash = logging.StreamHandler(sys.stdout)
        ash.setFormatter(logging.Formatter("AUDIT %(message)s"))
        audit.addHandler(ash)
    return audit


def load_config() -> dict:
    """Load YAML configuration and apply environment overrides for secrets.

    The Slack webhook is intentionally read from SLACK_WEBHOOK_URL when present
    so the secret can live in .env or the deployment environment instead of the
    committed config file.
    """
    cfg_path = Path(__file__).parent / "config.yaml"
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # env override for the secret webhook URL
    env_hook = os.environ.get("SLACK_WEBHOOK_URL")
    if env_hook:
        cfg["slack_webhook_url"] = env_hook
    return cfg


async def run() -> None:
    """Wire all daemon components together and run them concurrently.

    This function creates the shared event queue, loads blocker state, starts
    monitor/baseline/detector/unbanner/dashboard tasks, and coordinates graceful
    shutdown when SIGINT or SIGTERM is received.
    """
    cfg = load_config()
    audit = setup_logging(cfg["audit_log_path"])
    log = logging.getLogger("main")

    event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    notifier = SlackNotifier(cfg.get("slack_webhook_url", ""))
    baseline = Baseline(cfg, audit)
    blocker = Blocker(cfg, audit, notifier)
    await blocker.load_state()
    detector = AnomalyDetector(cfg, baseline, blocker, notifier, audit)
    monitor = LogMonitor(cfg["log_path"], event_queue)
    unbanner = Unbanner(cfg, blocker, notifier, audit)
    dashboard = Dashboard(cfg, detector, baseline, blocker)

    stop = asyncio.Event()

    def _shutdown(*_):
        """Signal the main run loop to cancel background tasks cleanly."""
        log.info("shutdown signal received")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except (NotImplementedError, RuntimeError):
            # Windows doesn't implement add_signal_handler.
            signal.signal(sig, lambda *_: _shutdown())

    tasks = [
        asyncio.create_task(monitor.run(), name="monitor"),
        asyncio.create_task(baseline.run(), name="baseline"),
        asyncio.create_task(detector.run(event_queue), name="detector"),
        asyncio.create_task(unbanner.run(), name="unbanner"),
        asyncio.create_task(dashboard.serve(), name="dashboard"),
    ]
    log.info("detector daemon started; tailing %s", cfg["log_path"])

    await stop.wait()

    log.info("stopping tasks…")
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    log.info("shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
