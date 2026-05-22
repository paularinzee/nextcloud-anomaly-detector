"""
Unban scheduler.

Wakes up every `unban_poll_seconds` (default 10), asks the blocker which
IPs are due for release, releases each one, and pings Slack on every
release. Permanent bans (`unban_at = None`) are never released.
"""
import asyncio
import logging
import time

log = logging.getLogger("unbanner")


class Unbanner:
    def __init__(self, cfg, blocker, notifier, audit):
        """Create the periodic release worker for timed bans."""
        self.blocker = blocker
        self.notifier = notifier
        self.audit = audit
        self.poll_s = int(cfg.get("unban_poll_seconds", 10))

    async def run(self) -> None:
        """Poll forever for expired bans and release them when due.

        Errors during one sweep are logged and the loop continues so a single
        failed unban operation does not permanently stop scheduled releases.
        """
        while True:
            await asyncio.sleep(self.poll_s)
            try:
                await self._sweep()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.exception("unbanner sweep failed: %s", e)

    async def _sweep(self) -> None:
        """Release all IPs whose ban expiry time has passed and notify Slack."""
        now = time.time()
        for ip in self.blocker.due_for_unban(now):
            ok = await self.blocker.unban(ip)
            if ok:
                await self.notifier.send_unban(ip)
