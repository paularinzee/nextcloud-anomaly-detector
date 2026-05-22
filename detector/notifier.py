"""
Slack incoming-webhook notifier.

If no URL is configured (empty / not http*) the notifier is "disabled" —
calls just log to stdout instead of posting. This makes local dev painless.

All HTTP errors are logged but never raised; a flaky Slack should never
take the daemon down.
"""
import logging
from datetime import datetime

import aiohttp

log = logging.getLogger("notifier")


def _fmt_duration(seconds: int) -> str:
    """Format a ban duration for human-readable Slack messages.

    Negative or missing values represent permanent bans; shorter timed bans are
    collapsed into seconds, minutes, or hours for compact alert text.
    """
    if seconds is None or seconds < 0:
        return "PERMANENT"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


class SlackNotifier:
    def __init__(self, webhook_url: str):
        """Configure the incoming webhook client and disabled-mode fallback."""
        self.url = (webhook_url or "").strip()
        self.enabled = self.url.startswith("http")
        if not self.enabled:
            log.warning("Slack webhook not configured; alerts will only be logged")

    async def _post(self, text: str) -> None:
        """Post a message to Slack without allowing HTTP failures to escape.

        When no webhook is configured, messages are logged instead. This keeps
        local development and Slack outages from breaking the detector pipeline.
        """
        if not self.enabled:
            log.info("[slack disabled] %s", text.replace("\n", " | "))
            return
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.post(self.url, json={"text": text}) as r:
                    if r.status >= 300:
                        body = await r.text()
                        log.warning("slack post failed (%d): %s", r.status, body[:200])
        except Exception as e:  # noqa: BLE001
            log.warning("slack post error: %s", e)

    async def send_ban(self, ip, condition, rate, baseline, duration) -> None:
        """Send a Slack alert describing a newly banned source IP."""
        ts = datetime.now().isoformat(timespec="seconds")
        text = (
            f":no_entry: *IP banned* `{ip}`\n"
            f"> condition: `{condition}`\n"
            f"> rate: *{rate:.2f} req/s*  baseline: *{baseline:.2f} req/s*\n"
            f"> ban duration: *{_fmt_duration(duration)}*\n"
            f"> at: {ts}"
        )
        await self._post(text)

    async def send_unban(self, ip) -> None:
        """Send a Slack alert when a timed ban has been released."""
        ts = datetime.now().isoformat(timespec="seconds")
        await self._post(f":white_check_mark: *IP unbanned* `{ip}` at {ts}")

    async def send_global(self, condition, rate, baseline) -> None:
        """Send a Slack alert for a global traffic anomaly."""
        ts = datetime.now().isoformat(timespec="seconds")
        text = (
            f":rotating_light: *Global anomaly*\n"
            f"> condition: `{condition}`\n"
            f"> rate: *{rate:.2f} req/s*  baseline: *{baseline:.2f} req/s*\n"
            f"> at: {ts}"
        )
        await self._post(text)
