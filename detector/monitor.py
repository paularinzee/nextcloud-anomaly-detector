"""
Log monitor — tails the Nginx JSON access log and emits normalized
event dicts onto an asyncio.Queue for the detector to consume.

Handles:
  - file not yet created (waits for it)
  - log rotation (reopens on inode change)
  - non-JSON / partial lines (skipped with a debug log)
"""
import asyncio
import json
import logging
import os

log = logging.getLogger("monitor")


class LogMonitor:
    def __init__(self, log_path: str, queue: asyncio.Queue):
        """Store the Nginx access-log path and output queue for parsed events."""
        self.path = log_path
        self.queue = queue

    async def run(self) -> None:
        """Continuously tail the access log, restarting on expected file issues.

        The monitor waits for Nginx to create the log file, handles rotation by
        reopening the file, and keeps the daemon alive if parsing/tailing fails.
        """
        while True:
            try:
                await self._tail_once()
            except FileNotFoundError:
                log.warning("log file %s not present yet; retrying in 2s", self.path)
                await asyncio.sleep(2)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.exception("tailer crashed, restarting in 1s: %s", e)
                await asyncio.sleep(1)

    async def _tail_once(self) -> None:
        """Tail one incarnation of the log file and enqueue normalized events.

        The method returns when log rotation is detected so the outer run loop
        can reopen the new file. Each JSON access-log line becomes a compact
        event dict containing IP, timestamp, request details, status, and size.
        """
        # Wait for the file to materialise.
        while not os.path.exists(self.path):
            await asyncio.sleep(2)

        f = open(self.path, "r", encoding="utf-8", errors="replace")
        f.seek(0, os.SEEK_END)
        try:
            inode = os.fstat(f.fileno()).st_ino
        except OSError:
            inode = None
        log.info("tailing %s (inode=%s)", self.path, inode)

        try:
            while True:
                line = f.readline()
                if not line:
                    # Detect log rotation: same path now points to a different inode.
                    try:
                        cur = os.stat(self.path).st_ino
                        if inode is not None and cur != inode:
                            log.info("log rotated; reopening")
                            return
                    except FileNotFoundError:
                        await asyncio.sleep(0.5)
                        continue
                    await asyncio.sleep(0.1)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("skipping non-JSON line: %s", line[:200])
                    continue

                evt = {
                    "ip": (raw.get("source_ip") or raw.get("remote_addr") or "").strip(),
                    "ts": raw.get("timestamp", ""),
                    "method": raw.get("method", ""),
                    "path": raw.get("path", ""),
                    "status": int(raw.get("status", 0) or 0),
                    "size": int(raw.get("response_size", 0) or 0),
                }
                if not evt["ip"]:
                    continue

                try:
                    self.queue.put_nowait(evt)
                except asyncio.QueueFull:
                    log.warning("event queue full; dropping event")
        finally:
            try:
                f.close()
            except Exception:
                pass
