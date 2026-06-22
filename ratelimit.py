#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2026 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
# You can use the code for free if your company or organisation doesn't have more than 2 people.
#-------------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class RateLimiter:
    """Per-key sliding-window rate limiter.

    Tracks recent operations per key (typically source IP) within a time
    window and rejects once the ceiling is hit.  Periodically prunes
    expired entries so the map doesn't grow without bound.
    """

    def __init__(self, max_per_window: int, window_sec: float = 60.0):
        self.max = max_per_window
        self.window = window_sec
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._prune_task: asyncio.Task | None = None

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        entries = self._buckets[key]
        while entries and entries[0] < cutoff:
            entries.pop(0)
        if len(entries) >= self.max:
            return False
        entries.append(now)
        return True

    def prune(self):
        now = time.time()
        cutoff = now - self.window
        for key in list(self._buckets.keys()):
            entries = self._buckets[key]
            while entries and entries[0] < cutoff:
                entries.pop(0)
            if not entries:
                del self._buckets[key]

    def start_background_prune(self, interval: float = 300.0):
        """Start a background task that prunes expired entries periodically."""
        async def _prune_loop():
            while True:
                await asyncio.sleep(interval)
                self.prune()
        self._prune_task = asyncio.create_task(_prune_loop())

    def stop(self):
        if self._prune_task:
            self._prune_task.cancel()
