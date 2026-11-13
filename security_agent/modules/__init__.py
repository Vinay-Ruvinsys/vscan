"""Scan modules. Each module exposes `async def run(ctx) -> list[finding]`."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Ctx:
    """Shared context handed to every module."""
    url: str                          # start URL
    pages: list                       # URLs discovered by the crawl
    storage_state: str | None = None  # path to Playwright storage-state JSON (optional)
    max_pages: int = 20

    @property
    def host(self) -> str:
        h = (urlparse(self.url).hostname or "").lower()
        return h[4:] if h.startswith("www.") else h


def in_scope(ctx: Ctx, url: str) -> bool:
    h = (urlparse(url).hostname or "").lower()
    return bool(h) and (h == ctx.host or h == "www." + ctx.host or h.endswith("." + ctx.host))


def mk(severity, topic, title, url, evidence, recommendation, confidence="firm", key=""):
    """Build a finding dict with the same shape the crawler produces."""
    return {
        "severity": severity, "topic": topic, "title": title, "url": url,
        "evidence": evidence, "recommendation": recommendation,
        "confidence": confidence, "key": key,
    }
