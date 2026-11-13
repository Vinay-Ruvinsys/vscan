"""Extra OWASP-oriented checks that go beyond the crawl: a handful of safe GET/OPTIONS probes.

Only a short, fixed list of well-known exposure paths is requested, and a finding is
raised only when the response body matches a content signature (so SPA catch-all
pages do not cause false positives). No directory enumeration, no payloads.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from . import Ctx, mk

EXPOSURES = [
    ("/.git/HEAD", re.compile(r"^ref:\s*refs/", re.M), "high", "Exposed .git repository",
     "Block access to VCS folders at the web server / CDN and rotate any secrets in the repo history."),
    ("/.env", re.compile(r"^[A-Z][A-Z0-9_]{2,}=.+", re.M), "high", "Exposed .env file",
     "Remove the file from the web root, block dotfiles, and rotate every credential it contained."),
    ("/web.config", re.compile(r"<configuration", re.I), "high", "Exposed web.config",
     "Deny direct access to configuration files."),
    ("/actuator/env", re.compile(r'"propertySources"'), "high", "Spring Boot actuator /env exposed",
     "Restrict actuator endpoints to internal networks and require authentication."),
    ("/server-status", re.compile(r"Apache Server Status", re.I), "medium", "Apache server-status exposed",
     "Restrict /server-status to localhost or an admin network."),
    ("/phpinfo.php", re.compile(r"PHP Version|phpinfo\(\)", re.I), "medium", "phpinfo() page exposed",
     "Delete diagnostic pages from production."),
]


async def run(ctx: Ctx):
    out = []
    p0 = urlparse(ctx.url)
    origin = f"{p0.scheme}://{p0.netloc}"
    async with async_playwright() as pw:
        req = await pw.request.new_context(ignore_https_errors=False)

        for path, rx, sev, title, rec in EXPOSURES:
            try:
                r = await req.get(origin + path, timeout=10000, max_redirects=0)
                if r.status == 200 and rx.search((await r.text())[:20000]):
                    out.append(mk(sev, "misconfig", title, origin + path,
                                  f"GET {path} returned HTTP 200 and matched a content signature (content not stored).",
                                  rec))
            except Exception:
                pass

        # HTTP -> HTTPS redirect (only meaningful on default ports)
        if p0.scheme == "https" and not p0.port:
            try:
                r = await req.get(f"http://{p0.hostname}/", timeout=8000, max_redirects=0)
                loc = r.headers.get("location", "")
                if r.status == 200:
                    out.append(mk("medium", "crypto", "HTTP is served without redirecting to HTTPS",
                                  f"http://{p0.hostname}/", "Plain-HTTP request returned 200.",
                                  "Redirect all HTTP traffic to HTTPS and enable HSTS."))
                elif 300 <= r.status < 400 and not loc.startswith("https://"):
                    out.append(mk("low", "crypto", "HTTP redirect does not point to HTTPS",
                                  f"http://{p0.hostname}/", f"Status {r.status}, Location: {loc[:120]}",
                                  "Redirect HTTP requests to the https:// URL."))
            except Exception:
                pass

        # TRACE should be disabled
        try:
            r = await req.fetch(origin + "/", method="TRACE", timeout=8000, max_redirects=0)
            if r.status == 200 and "TRACE" in (await r.text())[:500]:
                out.append(mk("medium", "misconfig", "HTTP TRACE method enabled", origin + "/",
                              "TRACE request was echoed back.", "Disable the TRACE method on the web server."))
        except Exception:
            pass

        await req.dispose()
    return out
