"""API security checks, driven by the XHR/fetch calls the app makes while its pages load.

Replays are limited to GET (and OPTIONS). Other methods are analysed from the observed
response only, never re-sent.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from ..scanner import ERROR_PATTERNS, redact
from . import Ctx, in_scope, mk

MAX_ENDPOINTS = 60
SECRET_KEY_RE = re.compile(
    r'"(password|passwd|secret|api_?key|private_?key|access_?token|refresh_?token)"\s*:\s*"([^"]{4,})"', re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
ID_PATH_RE = re.compile(r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", re.I)
DOC_PATHS = ["/swagger.json", "/openapi.json", "/v3/api-docs", "/api-docs", "/swagger-ui/index.html", "/swagger/index.html"]


async def run(ctx: Ctx):
    out, seen = [], {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        state = {"storage_state": ctx.storage_state} if ctx.storage_state else {}
        bc = await browser.new_context(**state)
        page = await bc.new_page()
        page.set_default_timeout(15000)

        async def on_response(resp):
            try:
                rq = resp.request
                if rq.resource_type not in ("xhr", "fetch") or not in_scope(ctx, resp.url) or len(seen) >= MAX_ENDPOINTS:
                    return
                key = (rq.method, urlparse(resp.url)._replace(query="", fragment="").geturl())
                if key in seen:
                    return
                rh = await rq.all_headers()
                hdr = await resp.all_headers()
                ct, body = hdr.get("content-type", "").lower(), ""
                if any(t in ct for t in ("json", "text", "xml")):
                    try:
                        body = (await resp.text())[:100000]
                    except Exception:
                        pass
                seen[key] = {"url": resp.url, "method": rq.method, "status": resp.status, "headers": hdr,
                             "ct": ct, "body": body, "authed": "authorization" in rh or "cookie" in rh}
            except Exception:
                pass

        page.on("response", on_response)
        for u in ctx.pages[:12]:
            try:
                await page.goto(u, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)
            except Exception:
                continue

        if not seen:
            out.append(mk("informational", "insecure_design", "No API calls observed", ctx.url,
                          "No XHR/fetch requests to this host were seen while the crawled pages loaded.",
                          "Use a storage state for authenticated apps, or start from a page that loads data.", "indicator"))

        un = await pw.request.new_context()
        rate_headers = False
        for (method, base), ep in seen.items():
            url, h = ep["url"], ep["headers"]
            label = f"{method} {urlparse(base).path}"
            if any(k for k in h if re.search(r"ratelimit|rate-limit|retry-after", k, re.I)):
                rate_headers = True

            # passive analysis of the observed response
            for lbl, rx, sev, topic, title in ERROR_PATTERNS:
                if ep["body"] and rx.search(ep["body"]):
                    out.append(mk(sev, topic, f"API error detail: {title}", url,
                                  f"{label} response contains a {lbl} signature.",
                                  "Return generic error bodies from the API; log details server-side.", key=label))
                    break
            m = SECRET_KEY_RE.search(ep["body"])
            if m:
                out.append(mk("medium", "crypto", "Secret-like field in API response", url,
                              f"{label} returns field '{m.group(1)}' (value {redact(m.group(2))}).",
                              "Never return secrets or password hashes to clients; filter fields server-side.",
                              "indicator", key=label))
            if len(EMAIL_RE.findall(ep["body"])) >= 20:
                out.append(mk("informational", "access_control", "Many e-mail addresses in one API response", url,
                              f"{label} returns 20+ e-mail addresses.",
                              "Check that the caller is authorised to see this data and that results are paginated.",
                              "indicator", key=label))
            if "json" in ep["ct"] and "nosniff" not in h.get("x-content-type-options", "").lower():
                out.append(mk("low", "misconfig", "API response missing X-Content-Type-Options", url,
                              f"{label} does not send nosniff.", "Add X-Content-Type-Options: nosniff.", key=label))
            if ep["authed"] and "json" in ep["ct"] and "no-store" not in h.get("cache-control", "").lower():
                out.append(mk("low", "crypto", "Authenticated API response may be cached", url,
                              f"{label} lacks Cache-Control: no-store.",
                              "Send no-store on responses that carry user-specific data.", "indicator", key=label))
            if ID_PATH_RE.search(urlparse(base).path):
                out.append(mk("informational", "access_control", "Object identifier in API path (BOLA/IDOR candidate)",
                              url, f"{label} addresses an object by ID.",
                              "Verify object-level authorisation server-side for every ID.", "indicator", key=label))

            # safe replays (GET only)
            if method != "GET":
                continue
            try:
                r = await un.get(url, max_redirects=0, timeout=10000)
                if ep["authed"] and r.status == 200 and "json" in r.headers.get("content-type", "").lower():
                    out.append(mk("high", "access_control", "API endpoint returns data without authentication", url,
                                  f"{label} answered HTTP 200 JSON to a request with no cookies or Authorization header, "
                                  "although the app called it with credentials.",
                                  "Enforce authentication and authorisation on every API route.", "indicator", key=label))
                await asyncio.sleep(0.15)
                r = await un.get(url, headers={"Origin": "https://cors-probe.invalid"}, max_redirects=0, timeout=10000)
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()
                if acao == "https://cors-probe.invalid":
                    out.append(mk("high" if acac == "true" else "low", "access_control",
                                  "CORS reflects arbitrary origin" + (" with credentials" if acac == "true" else ""), url,
                                  f"{label} echoed an untrusted Origin in Access-Control-Allow-Origin.",
                                  "Allow-list trusted origins; never reflect Origin together with credentials.", key=label))
                o = await un.fetch(url, method="OPTIONS", timeout=8000)
                allow = o.headers.get("allow", "") + "," + o.headers.get("access-control-allow-methods", "")
                if re.search(r"\b(TRACE|CONNECT)\b", allow, re.I):
                    out.append(mk("low", "misconfig", "Unnecessary HTTP methods advertised", url,
                                  f"{label} advertises: {allow.strip(', ')[:100]}.",
                                  "Allow only the methods each route needs.", key=label))
            except Exception:
                pass

        if seen and not rate_headers:
            out.append(mk("informational", "insecure_design", "No rate-limit headers observed on API responses", ctx.url,
                          "None of the observed API responses carried RateLimit / Retry-After style headers. "
                          "Rate limiting may still exist; it cannot be proven without load.",
                          "Confirm rate limiting and abuse protection exist for the API.", "indicator"))

        # exposed API documentation
        p0 = urlparse(ctx.url)
        origin = f"{p0.scheme}://{p0.netloc}"
        for path in DOC_PATHS:
            try:
                r = await un.get(origin + path, max_redirects=0, timeout=8000)
                txt = (await r.text())[:5000] if r.status == 200 else ""
                if re.search(r'"(openapi|swagger)"\s*:|swagger-ui', txt, re.I):
                    out.append(mk("low", "misconfig", "API documentation is publicly reachable", origin + path,
                                  f"GET {path} returned an OpenAPI/Swagger document or UI.",
                                  "Restrict API docs to internal users or non-production environments."))
            except Exception:
                pass
        await un.dispose()
        await browser.close()
    return out
