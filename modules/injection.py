"""Controlled XSS / SQL-injection probing.

Safety design (this module only runs when the host is on the server allow-list):
  * GET parameters only. POST forms are never submitted (they can change state).
  * Probes are canary strings, not exploit payloads: an XSS probe is a random token
    plus  "'<ztoken>  (checked for unencoded reflection); an SQLi probe is a single
    quote appended to the existing value (checked for database error signatures).
  * Hard request cap and a delay between requests.
"""
from __future__ import annotations

import asyncio
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from playwright.async_api import async_playwright

from ..scanner import ERROR_PATTERNS
from . import Ctx, in_scope, mk

MAX_TARGETS = 40
MAX_REQUESTS = 250
DELAY = 0.25
DB_ERRORS = [p for p in ERROR_PATTERNS if p[3] == "injection"]

FORMS_JS = r"""() => {
  const skip = ['hidden','submit','button','checkbox','radio','password','file','image','reset'];
  const out = [];
  document.querySelectorAll('form').forEach(f => {
    if ((f.getAttribute('method') || 'get').toLowerCase() !== 'get') return;
    if (f.querySelector('input[type=password],input[type=file]')) return;
    const names = [...f.querySelectorAll('input[name],textarea[name]')]
      .filter(i => !skip.includes((i.type || 'text').toLowerCase())).map(i => i.name);
    const hidden = [...f.querySelectorAll('input[type=hidden][name]')].map(i => [i.name, i.value || '']);
    let action = location.href;
    try { action = new URL(f.getAttribute('action') || location.href, location.href).href; } catch (e) {}
    if (names.length) out.push({action, names, hidden});
  });
  return out;
}"""


def with_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = [(k, value if k == name else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunparse(p._replace(query=urlencode(q)))


async def fetch(req, url: str):
    try:
        r = await req.get(url, timeout=15000)
        ct = r.headers.get("content-type", "").lower()
        body = ""
        if any(t in ct for t in ("html", "json", "xml", "text")):
            body = (await r.text())[:300000]
        return r.status, ct, body
    except Exception:
        return None, "", ""


async def run(ctx: Ctx):
    findings, targets, seen = [], [], set()

    def add_target(url, name):
        p = urlparse(url)
        k = (p.netloc, p.path, name)
        if k not in seen and len(targets) < MAX_TARGETS:
            seen.add(k)
            targets.append((url, name))

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        state = {"storage_state": ctx.storage_state} if ctx.storage_state else {}
        bc = await browser.new_context(**state)
        page = await bc.new_page()
        page.set_default_timeout(15000)

        # 1) discover GET parameters: query strings of crawled pages + GET forms
        for u in ctx.pages[:15]:
            for name, _ in parse_qsl(urlparse(u).query, keep_blank_values=True):
                add_target(u, name)
            try:
                await page.goto(u, wait_until="domcontentloaded")
                forms = await page.evaluate(FORMS_JS)
            except Exception:
                continue
            for fm in forms:
                if not in_scope(ctx, fm["action"]):
                    continue
                base = urlparse(fm["action"])
                q = (list(parse_qsl(base.query, keep_blank_values=True))
                     + [tuple(h) for h in fm["hidden"]] + [(n, "test") for n in fm["names"]])
                url = urlunparse(base._replace(query=urlencode(q)))
                for n in fm["names"]:
                    add_target(url, n)

        if not targets:
            await browser.close()
            return [mk("informational", "injection", "No GET parameters found to test", ctx.url,
                       "The crawl found no query-string parameters or GET forms. POST forms are intentionally not tested.",
                       "Provide a start URL that includes parameters, or test POST endpoints with a dedicated tool in staging.",
                       "indicator")]

        # 2) probe each parameter
        req, sent = bc.request, 0
        for url, name in targets:
            if sent >= MAX_REQUESTS:
                break
            orig = dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get(name) or "1"
            base_status, _, base_body = await fetch(req, url)
            sent += 1
            await asyncio.sleep(DELAY)

            # XSS: unencoded reflection of a harmless canary
            tok = secrets.token_hex(4)
            _, ct, body = await fetch(req, with_param(url, name, f"{tok}\"'<z{tok}>"))
            sent += 1
            await asyncio.sleep(DELAY)
            if body and "html" in ct and f"<z{tok}>" in body:
                findings.append(mk(
                    "medium", "injection", "Reflected input is not HTML-encoded (possible XSS)", url,
                    f"Parameter '{name}': a canary containing < and > came back unencoded in an HTML response.",
                    "Context-aware output encoding for reflected values, plus a strict CSP. Confirm manually in staging.",
                    "firm", key=name))

            # SQLi: database error triggered by a quote that the baseline does not show
            for q in ("'", '"'):
                status, _, body = await fetch(req, with_param(url, name, orig + q))
                sent += 1
                await asyncio.sleep(DELAY)
                hit = next((l for l, rx, *_ in DB_ERRORS if rx.search(body) and not rx.search(base_body)), None)
                if hit:
                    findings.append(mk(
                        "high", "injection", "Possible SQL injection: database error triggered by a quote", url,
                        f"Parameter '{name}': appending {q!r} produced a {hit} error message that the baseline response did not have.",
                        "Use parameterised queries / an ORM for this parameter and suppress database errors.",
                        "firm", key=name))
                    break
                if status and status >= 500 and (base_status or 0) < 500:
                    findings.append(mk(
                        "medium", "injection", "Server error triggered by a quote character", url,
                        f"Parameter '{name}': appending {q!r} changed the response from {base_status} to {status}.",
                        "Check how this parameter reaches a query or parser; validate input and handle errors gracefully.",
                        "indicator", key=name))
                    break

        await browser.close()
    return findings
