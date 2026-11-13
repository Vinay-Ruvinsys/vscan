"""Login / authentication / session security checks (passive; no brute force, no lockout testing).

Needs a Playwright storage-state file for the authenticated checks. Without one, only the
anonymous login-surface checks run.
"""
from __future__ import annotations

import base64
import json
import re
import time
from pathlib import Path

from playwright.async_api import async_playwright

from ..scanner import SESSION_COOKIE_RE
from . import Ctx, mk

TOKEN_NAME_RE = re.compile(r"token|jwt|auth|session", re.I)


def jwt_parts(value: str):
    parts = (value or "").split(".")
    if len(parts) != 3:
        return None
    try:
        dec = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        return dec(parts[0]), dec(parts[1])
    except Exception:
        return None


def check_state(ctx: Ctx, state: dict):
    out, now, https = [], time.time(), ctx.url.startswith("https://")
    for c in state.get("cookies", []):
        name, value = c.get("name", ""), c.get("value", "")
        jwt = jwt_parts(value)
        if not (SESSION_COOKIE_RE.search(name) or jwt):
            continue
        who = f"Cookie '{name}' ({c.get('domain', '')})"
        if not c.get("httpOnly"):
            out.append(mk("medium", "auth", "Authenticated session cookie lacks HttpOnly", ctx.url,
                          f"{who} can be read by JavaScript.",
                          "Set HttpOnly on session cookies so XSS cannot steal them.", key=name))
        if https and not c.get("secure"):
            out.append(mk("medium", "crypto", "Authenticated session cookie lacks Secure", ctx.url,
                          f"{who} may be sent over plain HTTP.", "Set Secure on session cookies.", key=name))
        if c.get("sameSite") in (None, "", "None"):
            out.append(mk("low", "access_control", "Authenticated session cookie has no SameSite restriction",
                          ctx.url, f"{who} uses SameSite={c.get('sameSite') or 'unset'}.",
                          "Use SameSite=Lax or Strict unless cross-site use is required.", key=name))
        exp = c.get("expires", -1)
        if exp and exp > 0 and exp - now > 30 * 86400:
            out.append(mk("low", "auth", "Long-lived session cookie", ctx.url,
                          f"{who} expires in about {int((exp - now) / 86400)} days.",
                          "Use short session lifetimes with idle timeout and re-authentication for sensitive actions.",
                          key=name))
        if not jwt and len(value) < 16:
            out.append(mk("medium", "auth", "Short session identifier", ctx.url,
                          f"{who} value is only {len(value)} characters.",
                          "Use at least 128 bits of random session ID entropy.", "indicator", key=name))
        if jwt:
            hdr, pl = jwt
            if str(hdr.get("alg", "")).lower() == "none":
                out.append(mk("high", "auth", "JWT uses alg=none", ctx.url,
                              f"{who} holds an unsigned JWT.", "Reject unsigned tokens; pin the signing algorithm.",
                              key=name))
            if "exp" not in pl:
                out.append(mk("medium", "auth", "JWT without expiry", ctx.url,
                              f"{who} has no 'exp' claim.", "Issue short-lived tokens with an exp claim.", key=name))
            elif pl["exp"] - now > 86400:
                out.append(mk("low", "auth", "JWT valid for more than 24 hours", ctx.url,
                              f"{who} expires in about {int((pl['exp'] - now) / 3600)} hours.",
                              "Use short-lived access tokens plus refresh-token rotation.", "indicator", key=name))
    for origin in state.get("origins", []):
        for item in origin.get("localStorage", []):
            if TOKEN_NAME_RE.search(item.get("name", "")) and (jwt_parts(item.get("value", "")) or len(item.get("value", "")) > 20):
                out.append(mk("low", "auth", "Authentication token stored in localStorage", origin.get("origin", ctx.url),
                              f"localStorage key '{item.get('name')}' looks like a token (value not stored).",
                              "localStorage is readable by any XSS. Prefer HttpOnly cookies, or keep tokens short-lived.",
                              "indicator", key=item.get("name", "")))
    return out


async def run(ctx: Ctx):
    out, state = [], None
    if ctx.storage_state:
        try:
            state = json.loads(Path(ctx.storage_state).read_text(encoding="utf-8"))
            out += check_state(ctx, state)
        except Exception as exc:
            out.append(mk("informational", "exceptions", "Storage state could not be read", ctx.url,
                          f"{type(exc).__name__}: {str(exc)[:150]}", "Re-export the Playwright storage state.", "indicator"))
    else:
        out.append(mk("informational", "auth", "Authenticated session checks skipped", ctx.url,
                      "No storage-state file was provided, so cookie, token and access checks for a logged-in session did not run.",
                      "Export a storage state from a dedicated low-privilege test account and attach it to the scan.",
                      "indicator"))

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        anon = await browser.new_context()
        page = await anon.new_page()
        page.set_default_timeout(15000)
        login_pages = []
        for u in ctx.pages[:15]:
            try:
                await page.goto(u, wait_until="domcontentloaded")
                await page.wait_for_timeout(400)
                if await page.locator("input[type=password]").count():
                    login_pages.append(page.url)
            except Exception:
                continue
        login_pages = list(dict.fromkeys(login_pages))
        pre = [c["name"] for c in await anon.cookies() if SESSION_COOKIE_RE.search(c["name"])]
        if login_pages and pre:
            out.append(mk("informational", "auth", "Session cookie issued before login", login_pages[0],
                          f"Cookie(s) {', '.join(sorted(set(pre))[:3])} were set for an anonymous visitor.",
                          "Confirm the session ID is regenerated on login (session fixation).", "indicator"))
        if not login_pages:
            out.append(mk("informational", "auth", "No login form found in crawled pages", ctx.url,
                          "No password field was seen for an anonymous visitor.",
                          "Start the scan from the login page if login behaviour should be assessed.", "indicator"))

        # Pages crawled with the session: are they reachable with no cookies at all?
        if state:
            un = await pw.request.new_context()
            for u in ctx.pages[:20]:
                if u in login_pages:
                    continue
                try:
                    r = await un.get(u, max_redirects=0, timeout=10000)
                    ct = r.headers.get("content-type", "")
                    if r.status == 200 and "html" in ct and 'type="password"' not in (await r.text())[:200000]:
                        out.append(mk("low", "access_control", "Page returns content without a session", u,
                                      "Request with no cookies returned HTTP 200 and no login form. Single-page apps often serve "
                                      "a shell for every route, so verify the data calls (see the API module).",
                                      "Confirm the page is meant to be public and that server-side authorisation protects its data.",
                                      "indicator"))
                except Exception:
                    continue
            await un.dispose()
        await browser.close()
    return out
