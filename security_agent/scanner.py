from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections import Counter, deque
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from string import Template
from urllib.parse import parse_qsl, unquote, urldefrag, urlparse

from playwright.async_api import async_playwright


SCANNER_VERSION = "2.0"

# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------

SEVERITY_ORDER = ["high", "medium", "low", "informational"]

# --------------------------------------------------------------------------
# OWASP Top 10 mapping
#
# Every finding carries an internal "topic". Topics are resolved to a category
# ID at report time, so the same scan can be reported against either edition.
# OWASP Top 10:2025 (final, Jan 2026) is the default; 2021 is still widely
# referenced in audits, so it is selectable with --owasp-version.
# --------------------------------------------------------------------------

OWASP_VERSIONS = {
    "2025": {
        "label": "OWASP Top 10:2025",
        "categories": {
            "A01": "Broken Access Control",
            "A02": "Security Misconfiguration",
            "A03": "Software Supply Chain Failures",
            "A04": "Cryptographic Failures",
            "A05": "Injection",
            "A06": "Insecure Design",
            "A07": "Authentication Failures",
            "A08": "Software or Data Integrity Failures",
            "A09": "Security Logging & Alerting Failures",
            "A10": "Mishandling of Exceptional Conditions",
        },
        "topics": {
            "access_control": "A01",
            "ssrf": "A01",          # SSRF was merged into A01 in 2025
            "misconfig": "A02",
            "components": "A03",
            "crypto": "A04",
            "injection": "A05",
            "insecure_design": "A06",
            "auth": "A07",
            "integrity": "A08",
            "logging": "A09",
            "exceptions": "A10",
        },
    },
    "2021": {
        "label": "OWASP Top 10:2021",
        "categories": {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery",
        },
        "topics": {
            "access_control": "A01",
            "crypto": "A02",
            "injection": "A03",
            "insecure_design": "A04",
            "misconfig": "A05",
            "exceptions": "A05",    # verbose errors / stack traces sit in A05:2021
            "components": "A06",
            "auth": "A07",
            "integrity": "A08",
            "logging": "A09",
            "ssrf": "A10",
        },
    },
}

# What this passive scanner actually looks at, per topic. Used for the
# coverage summary. Levels: Partial > Indicators only > Minimal.
TOPIC_COVERAGE = {
    "access_control": ("Partial", [
        "CSRF token heuristics on POST forms",
        "SameSite cookie attribute",
        "Permissive CORS headers",
        "Object-reference IDs in form fields",
        "Links to sensitive-looking paths (.git, .env, backups, admin)",
    ]),
    "ssrf": ("Indicators only", [
        "URL / redirect-style parameters in links and form fields",
    ]),
    "misconfig": ("Partial", [
        "CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy",
        "CSP weaknesses (unsafe-inline, unsafe-eval, wildcards)",
        "Clickjacking protection",
        "Server / framework version disclosure",
        "Debug headers, directory listing, target=_blank without noopener",
    ]),
    "components": ("Partial", [
        "Client-side library versions vs known-vulnerable / end-of-life releases",
        "Third-party iframes without sandbox",
        "Third-party origin inventory",
    ]),
    "crypto": ("Partial", [
        "HTTPS usage, HSTS presence and strength, mixed content",
        "Secure cookie attribute",
        "Password forms posting insecurely",
        "Secrets / tokens in URLs and page source",
        "Cache-Control on pages with password fields",
    ]),
    "injection": ("Indicators only", [
        "URL parameter values reflected in the response",
        "DOM source-to-sink patterns in inline scripts",
        "Database error messages in responses",
        "Injection-prone parameter names",
    ]),
    "insecure_design": ("Minimal", [
        "Client-trusted business values in hidden fields",
        "File upload inputs without type restrictions",
    ]),
    "auth": ("Partial", [
        "HttpOnly flag on cookies, session-cookie heuristics",
        "Session IDs and credentials in URLs",
        "Basic authentication",
        "Login forms without CAPTCHA / MFA hints",
        "Weak client-side password policy on sign-up forms",
    ]),
    "integrity": ("Partial", [
        "Subresource Integrity (SRI) on third-party scripts and stylesheets",
        "Weak SRI hash algorithms",
        "Third-party resources loaded over HTTP",
        "Serialized-object markers in cookies and hidden fields",
    ]),
    "logging": ("Minimal", [
        "Browser reporting endpoints (Reporting-Endpoints, Report-To, CSP report-uri)",
    ]),
    "exceptions": ("Partial", [
        "Stack traces and framework error pages",
        "Debug-mode pages",
        "HTTP 5xx responses",
        "Server file-path disclosure in errors",
    ]),
}

LEVEL_RANK = {"Partial": 3, "Indicators only": 2, "Minimal": 1}

# --------------------------------------------------------------------------
# Detection patterns
# --------------------------------------------------------------------------

SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", "medium"),
    "strict-transport-security": ("Missing Strict-Transport-Security", "medium"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "low"),
    "referrer-policy": ("Missing Referrer-Policy", "low"),
    "permissions-policy": ("Missing Permissions-Policy", "low"),
}

SESSION_COOKIE_RE = re.compile(r"sess|sid\b|^sid|auth|token|jwt|login|sso", re.I)
SERIALIZED_RE = re.compile(r"^(rO0AB|O:\d+:\"|AAEAAAD/////)")

SECRET_PARAM_RE = re.compile(
    r"^(password|passwd|pwd|pass|token|access_token|id_token|secret|"
    r"api[_-]?key|apikey|auth|authorization|jwt)$", re.I)
SESSION_PARAM_RE = re.compile(
    r"^(sessionid|session_id|sessid|sid|jsessionid|phpsessid)$", re.I)
SSRF_PARAM_RE = re.compile(
    r"^(url|uri|link|src|source|dest|destination|redirect|redirect_?uri|"
    r"redirect_?url|return|return_?url|returnto|next|continue|goto|callback|"
    r"webhook|feed|proxy|remote|target|domain|host|image|img)$", re.I)
INJECTION_NAME_RE = re.compile(
    r"^(id|uid|user_?id|item|cat|category|q|query|search|keyword|filter|sort|"
    r"order|orderby|where|select|table|column|field|cmd|command|exec|file|path|"
    r"page|template|include|dir|folder|doc|document)$", re.I)

HIGH_RISK_PATH_RE = re.compile(
    r"/\.git(/|$)|/\.env\b|/\.svn|\.(bak|old|orig|sql|zip|tar\.gz)(\?|$)|"
    r"/actuator|/phpmyadmin", re.I)
ADMIN_PATH_RE = re.compile(r"/(admin|administrator|wp-admin|console)(/|$)", re.I)

CLIENT_TRUSTED_RE = re.compile(
    r"price|amount|total|premium|discount|fee|role|admin|privilege", re.I)
OBJECT_REF_RE = re.compile(
    r"^(user|account|policy|order|customer|owner|claim|member)_?id$", re.I)

CSRF_HINT_RE = re.compile(r"csrf|xsrf|_token|authenticity|requestverificationtoken", re.I)

DOM_SOURCE_RE = re.compile(
    r"location\.(?:search|hash|href)|document\.(?:URL|documentURI|referrer)|window\.name")
DOM_SINK_RE = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|\beval\s*\(|"
    r"insertAdjacentHTML\s*\(|new Function\s*\(")

# (label, regex, severity, topic, title)
ERROR_PATTERNS = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|mysqli?_\w+\(|MySQLSyntaxErrorException"),
     "high", "injection", "Database error message disclosed"),
    ("PostgreSQL", re.compile(r"PSQLException|pg_query\(\)|syntax error at or near|psycopg2\."),
     "high", "injection", "Database error message disclosed"),
    ("Oracle", re.compile(r"\bORA-\d{5}\b"),
     "high", "injection", "Database error message disclosed"),
    ("SQL Server", re.compile(r"Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|SqlException|\[Microsoft\]\[ODBC"),
     "high", "injection", "Database error message disclosed"),
    ("SQLite", re.compile(r"SQLite3?::|sqlite3\.OperationalError|SQLITE_ERROR"),
     "high", "injection", "Database error message disclosed"),
    ("SQLSTATE", re.compile(r"SQLSTATE\[\w+\]"),
     "high", "injection", "Database error message disclosed"),
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)"),
     "medium", "exceptions", "Stack trace or framework error disclosed"),
    ("Java stack trace", re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)|java\.lang\.\w*(?:Exception|Error)"),
     "medium", "exceptions", "Stack trace or framework error disclosed"),
    (".NET error page", re.compile(r"Server Error in '[^']*' Application|System\.\w+Exception|at System\.[\w.]+\("),
     "medium", "exceptions", "Stack trace or framework error disclosed"),
    ("PHP error", re.compile(r"(?:Fatal error|Parse error|Warning|Notice): .{0,200} on line \d+|Stack trace:\s*#0"),
     "medium", "exceptions", "Stack trace or framework error disclosed"),
    ("Node.js stack trace", re.compile(r"\bat [\w.<>$]+ \((?:/|[A-Za-z]:\\)[^)]*:\d+:\d+\)"),
     "medium", "exceptions", "Stack trace or framework error disclosed"),
    ("Ruby/Rails error", re.compile(r"ActionController::\w+|ActiveRecord::\w+|\.rb:\d+:in `"),
     "medium", "exceptions", "Stack trace or framework error disclosed"),
    ("Spring Whitelabel", re.compile(r"Whitelabel Error Page"),
     "low", "exceptions", "Stack trace or framework error disclosed"),
    ("Django debug page", re.compile(r"You're seeing this error because you have <code>DEBUG = True|Django Version:"),
     "high", "misconfig", "Debug mode appears to be enabled"),
    ("Laravel/Symfony debug", re.compile(r"Whoops! There was an error|Symfony\\Component\\|Illuminate\\"),
     "high", "misconfig", "Debug mode appears to be enabled"),
]

PATH_DISCLOSURE_RE = re.compile(
    r"[A-Za-z]:\\(?:inetpub|Users|Windows|xampp|wwwroot)[^\s<\"']{0,80}|"
    r"/(?:var/www|home/\w+|usr/local|opt/\w+|srv)/[^\s<\"']{3,80}")

# (label, regex, severity, confidence)
SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", "firm"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high", "firm"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "high", "firm"),
    ("Hard-coded credential assignment",
     re.compile(r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"\s]{8,}['"]"""),
     "medium", "indicator"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "low", "indicator"),
]

# name -> (fixed-in tuple, note). Version-specific rules are in check_components.
LIB_ALIASES = {"jquery": "jQuery", "bootstrap": "Bootstrap", "angular": "AngularJS",
               "lodash": "lodash", "moment": "moment"}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def origin(url: str):
    p = urlparse(url)
    return p.scheme, (p.hostname or "").lower(), p.port


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_third_party(url: str, base_host: str) -> bool:
    """Third party = a host that is neither the target host nor one of its subdomains."""
    h = host_of(url)
    return bool(h) and h != base_host and not h.endswith("." + base_host)


def fmt_list(items, limit=5) -> str:
    items = list(dict.fromkeys(items))
    shown = ", ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def redact(value: str) -> str:
    return f"{value[:2]}… ({len(value)} chars)" if value else "(empty)"


def snippet(body: str, m: re.Match, width: int = 60) -> str:
    s, e = max(0, m.start() - width), min(len(body), m.end() + width)
    return re.sub(r"\s+", " ", body[s:e]).strip()[:200]


def parse_version(text: str):
    nums = re.findall(r"\d+", text or "")[:3]
    return tuple(int(n) for n in nums) + (0,) * (3 - len(nums))


def parse_set_cookie(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), value.strip(), attrs


def add_finding(
    findings,
    severity,
    topic,
    title,
    url,
    evidence,
    recommendation,
    confidence="firm",
):
    """confidence: 'firm' = directly observed; 'indicator' = heuristic, needs manual validation."""
    assert severity in SEVERITY_ORDER, severity
    findings.append({
        "severity": severity,
        "topic": topic,
        "title": title,
        "url": url,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
    })


class ScanState:
    def __init__(self, base_host: str):
        self.findings = []
        self.base_host = base_host
        self.third_party = {}        # host -> counters
        self.libraries = {}          # "name version" -> set(pages)
        self.explicit_samesite = False
        self.reporting_checked = False


# --------------------------------------------------------------------------
# In-page DOM collection (raw string so JS regex escapes stay intact)
# --------------------------------------------------------------------------

DOM_JS = r"""() => {
  const abs = (v) => { try { return new URL(v, location.href).href; } catch (e) { return ""; } };
  const csrfRe = /csrf|xsrf|_token|authenticity|requestverificationtoken|anti.?forgery/i;

  const resources = [];
  document.querySelectorAll('script[src]').forEach(e => resources.push({
    kind: 'script', url: abs(e.getAttribute('src')),
    integrity: e.getAttribute('integrity') || '', sandbox: false }));
  document.querySelectorAll('link[rel~="stylesheet"][href]').forEach(e => resources.push({
    kind: 'stylesheet', url: abs(e.getAttribute('href')),
    integrity: e.getAttribute('integrity') || '', sandbox: false }));
  document.querySelectorAll('iframe[src]').forEach(e => resources.push({
    kind: 'iframe', url: abs(e.getAttribute('src')),
    integrity: '', sandbox: e.hasAttribute('sandbox') }));
  const images = [...document.querySelectorAll('img[src]')].map(e => abs(e.getAttribute('src')));

  const csrfMeta = [...document.querySelectorAll('meta[name]')]
    .some(m => csrfRe.test(m.getAttribute('name')));
  const captchaOnPage =
    !!document.querySelector('.g-recaptcha,.h-captcha,.cf-turnstile,[data-sitekey],' +
      'iframe[src*="recaptcha"],[class*="captcha" i],[id*="captcha" i]') ||
    resources.some(r => /recaptcha|hcaptcha|turnstile|captcha/i.test(r.url));
  const otpOnPage = !!document.querySelector(
    'input[autocomplete="one-time-code"],input[name*="otp" i],input[name*="mfa" i],input[name*="2fa" i]');

  const forms = [...document.querySelectorAll('form')].map(f => {
    const pw = [...f.querySelectorAll('input[type=password]')];
    const inputs = [...f.querySelectorAll('input[name],textarea[name],select[name]')];
    return {
      action: abs(f.getAttribute('action') || location.href),
      method: (f.getAttribute('method') || 'get').toUpperCase(),
      passwordCount: pw.length,
      hasToken: inputs.some(i => csrfRe.test(i.name)),
      hasMinlength: pw.some(p =>
        parseInt(p.getAttribute('minlength') || '0', 10) >= 8 || p.hasAttribute('pattern')),
      fileNoAccept: [...f.querySelectorAll('input[type=file]')].some(i => !i.hasAttribute('accept')),
      isSearch: !!f.querySelector('input[type=search]') ||
                (f.getAttribute('role') || '').toLowerCase() === 'search',
      names: inputs.map(i => i.name).slice(0, 60),
      urlInputs: inputs.filter(i => (i.type || '').toLowerCase() === 'url').map(i => i.name),
      hidden: [...f.querySelectorAll('input[type=hidden][name]')]
        .map(i => ({ name: i.name, value: (i.value || '').slice(0, 200) }))
    };
  });

  const libs = [];
  const tryPush = (name, fn) => { try { const v = fn(); if (v) libs.push([name, String(v)]); } catch (e) {} };
  tryPush('jQuery', () => window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery);
  tryPush('AngularJS', () => window.angular && window.angular.version && window.angular.version.full);
  tryPush('lodash', () => window._ && window._.VERSION);
  tryPush('moment', () => window.moment && window.moment.version);
  tryPush('Vue', () => window.Vue && window.Vue.version);
  tryPush('Bootstrap', () =>
    (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) ||
    (window.jQuery && window.jQuery.fn.tooltip && window.jQuery.fn.tooltip.Constructor &&
     window.jQuery.fn.tooltip.Constructor.VERSION));

  return {
    resources, images, forms, libs, csrfMeta, captchaOnPage, otpOnPage,
    generator: (document.querySelector('meta[name=generator]') || {}).content || '',
    inlineScripts: [...document.querySelectorAll('script:not([src])')]
      .map(s => s.textContent).join('\n').slice(0, 300000),
    links: [...document.querySelectorAll('a[href]')].map(a => a.href),
    externalBlank: [...document.querySelectorAll('a[target=_blank]')]
      .filter(a => a.origin !== location.origin &&
                   !/\b(noopener|noreferrer)\b/i.test(a.rel || '')).length,
    sensitiveNames: [...document.querySelectorAll('input[name],textarea[name]')]
      .map(e => e.name)
      .filter(n => /password|passwd|token|secret|api[_-]?key/i.test(n))
  };
}"""


# --------------------------------------------------------------------------
# Checks (each one is small and independent)
# --------------------------------------------------------------------------

def check_transport(f, url, dom):
    https = urlparse(url).scheme == "https"

    if not https:
        add_finding(f, "high", "crypto", "Page is served over HTTP", url,
                    "The page URL does not use HTTPS.",
                    "Serve the application over HTTPS and redirect HTTP to HTTPS.")

    if https:
        mixed = [u for u in dom["images"] + [r["url"] for r in dom["resources"]]
                 if u.startswith("http://")]
        if mixed:
            add_finding(f, "medium", "crypto", "Mixed-content resources", url,
                        f"{len(mixed)} HTTP resource(s) referenced by an HTTPS page: {fmt_list(mixed, 3)}.",
                        "Load all scripts, stylesheets, images and frames over HTTPS.")

    if dom["sensitiveNames"]:
        add_finding(f, "informational", "crypto", "Potentially sensitive input names detected", url,
                    "Input field names suggest sensitive data; values were not read.",
                    "Confirm sensitive data is handled server-side and never exposed in URLs or logs.",
                    "indicator")


def check_headers(f, url, headers, dom, state):
    https = urlparse(url).scheme == "https"

    # Presence checks
    for header, (title, sev) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not https:
            continue
        if not headers.get(header):
            topic = "crypto" if header == "strict-transport-security" else "misconfig"
            add_finding(f, sev, topic, title, url,
                        f"Response did not include {header}.",
                        f"Review and configure the {header} response header.")

    # HSTS strength
    hsts = headers.get("strict-transport-security", "")
    if https and hsts:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        if not m or int(m.group(1)) < 15552000:
            add_finding(f, "low", "crypto", "Weak Strict-Transport-Security max-age", url,
                        f"HSTS value is '{hsts}'.",
                        "Use max-age of at least 15552000 (180 days); 31536000 is the common target.")

    # X-Content-Type-Options value
    xcto = headers.get("x-content-type-options", "")
    if xcto and xcto.strip().lower() != "nosniff":
        add_finding(f, "low", "misconfig", "Invalid X-Content-Type-Options value", url,
                    f"Header value is '{xcto}'.", "Set X-Content-Type-Options: nosniff.")

    # CSP quality
    csp = headers.get("content-security-policy", "")
    directives = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    script_src = directives.get("script-src", directives.get("default-src"))
    if script_src is not None:
        guarded = any(s.startswith("'nonce-") or s.startswith("'sha") or s == "'strict-dynamic'"
                      for s in script_src)
        weak = []
        if "'unsafe-inline'" in script_src and not guarded:
            weak.append("'unsafe-inline'")
        if any(s in ("*", "http:", "https:", "data:") for s in script_src):
            weak.append("wildcard/scheme source")
        eval_only = "'unsafe-eval'" in script_src
        if weak or eval_only:
            if eval_only:
                weak.append("'unsafe-eval'")
            add_finding(f, "medium" if len(weak) > int(eval_only) else "low", "misconfig",
                        "Weak Content-Security-Policy script policy", url,
                        f"script-src/default-src allows: {', '.join(weak)}.",
                        "Remove unsafe-inline/unsafe-eval and broad sources; use nonces or hashes.")

    # Clickjacking
    if not headers.get("x-frame-options") and "frame-ancestors" not in directives:
        has_pw = any(fm["passwordCount"] for fm in dom["forms"])
        add_finding(f, "medium" if has_pw else "low", "misconfig",
                    "No clickjacking protection", url,
                    "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                    "Set CSP frame-ancestors (or X-Frame-Options) to restrict framing.")

    # Technology disclosure
    server = headers.get("server", "")
    if re.search(r"\d+\.\d+", server):
        add_finding(f, "low", "misconfig", "Server version disclosed", url,
                    f"Server header: '{server}'.", "Remove version details from the Server header.")
    for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if headers.get(h):
            add_finding(f, "low", "misconfig", f"Technology disclosed via {h}", url,
                        f"{h}: '{headers[h]}'.", f"Remove the {h} header.")
    if dom.get("generator") and re.search(r"\d+\.\d+", dom["generator"]):
        add_finding(f, "low", "misconfig", "Platform version disclosed in generator meta tag", url,
                    f"Generator: '{dom['generator']}'.", "Remove the generator meta tag.")

    # Debug headers
    if headers.get("x-debug-token") or headers.get("x-debug-token-link"):
        add_finding(f, "medium", "misconfig", "Debug profiler headers exposed", url,
                    "X-Debug-Token header present.", "Disable the debug profiler in production.")

    # Caching of credential pages
    if any(fm["passwordCount"] for fm in dom["forms"]):
        if "no-store" not in headers.get("cache-control", "").lower():
            add_finding(f, "low", "crypto", "Credential page may be cached", url,
                        "Page has a password field but Cache-Control lacks no-store.",
                        "Send Cache-Control: no-store on pages handling credentials.")

    # CORS
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        add_finding(f, "medium", "access_control", "CORS wildcard combined with credentials", url,
                    "Access-Control-Allow-Origin: * with Allow-Credentials: true.",
                    "Reflect only an allow-list of trusted origins; never combine * with credentials.")
    elif acao == "null":
        add_finding(f, "medium", "access_control", "CORS allows the 'null' origin", url,
                    "Access-Control-Allow-Origin: null.", "Do not trust the null origin.")
    elif acao == "*":
        add_finding(f, "informational", "access_control", "CORS allows any origin", url,
                    "Access-Control-Allow-Origin: *.",
                    "Confirm this resource is public and carries no user-specific data.", "indicator")

    # Basic authentication
    if "basic" in headers.get("www-authenticate", "").lower():
        add_finding(f, "high" if not https else "low", "auth", "HTTP Basic authentication in use", url,
                    "WWW-Authenticate advertises Basic.",
                    "Use HTTPS only and prefer session/token-based authentication with MFA.")

    # Logging/monitoring hint (site-wide, report once)
    if not state.reporting_checked:
        state.reporting_checked = True
        if not any(headers.get(h) for h in ("reporting-endpoints", "report-to", "nel")) \
                and "report-uri" not in directives and "report-to" not in directives:
            add_finding(f, "informational", "logging", "No browser reporting endpoints observed", url,
                        "No Reporting-Endpoints, Report-To, NEL or CSP report-uri/report-to found. "
                        "Server-side logging and alerting cannot be assessed from outside.",
                        "Review logging, monitoring and alerting with the application owner; "
                        "consider CSP/NEL reporting.", "indicator")


def check_cookies(f, url, set_cookies, dom, state):
    https = urlparse(url).scheme == "https"
    for raw in set_cookies:
        name, value, attrs = parse_set_cookie(raw)
        if not name:
            continue
        session_like = bool(SESSION_COOKIE_RE.search(name))
        samesite = attrs.get("samesite", "").lower()
        if samesite in ("lax", "strict"):
            state.explicit_samesite = True

        if https and "secure" not in attrs:
            add_finding(f, "medium" if session_like else "low", "crypto",
                        "Cookie missing Secure attribute", url,
                        f"Cookie '{name}' does not show the Secure attribute.",
                        "Set Secure on cookies that should only travel over HTTPS.")
        if "httponly" not in attrs:
            add_finding(f, "medium" if session_like else "low", "auth",
                        "Cookie missing HttpOnly attribute", url,
                        f"Cookie '{name}' does not show the HttpOnly attribute.",
                        "Set HttpOnly on session and other sensitive cookies where JavaScript access is unnecessary.")
        if not samesite:
            add_finding(f, "low" if session_like else "informational", "access_control",
                        "Cookie missing SameSite attribute", url,
                        f"Cookie '{name}' does not show a SameSite attribute.",
                        "Set an appropriate SameSite policy and validate cross-site flows.")
        elif samesite == "none" and "secure" not in attrs:
            add_finding(f, "medium", "access_control", "SameSite=None cookie without Secure", url,
                        f"Cookie '{name}' uses SameSite=None without Secure.",
                        "Cookies with SameSite=None must also set Secure.")
        if SERIALIZED_RE.match(unquote(value)):
            add_finding(f, "medium", "integrity", "Cookie appears to hold a serialized object", url,
                        f"Cookie '{name}' starts with a serialization marker.",
                        "Avoid serialized objects in client-controlled data; sign/encrypt and validate server-side.",
                        "indicator")


def check_forms(f, url, dom, state):
    forms = dom["forms"]

    for fm in forms:
        action_https = urlparse(fm["action"]).scheme == "https"
        has_pw = fm["passwordCount"] > 0

        # Password transport
        if has_pw and (urlparse(url).scheme != "https" or not action_https or fm["method"] == "GET"):
            add_finding(f, "high", "crypto", "Password form may submit insecurely", url,
                        f"Password form submits via {fm['method']} to {fm['action']}.",
                        "Use HTTPS for the page and form destination; avoid GET for credentials.")

        # CSRF heuristic
        if fm["method"] == "POST" and not fm["hasToken"] and not dom["csrfMeta"] and not fm["isSearch"]:
            is_login = fm["passwordCount"] == 1
            mitigated = state.explicit_samesite
            sev = "low" if (is_login or mitigated) else "medium"
            note = []
            if is_login:
                note.append("login form (login-CSRF risk only)")
            if mitigated:
                note.append("SameSite cookies observed, which may mitigate")
            add_finding(f, sev, "access_control", "POST form without recognisable anti-CSRF token", url,
                        f"Form posting to {fm['action']} has no CSRF-style hidden field or meta tag"
                        + (f" ({'; '.join(note)})." if note else "."),
                        "Use per-session anti-CSRF tokens (or double-submit cookie) plus SameSite cookies "
                        "and verify Origin/Referer on state-changing requests.",
                        "indicator")

        # Authentication hygiene
        if fm["passwordCount"] == 1 and not dom["captchaOnPage"] and not dom["otpOnPage"]:
            add_finding(f, "informational", "auth", "Login form shows no CAPTCHA or MFA hint", url,
                        "No CAPTCHA widget or one-time-code field was seen near the login form.",
                        "Confirm server-side rate limiting, lockout and MFA; this is a visibility check only.",
                        "indicator")
        if fm["passwordCount"] >= 2 and not fm["hasMinlength"]:
            add_finding(f, "informational", "auth", "No client-side password policy on sign-up form", url,
                        "Sign-up/change-password form has no minlength (>=8) or pattern on password fields.",
                        "Enforce a password policy server-side (length, breached-password screening).",
                        "indicator")

        # Insecure design indicators
        if fm["fileNoAccept"]:
            add_finding(f, "informational", "insecure_design", "File upload without type restrictions", url,
                        "A file input has no accept attribute.",
                        "Enforce type, size and content validation and safe storage server-side.", "indicator")

    # Hidden fields: client-trusted values, object references, serialized data
    trusted, refs = [], []
    for fm in forms:
        for h in fm["hidden"]:
            if CLIENT_TRUSTED_RE.search(h["name"]):
                trusted.append(h["name"])
            if OBJECT_REF_RE.match(h["name"]):
                refs.append(h["name"])
            if SERIALIZED_RE.match(unquote(h["value"])):
                add_finding(f, "medium", "integrity", "Hidden field appears to hold a serialized object", url,
                            f"Hidden field '{h['name']}' starts with a serialization marker.",
                            "Avoid serialized objects in client-controlled data; sign and validate server-side.",
                            "indicator")
    if trusted:
        add_finding(f, "informational", "insecure_design", "Business-critical values in hidden fields", url,
                    f"Hidden field(s): {fmt_list(trusted)}.",
                    "Never trust client-supplied prices, roles or amounts; recompute and authorise server-side.",
                    "indicator")
    if refs:
        add_finding(f, "informational", "access_control", "Object identifiers exposed in form fields", url,
                    f"Hidden field(s): {fmt_list(refs)}.",
                    "Verify object-level authorisation on the server (IDOR) for every identifier.", "indicator")


def check_third_party(f, url, dom, state):
    http_assets, no_sri_scripts, no_sri_styles, weak_sri, open_frames = [], [], [], [], []

    for r in dom["resources"]:
        if not r["url"] or not is_third_party(r["url"], state.base_host):
            continue
        host = host_of(r["url"])
        inv = state.third_party.setdefault(host, {
            "script": 0, "stylesheet": 0, "iframe": 0, "without_sri": 0, "pages": set()})
        inv[r["kind"]] += 1
        inv["pages"].add(url)

        if r["kind"] == "iframe":
            if not r["sandbox"]:
                open_frames.append(r["url"])
            continue

        if r["url"].startswith("http://"):
            http_assets.append(r["url"])

        integrity = r["integrity"].strip().lower()
        if not integrity:
            inv["without_sri"] += 1
            (no_sri_scripts if r["kind"] == "script" else no_sri_styles).append(r["url"])
        elif not re.search(r"\bsha(256|384|512)-", integrity):
            weak_sri.append(r["url"])

    if http_assets:
        add_finding(f, "high", "integrity", "Third-party resources loaded over HTTP", url,
                    f"{len(http_assets)} resource(s): {fmt_list(http_assets, 3)}.",
                    "Load third-party code only over HTTPS, with SRI.")
    if no_sri_scripts:
        add_finding(f, "medium", "integrity", "Third-party scripts without Subresource Integrity", url,
                    f"{len(no_sri_scripts)} script(s) lack an integrity attribute: {fmt_list(no_sri_scripts, 3)}.",
                    "Add integrity + crossorigin=\"anonymous\" for static, version-pinned files. For vendor-managed "
                    "scripts (tag managers, analytics) SRI is not practical: restrict them with CSP and review the vendor.")
    if no_sri_styles:
        add_finding(f, "low", "integrity", "Third-party stylesheets without Subresource Integrity", url,
                    f"{len(no_sri_styles)} stylesheet(s) lack an integrity attribute: {fmt_list(no_sri_styles, 3)}.",
                    "Add integrity + crossorigin=\"anonymous\", or self-host the stylesheet.")
    if weak_sri:
        add_finding(f, "medium", "integrity", "Weak or invalid SRI hash", url,
                    f"Integrity value is not sha256/384/512 for: {fmt_list(weak_sri, 3)}.",
                    "Use sha384 (or stronger) SRI hashes.")
    if open_frames:
        add_finding(f, "informational", "components", "Third-party iframes without sandbox", url,
                    f"{len(open_frames)} iframe(s): {fmt_list(open_frames, 3)}.",
                    "Add a sandbox attribute (and allow only the capabilities required).", "indicator")


def check_components(f, url, dom, state):
    detected = {(n, v): "runtime" for n, v in dom["libs"]}

    # Version hints from script URLs (weaker evidence)
    for r in dom["resources"]:
        if r["kind"] != "script":
            continue
        m = re.search(r"(jquery|bootstrap|angular|lodash|moment)[-.@/]v?(\d+\.\d+(?:\.\d+)?)",
                      r["url"], re.I)
        if m:
            key = (LIB_ALIASES[m.group(1).lower()], m.group(2))
            detected.setdefault(key, "script URL")

    for (name, version), source in detected.items():
        state.libraries.setdefault(f"{name} {version}", set()).add(url)
        v = parse_version(version)
        issue = None
        if name == "jQuery" and v < (3, 5, 0):
            issue = ("medium", "versions before 3.5.0 have known XSS issues (CVE-2020-11022/11023)")
        elif name == "Bootstrap" and ((v[0] == 3 and v < (3, 4, 1)) or (v[0] == 4 and v < (4, 3, 1)) or v[0] < 3):
            issue = ("medium", "versions before 3.4.1 / 4.3.1 have known XSS issues (CVE-2019-8331)")
        elif name == "lodash" and v < (4, 17, 21):
            issue = ("medium", "versions before 4.17.21 have prototype-pollution / command-injection issues")
        elif name == "moment" and v < (2, 29, 4):
            issue = ("low", "versions before 2.29.4 have a ReDoS issue (CVE-2022-31129)")
        elif name == "AngularJS":
            issue = ("medium", "AngularJS 1.x reached end of life in January 2022")
        elif name == "Vue" and v[0] == 2:
            issue = ("low", "Vue 2 reached end of life on 31 December 2023")
        if issue:
            add_finding(f, issue[0], "components", f"Outdated or end-of-life library: {name} {version}", url,
                        f"{name} {version} detected ({source}); {issue[1]}.",
                        f"Upgrade {name} to a supported release and confirm against current advisories.",
                        "firm" if source == "runtime" else "indicator")


def check_injection(f, url, body, dom):
    # Reflection of values already present in the URL (no payloads are sent)
    if body:
        for name, value in parse_qsl(urlparse(url).query):
            if len(value) < 4 or value not in body:
                continue
            special = any(c in value for c in "<>\"'")
            add_finding(f, "medium" if special else "informational", "injection",
                        "URL parameter reflected in response", url,
                        f"Parameter '{name}' value appears in the response"
                        + (" with HTML-special characters unescaped." if special else "."),
                        "Output-encode reflected data for its context and validate input; "
                        "confirm with authorised active testing.", "indicator")

    scripts = dom["inlineScripts"]
    sinks = sorted(set(m.group(0).strip() for m in DOM_SINK_RE.finditer(scripts)))
    if sinks:
        if DOM_SOURCE_RE.search(scripts):
            add_finding(f, "medium", "injection", "Possible DOM-based XSS pattern", url,
                        f"Inline script uses a URL/DOM source and a dangerous sink ({fmt_list(sinks, 3)}).",
                        "Avoid writing untrusted data to innerHTML/eval/document.write; use textContent or a sanitiser.",
                        "indicator")
        else:
            add_finding(f, "informational", "injection", "Dangerous JavaScript sinks in inline script", url,
                        f"Sink(s) used: {fmt_list(sinks, 3)}.",
                        "Review that no untrusted data reaches these sinks.", "indicator")


def check_urls(f, url, dom, state):
    """Parameter- and path-level heuristics over the page URL and same-origin links."""
    urls = [url] + [l for l in dom["links"]
                    if l.startswith(("http://", "https://")) and not is_third_party(l, state.base_host)][:300]

    secrets, sessions, ssrf, ssrf_full, inj, risky, admin = [], [], [], False, [], [], []

    for u in urls:
        p = urlparse(u)
        if re.search(r";jsessionid=", p.path, re.I):
            sessions.append(f"jsessionid (in {p.path})")
        if HIGH_RISK_PATH_RE.search(p.path):
            risky.append(p.path)
        elif ADMIN_PATH_RE.search(p.path):
            admin.append(p.path)
        for name, value in parse_qsl(p.query, keep_blank_values=True):
            if SECRET_PARAM_RE.match(name):
                secrets.append(f"{name}={redact(value)} (in {p.path})")
            elif SESSION_PARAM_RE.match(name):
                sessions.append(f"{name}={redact(value)} (in {p.path})")
            if SSRF_PARAM_RE.match(name):
                ssrf.append(name)
                if re.match(r"^(https?:)?//", value, re.I):
                    ssrf_full = True
            if INJECTION_NAME_RE.match(name):
                inj.append(name)

    for fm in dom["forms"]:
        for n in fm["names"]:
            if SSRF_PARAM_RE.match(n):
                ssrf.append(n)
            if INJECTION_NAME_RE.match(n):
                inj.append(n)
        ssrf.extend(fm["urlInputs"])

    if secrets:
        add_finding(f, "medium", "crypto", "Sensitive value in URL query string", url,
                    f"{fmt_list(secrets, 3)}.",
                    "Never pass credentials or tokens in URLs; they leak via logs, history and Referer.")
    if sessions:
        add_finding(f, "medium", "auth", "Session identifier in URL", url,
                    f"{fmt_list(sessions, 3)}.",
                    "Keep session IDs in HttpOnly cookies, not in URLs.")
    if ssrf:
        add_finding(f, "low" if ssrf_full else "informational", "ssrf",
                    "URL/redirect-style parameters (SSRF / open-redirect candidates)", url,
                    f"Parameter(s): {fmt_list(ssrf)}"
                    + ("; at least one carries a full URL value." if ssrf_full else "."),
                    "Allow-list destinations server-side, block internal address ranges, and validate redirects.",
                    "indicator")
    if inj:
        add_finding(f, "informational", "injection", "Injection-prone parameter names", url,
                    f"Parameter(s): {fmt_list(inj)}.",
                    "Use parameterised queries and strict input validation for these inputs; "
                    "prioritise them for authorised active testing.", "indicator")
    if risky:
        add_finding(f, "low", "access_control", "Links to sensitive-looking resources", url,
                    f"Path(s): {fmt_list(risky, 3)}.",
                    "Remove backups, VCS folders and management endpoints from public exposure.", "indicator")
    if admin:
        add_finding(f, "informational", "access_control", "Links to administrative paths", url,
                    f"Path(s): {fmt_list(admin, 3)}.",
                    "Confirm administrative interfaces require strong authentication and network restrictions.",
                    "indicator")

    if dom["externalBlank"]:
        add_finding(f, "informational", "misconfig", "External links may lack rel=noopener", url,
                    f"{dom['externalBlank']} cross-origin link(s) use target=_blank without noopener/noreferrer.",
                    "Add rel=\"noopener\" (and optionally noreferrer) to target=_blank links.")


def check_body(f, url, status, body):
    # Error / stack-trace / debug disclosure
    error_seen = False
    seen_labels = set()
    for label, rx, sev, topic, title in ERROR_PATTERNS:
        m = rx.search(body)
        if m and (title, label) not in seen_labels:
            seen_labels.add((title, label))
            error_seen = True
            rec = ("Treat as a possible injection point: use parameterised queries, suppress database errors, "
                   "and confirm with authorised testing." if topic == "injection" else
                   "Disable debug mode and verbose errors in production; return generic error pages and log details server-side.")
            add_finding(f, sev, topic, title, url,
                        f"{label} pattern found: '{snippet(body, m)}'", rec,
                        "indicator" if topic == "injection" else "firm")

    if status and status >= 500:
        add_finding(f, "low", "exceptions", "Server error response", url,
                    f"HTTP {status} returned.",
                    "Handle failures gracefully with generic error pages; investigate the root cause.")
        error_seen = True

    if error_seen:
        m = PATH_DISCLOSURE_RE.search(body)
        if m:
            add_finding(f, "low", "exceptions", "Server file path disclosed in error output", url,
                        f"Path-like string found: '{snippet(body, m, 20)}'",
                        "Suppress internal paths in error responses.", "indicator")

    # Directory listing
    if re.search(r"<title>\s*Index of /|Directory listing for /", body, re.I):
        add_finding(f, "medium", "misconfig", "Directory listing enabled", url,
                    "Response looks like an auto-generated directory index.",
                    "Disable directory indexing on the web server.")

    # Secrets in page source (values are redacted)
    for label, rx, sev, conf in SECRET_PATTERNS:
        m = rx.search(body)
        if m:
            add_finding(f, sev, "crypto", f"Possible secret in page source: {label}", url,
                        f"Matched {label} (value redacted: {redact(m.group(0))}).",
                        "Remove secrets from client-delivered code; rotate the credential if it is real.", conf)


# --------------------------------------------------------------------------
# Page inspection
# --------------------------------------------------------------------------

async def read_body(response, ctype: str) -> str:
    if not response:
        return ""
    if ctype and not any(t in ctype for t in ("html", "json", "xml", "text", "javascript")):
        return ""
    try:
        return (await response.text())[:750_000]
    except Exception:
        return ""


async def inspect_page(page, url, response, state):
    f = state.findings
    status = response.status if response else None

    headers, set_cookies = {}, []
    # response.headers omits cookie-related headers; headers_array() keeps Set-Cookie.
    for h in (await response.headers_array() if response else []):
        name = h["name"].lower()
        if name == "set-cookie":
            set_cookies.append(h["value"])
        else:
            headers[name] = f"{headers[name]}, {h['value']}" if name in headers else h["value"]

    ctype = headers.get("content-type", "").lower()
    is_html = "html" in ctype or not ctype
    body = await read_body(response, ctype)

    check_body(f, url, status, body)
    if headers.get("x-debug-token") or headers.get("www-authenticate"):
        pass  # handled in check_headers when DOM is available

    if not is_html:
        return []

    dom = await page.evaluate(DOM_JS)

    check_transport(f, url, dom)
    check_cookies(f, url, set_cookies, dom, state)   # first: records SameSite for CSRF heuristic
    check_headers(f, url, headers, dom, state)
    check_forms(f, url, dom, state)
    check_third_party(f, url, dom, state)
    check_components(f, url, dom, state)
    check_injection(f, url, body, dom)
    check_urls(f, url, dom, state)

    return dom["links"]


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def build_coverage(findings, version):
    spec = OWASP_VERSIONS[version]
    rows = []
    for cid, cname in spec["categories"].items():
        topics = [t for t, c in spec["topics"].items() if c == cid]
        checks, level = [], "Minimal"
        for t in topics:
            lvl, cks = TOPIC_COVERAGE[t]
            checks.extend(cks)
            if LEVEL_RANK[lvl] > LEVEL_RANK[level]:
                level = lvl
        hits = [x for x in findings if x["owasp"].split(":")[0] == cid]
        counts = Counter(x["severity"] for x in hits)
        if hits:
            status = "Findings reported"
        elif level == "Minimal":
            status = "Not assessable passively"
        else:
            status = "No findings from passive checks"
        rows.append({
            "id": f"{cid}:{version}",
            "category": cname,
            "coverage": level,
            "checks_performed": checks,
            "findings": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
            "total_findings": len(hits),
            "status": status,
        })
    return rows


async def scan(args):
    start = args.url.rstrip("/")
    start_origin = origin(start)

    if start_origin[0] not in ("http", "https") or not start_origin[1]:
        raise ValueError("Provide a valid http:// or https:// URL.")

    base_host = re.sub(r"^www\.", "", start_origin[1])
    state = ScanState(base_host)
    visited = set()
    queue = deque([start])
    page_summaries = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=not args.headed)

        context_args = {}
        if args.storage_state:
            context_args["storage_state"] = args.storage_state

        context = await browser.new_context(**context_args)
        page = await context.new_page()
        page.set_default_timeout(15000)

        while queue and len(visited) < args.max_pages:
            current = urldefrag(queue.popleft())[0]

            if current in visited or origin(current) != start_origin:
                continue
            visited.add(current)

            try:
                response = await page.goto(current, wait_until="domcontentloaded")
                await page.wait_for_timeout(500)

                # Inspect the final URL so an HTTP->HTTPS redirect is not reported as HTTP.
                final_url = urldefrag(page.url)[0]
                if origin(final_url) != start_origin and origin(final_url)[1] != start_origin[1]:
                    continue
                visited.add(final_url)

                links = await inspect_page(page, final_url, response, state)

                page_summaries.append({
                    "url": final_url,
                    "status": response.status if response else None,
                    "title": await page.title(),
                })

                for link in links:
                    clean = urldefrag(link)[0]
                    if (clean and origin(clean) == start_origin and clean not in visited
                            and len(queue) < args.max_pages * 5):
                        queue.append(clean)

            except Exception as exc:
                add_finding(state.findings, "informational", "exceptions",
                            "Page could not be inspected", current,
                            f"{type(exc).__name__}: {str(exc)[:180]}",
                            "Check whether the page requires authentication or blocks browser navigation.",
                            "indicator")

        await context.close()
        await browser.close()

    # Tag with OWASP category, de-duplicate and sort
    version = args.owasp_version
    spec = OWASP_VERSIONS[version]
    unique = {}
    for fnd in state.findings:
        cid = spec["topics"][fnd["topic"]]
        fnd["owasp"] = f"{cid}:{version}"
        fnd["owasp_category"] = spec["categories"][cid]
        key = (fnd["severity"], fnd["topic"], fnd["title"], fnd["url"], fnd["evidence"])
        unique[key] = fnd

    findings = sorted(
        unique.values(),
        key=lambda x: (SEVERITY_ORDER.index(x["severity"]), x["owasp"], x["title"], x["url"]),
    )
    by_sev = Counter(x["severity"] for x in findings)

    report = {
        "scanner_version": SCANNER_VERSION,
        "target": start,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "owasp_version": spec["label"],
        "pages_scanned": len(page_summaries),
        "pages": page_summaries,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER},
        },
        "owasp_coverage": build_coverage(findings, version),
        "third_party_inventory": sorted(
            ({"host": h, "scripts": v["script"], "stylesheets": v["stylesheet"],
              "iframes": v["iframe"], "without_sri": v["without_sri"], "pages": len(v["pages"])}
             for h, v in state.third_party.items()),
            key=lambda r: -r["without_sri"]),
        "client_side_libraries": sorted(
            {"library": k, "pages": len(v)} for k, v in state.libraries.items()
        ) if False else [{"library": k, "pages": len(v)} for k, v in sorted(state.libraries.items())],
        "findings": findings,
        "scope_note": (
            "Passive, non-destructive checks only. No fuzzing, exploit payloads, brute force, "
            "credential guessing, or state-changing requests."
        ),
        "limitations": [
            "Coverage describes what this scanner looks for, not assurance that a category is free of issues.",
            "Findings marked 'indicator' are heuristics (CSRF, injection, auth, SSRF, design) and need manual validation.",
            "Insecure Design and Logging/Alerting need architecture review and server-side evidence.",
            "Content rendered after DOMContentLoaded + 0.5s, and authenticated areas without --storage-state, may be missed.",
        ],
    }

    output_path = Path(args.out)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_html(report, output_path.with_suffix(".html"))
    return report


def write_html(report, path):
    sev = report["summary"]["by_severity"]

    cards = "".join(
        f'<div class="card {s}"><div class="n">{sev[s]}</div><div>{escape(s.title())}</div></div>'
        for s in SEVERITY_ORDER
    )

    cov_rows = []
    for c in report["owasp_coverage"]:
        checks = "".join(f"<li>{escape(x)}</li>" for x in c["checks_performed"])
        fc = c["findings"]
        cov_rows.append(
            "<tr>"
            f"<td>{escape(c['id'])}</td>"
            f"<td>{escape(c['category'])}</td>"
            f"<td>{escape(c['coverage'])}</td>"
            f"<td><ul>{checks}</ul></td>"
            f"<td class='num'>{fc['high']}</td><td class='num'>{fc['medium']}</td>"
            f"<td class='num'>{fc['low']}</td><td class='num'>{fc['informational']}</td>"
            f"<td>{escape(c['status'])}</td>"
            "</tr>"
        )

    tp_rows = "".join(
        "<tr>"
        f"<td>{escape(t['host'])}</td><td class='num'>{t['scripts']}</td>"
        f"<td class='num'>{t['stylesheets']}</td><td class='num'>{t['iframes']}</td>"
        f"<td class='num'>{t['without_sri']}</td><td class='num'>{t['pages']}</td>"
        "</tr>"
        for t in report["third_party_inventory"]
    ) or "<tr><td colspan='6'>No third-party origins observed.</td></tr>"

    rows = []
    for fnd in report["findings"]:
        rows.append(
            "<tr>"
            f"<td><span class=\"badge {escape(fnd['severity'])}\">{escape(fnd['severity'].upper())}</span></td>"
            f"<td>{escape(fnd['owasp'])}<br><small>{escape(fnd['owasp_category'])}</small></td>"
            f"<td>{escape(fnd['title'])}<br><small>{escape(fnd['confidence'])}</small></td>"
            f"<td><a href=\"{escape(fnd['url'], quote=True)}\">{escape(fnd['url'])}</a></td>"
            f"<td>{escape(fnd['evidence'])}</td>"
            f"<td>{escape(fnd['recommendation'])}</td>"
            "</tr>"
        )

    limits = "".join(f"<li>{escape(x)}</li>" for x in report["limitations"])

    # Template avoids clashes between CSS braces and Python formatting.
    html_template = Template("""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CA QA - Web Security Agent Report</title>
<style>
body { font: 14px Arial; margin: 28px; color: #222; }
h2 { margin-top: 34px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 9px; text-align: left; vertical-align: top; }
th { background: #f3f5f7; }
td.num { text-align: center; }
ul { margin: 0; padding-left: 18px; }
small { color: #666; }
.cards { display: flex; gap: 12px; margin: 16px 0; }
.card { flex: 1; padding: 12px; border-radius: 6px; text-align: center; color: #fff; }
.card .n { font-size: 26px; font-weight: bold; }
.high { background: #b42318; }
.medium { background: #c2570c; }
.low { background: #946c00; }
.informational { background: #475467; }
.badge { color: #fff; padding: 2px 7px; border-radius: 4px; font-size: 12px; }
</style>
</head>
<body>

<h1>CA QA Web Security Agent</h1>
<p><b>Target:</b> $target</p>
<p><b>Generated:</b> $generated</p>
<p><b>Pages scanned:</b> $count &nbsp; <b>Framework:</b> $owasp</p>
<p>$scope</p>

<div class="cards">$cards</div>

<h2>OWASP coverage summary</h2>
<p><small>Coverage shows what the passive checks look for. "No findings" is not proof a category is secure.</small></p>
<table>
<thead><tr>
<th>ID</th><th>Category</th><th>Coverage</th><th>Checks performed</th>
<th>High</th><th>Med</th><th>Low</th><th>Info</th><th>Status</th>
</tr></thead>
<tbody>$coverage</tbody>
</table>

<h2>Third-party origins</h2>
<table>
<thead><tr><th>Host</th><th>Scripts</th><th>Stylesheets</th><th>Iframes</th><th>Without SRI</th><th>Pages</th></tr></thead>
<tbody>$thirdparty</tbody>
</table>

<h2>Findings</h2>
<table>
<thead><tr>
<th>Severity</th><th>OWASP</th><th>Finding</th><th>Page</th><th>Evidence</th><th>Recommendation</th>
</tr></thead>
<tbody>
$rows
</tbody>
</table>

<h2>Limitations</h2>
<ul>$limits</ul>

</body>
</html>
""")

    final_html = html_template.substitute(
        target=escape(report["target"]),
        generated=escape(report["generated_at"]),
        count=report["pages_scanned"],
        owasp=escape(report["owasp_version"]),
        scope=escape(report["scope_note"]),
        cards=cards,
        coverage="".join(cov_rows),
        thirdparty=tp_rows,
        rows="".join(rows),
        limits=limits,
    )

    path.write_text(final_html, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Small passive browser-based web security checker"
    )
    parser.add_argument("--url", required=True, help="Authorized application URL")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--out", default="security-report.json")
    parser.add_argument("--headed", action="store_true", help="Show Chromium while scanning")
    parser.add_argument("--storage-state", help="Optional Playwright storage-state JSON")
    parser.add_argument(
        "--owasp-version",
        choices=sorted(OWASP_VERSIONS),
        default="2025",
        help="OWASP Top 10 edition used for category mapping (default: 2025)",
    )

    args = parser.parse_args()

    if not 1 <= args.max_pages <= 100:
        parser.error("--max-pages must be between 1 and 100")

    report = asyncio.run(scan(args))

    print(f"Scanned {report['pages_scanned']} page(s).")
    print(f"Findings: {report['summary']['by_severity']}")
    print(f"\n{report['owasp_version']} coverage:")
    for c in report["owasp_coverage"]:
        print(f"  {c['id']:<9} {c['category']:<42} {c['coverage']:<16} "
              f"{c['total_findings']:>3} finding(s)  [{c['status']}]")
    print(f"\nJSON Report: {args.out}")
    print(f"HTML Report: {Path(args.out).with_suffix('.html')}")


if __name__ == "__main__":
    main()