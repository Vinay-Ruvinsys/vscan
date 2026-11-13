# Mini Web Security Agent

A small Python + Playwright browser agent for **authorized, non-destructive** first-pass checks of your own web application.

## What it checks

- HTTPS usage
- Common response security headers: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Cookie attributes: Secure, HttpOnly, SameSite (cookie values are never stored in the report)
- Mixed-content resource references
- Password forms that use HTTP or submit to an HTTP destination
- `target="_blank"` links missing `rel="noopener"`
- Potentially sensitive input field names (field values are never read)

It crawls same-origin links only, up to a configurable page limit, and creates JSON and HTML reports.

## What it deliberately does NOT do

No exploit payloads, fuzzing, brute force, directory enumeration, SQL injection attempts, XSS injection, authentication bypass, destructive requests, or load testing. This is a baseline checker, not a replacement for a professional penetration test or OWASP ZAP/Burp assessment.

## Setup (Windows / PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

## Run

```powershell
python -m security_agent.scanner --url https://your-test-app.example --max-pages 20
```

Show the browser:

```powershell
python -m security_agent.scanner --url https://your-test-app.example --headed
```

For an authenticated test environment, export Playwright storage state from a dedicated test account and pass it in:

```powershell
python -m security_agent.scanner --url https://your-test-app.example --storage-state .\test-auth.json
```

Treat `test-auth.json` as a password: do not commit or share it. Use a dedicated low-privilege test account. The scanner does not submit forms or click buttons.

## Output

- `security-report.json`
- `security-report.html`

Severity is a triage hint, not proof of exploitability. Review findings manually and confirm your application's intended security policy before changing configuration.

## Safe operating rules

1. Scan only applications you own or have explicit written permission to test.
2. Start with staging / QA, not production.
3. Keep the page limit low initially.
4. Use test accounts and synthetic data.
5. Do not scan third-party hosts or follow links outside the starting origin.
