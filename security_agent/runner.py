"""Orchestrator: runs the crawl, the selected modules, scoring and regression, and writes the report."""
from __future__ import annotations

import json
import os
from argparse import Namespace
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import scanner, scoring, store
from .modules import Ctx, api, auth, injection, mk, owasp_extra

REPORT_DIR = Path(os.environ.get("REPORT_DIR", "reports"))

# id -> metadata shown in the UI. `active` modules send probe requests and are allow-list gated.
MODULES = {
    "crawl_headers": {"label": "Browser crawling and security headers", "priority": "Built", "active": False},
    "owasp": {"label": "OWASP Top 10 security checks", "priority": "High", "active": False},
    "auth": {"label": "Login/authentication and session security", "priority": "High", "active": False},
    "injection": {"label": "XSS and SQL injection testing (controlled environments)", "priority": "High", "active": True},
    "api": {"label": "API security testing", "priority": "Medium", "active": False},
    "dashboard": {"label": "Security dashboard and risk scoring", "priority": "Medium", "active": False},
    "regression": {"label": "Automatic security regression reports", "priority": "Medium", "active": False},
}
RUN_ORDER = [("owasp", owasp_extra), ("auth", auth), ("injection", injection), ("api", api)]
CRAWL_TOPICS = {"misconfig", "crypto", "components", "integrity", "exceptions", "logging"}


def claim(selected: set, topic: str):
    """Which selected module 'owns' a finding produced by the base crawl (None = not selected)."""
    if "auth" in selected and topic == "auth":
        return "auth"
    if "injection" in selected and topic == "injection":
        return "injection"
    if "crawl_headers" in selected and topic in CRAWL_TOPICS:
        return "crawl_headers"
    if "owasp" in selected:
        return "owasp"
    return None


async def run_scan(scan_id, url, modules, max_pages=20, owasp_version="2025", storage_state_json=None):
    selected = set(modules)
    out_dir = REPORT_DIR / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = None
    try:
        if storage_state_json:
            state_path = out_dir / "_state.json"
            state_path.write_text(storage_state_json, encoding="utf-8")

        store.update(scan_id, status="running", progress="Crawling pages")
        crawl = await scanner.scan(Namespace(
            url=url, max_pages=max_pages, out=str(out_dir / "_crawl.json"), headed=False,
            storage_state=str(state_path) if state_path else None, owasp_version=owasp_version))

        findings = []
        for f in crawl["findings"]:
            m = claim(selected, f["topic"])
            if m:
                f["module"] = m
                findings.append(f)

        ctx = Ctx(url=url, pages=[p["url"] for p in crawl["pages"]] or [url],
                  storage_state=str(state_path) if state_path else None, max_pages=max_pages)
        for mid, mod in RUN_ORDER:
            if mid not in selected:
                continue
            store.update(scan_id, progress=f"Running: {MODULES[mid]['label']}")
            try:
                new = await mod.run(ctx)
            except Exception as exc:
                new = [mk("informational", "exceptions", f"Module '{mid}' failed", url,
                          f"{type(exc).__name__}: {str(exc)[:200]}", "Check the server log and re-run.", "indicator")]
            for n in new:
                n["module"] = mid
            findings += new

        # tag, fingerprint, de-duplicate, sort
        spec = scanner.OWASP_VERSIONS[owasp_version]
        unique = {}
        for f in findings:
            cid = spec["topics"][f["topic"]]
            f["owasp"], f["owasp_category"] = f"{cid}:{owasp_version}", spec["categories"][cid]
            f.setdefault("key", "")
            f["fingerprint"] = scoring.fingerprint(f)
            unique[(f["fingerprint"], f["evidence"])] = f
        findings = sorted(unique.values(), key=lambda x: (
            scanner.SEVERITY_ORDER.index(x["severity"]), x["owasp"], x["title"], x["url"]))
        by_sev = Counter(f["severity"] for f in findings)

        extra_limits = []
        if "injection" in selected:
            extra_limits.append("Injection testing used GET parameters and canary probes only; POST forms were not submitted.")
        if "auth" in selected:
            extra_limits.append("Brute force, lockout and password-reset abuse are deliberately not tested.")
        report = {
            "scanner_version": scanner.SCANNER_VERSION, "target": url,
            "generated_at": datetime.now(timezone.utc).isoformat(), "scan_id": scan_id,
            "modules": sorted(selected), "owasp_version": spec["label"],
            "pages_scanned": crawl["pages_scanned"], "pages": crawl["pages"],
            "summary": {"total_findings": len(findings),
                        "by_severity": {s: by_sev.get(s, 0) for s in scanner.SEVERITY_ORDER}},
            "owasp_coverage": scanner.build_coverage(findings, owasp_version),
            "third_party_inventory": crawl["third_party_inventory"],
            "findings": findings,
            "scope_note": crawl["scope_note"] if "injection" not in selected else
            "Passive checks plus controlled, allow-listed GET-parameter probes (canary strings only). "
            "No brute force, credential guessing, or state-changing requests.",
            "limitations": crawl["limitations"] + extra_limits,
        }

        score = None
        if "dashboard" in selected:
            report["risk"] = scoring.risk_score(findings)
            score = report["risk"]["score"]
        if "regression" in selected:
            prev = store.previous_completed(url, selected, scan_id)
            report["regression"] = (scoring.compare(findings, prev["report"], prev) if prev else
                                    {"status": "no_baseline",
                                     "message": "No earlier scan with the same URL and the same checks. This scan becomes the baseline."})

        (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        scanner.write_html(report, out_dir / "report.html")
        store.update(scan_id, status="done", progress="Finished", finished_at=store.now(),
                     score=score, summary=report["summary"], report=report)
    except Exception as exc:
        store.update(scan_id, status="failed", progress="Failed", finished_at=store.now(),
                     error=f"{type(exc).__name__}: {str(exc)[:300]}")
    finally:
        for name in ("_state.json", "_crawl.json", "_crawl.html"):   # never keep credentials around
            (out_dir / name).unlink(missing_ok=True)
