"""Web UI + API for the security agent.

Run:  python -m security_agent.web.app      (do NOT use --reload on Windows: Playwright needs the Proactor loop)
Env:  SCAN_ALLOWED_HOSTS  comma list: exact hosts, wildcards (*.qa.example.com) or CIDRs (10.128.0.0/16)
      SCAN_CONCURRENCY    parallel scans (default 2)
      HOST / PORT         bind address (default 127.0.0.1:8000)
"""
from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import json
import os
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import runner, store

app = FastAPI(title="CA QA Security Agent")
STATIC = Path(__file__).parent / "static"
SEM = asyncio.Semaphore(int(os.environ.get("SCAN_CONCURRENCY", "2")))
ALLOWED = [x.strip() for x in os.environ.get("SCAN_ALLOWED_HOSTS", "").split(",") if x.strip()]
TASKS: set = set()


def host_allowed(host: str) -> bool:
    for pat in ALLOWED:
        if "/" in pat:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(pat, strict=False):
                    return True
            except ValueError:
                continue
        elif fnmatch.fnmatch(host.lower(), pat.lower()):
            return True
    return False


class ScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=20)
    modules: list[str] = Field(min_length=1)
    authorized: bool = False
    max_pages: int = Field(20, ge=1, le=100)
    owasp_version: str = "2025"
    storage_state: str | None = None
    requested_by: str = ""


@app.on_event("startup")
def _startup():
    store.init()


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/modules")
def modules():
    return {"modules": [{"id": k, **v} for k, v in runner.MODULES.items()],
            "active_allowed_hosts_configured": bool(ALLOWED)}


async def _run(scan_id, url, req: ScanRequest):
    async with SEM:
        await runner.run_scan(scan_id, url, req.modules, req.max_pages, req.owasp_version, req.storage_state)


@app.post("/api/scans")
async def create_scans(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(400, "Confirm that you are authorised to test these applications.")
    unknown = [m for m in req.modules if m not in runner.MODULES]
    if unknown:
        raise HTTPException(400, f"Unknown check(s): {', '.join(unknown)}")
    if req.owasp_version not in ("2025", "2021"):
        raise HTTPException(400, "owasp_version must be 2025 or 2021")
    if req.storage_state:
        try:
            json.loads(req.storage_state)
        except ValueError:
            raise HTTPException(400, "Storage state is not valid JSON.")
    active = any(runner.MODULES[m]["active"] for m in req.modules)

    urls = []
    for u in dict.fromkeys(x.strip().rstrip("/") for x in req.urls if x.strip()):
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise HTTPException(400, f"Not a valid http(s) URL: {u}")
        if ALLOWED and not host_allowed(p.hostname):
            raise HTTPException(403, f"{p.hostname} is not on the scan allow-list.")
        if active and not host_allowed(p.hostname):
            raise HTTPException(403, "Injection testing only runs against allow-listed hosts "
                                     "(set SCAN_ALLOWED_HOSTS on the server).")
        urls.append(u)
    if not urls:
        raise HTTPException(400, "Enter at least one URL.")

    ids = []
    for u in urls:
        sid = uuid.uuid4().hex[:12]
        store.create(sid, u, req.modules, req.requested_by)
        t = asyncio.create_task(_run(sid, u, req))
        TASKS.add(t)
        t.add_done_callback(TASKS.discard)
        ids.append(sid)
    return {"ids": ids}


@app.get("/api/scans")
def list_scans():
    return {"scans": store.list_scans()}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    s = store.get(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return s


@app.get("/api/scans/{scan_id}/report.html")
def report_html(scan_id: str):
    p = runner.REPORT_DIR / scan_id / "report.html"
    if not scan_id.isalnum() or not p.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(p)


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: str):
    p = runner.REPORT_DIR / scan_id / "report.json"
    if not scan_id.isalnum() or not p.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(p, media_type="application/json", filename=f"security-report-{scan_id}.json")


@app.get("/api/dashboard")
def dashboard():
    targets = {}
    for r in store.score_history():
        t = targets.setdefault(r["target"], {"target": r["target"], "history": []})
        t["history"].append({"id": r["id"], "at": r["created_at"], "score": r["score"],
                             "by_severity": (r["summary"] or {}).get("by_severity", {})})
    return {"targets": sorted(targets.values(), key=lambda t: t["history"][-1]["score"])}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
