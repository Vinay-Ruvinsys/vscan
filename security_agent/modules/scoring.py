"""Risk scoring and regression comparison."""
from __future__ import annotations

import hashlib
import math
from collections import Counter, defaultdict
from urllib.parse import urlparse

WEIGHTS = {"high": 10, "medium": 4, "low": 1, "informational": 0}


def fingerprint(f: dict) -> str:
    """Stable identity for a finding across scans (same issue, same place)."""
    p = urlparse(f["url"])
    raw = "|".join([f["topic"], f["title"], p.netloc, p.path, f.get("key", "")])
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def risk_score(findings: list) -> dict:
    """100 minus a penalty per *distinct issue*. The same issue on many pages costs more,
    but only logarithmically, so 13 pages missing one header do not swamp a real flaw.
    Heuristic ('indicator') issues count half."""
    groups = defaultdict(list)
    for f in findings:
        groups[(f["severity"], f["title"])].append(f)
    penalty, top = 0.0, []
    for (sev, title), items in groups.items():
        w = WEIGHTS[sev]
        if not w:
            continue
        p = w * (1 + 0.5 * math.log2(len(items)))
        if all(i["confidence"] == "indicator" for i in items):
            p *= 0.5
        penalty += p
        top.append({"title": title, "severity": sev, "occurrences": len(items), "penalty": round(p, 1)})
    score = max(0, round(100 - penalty))
    by_owasp = Counter(f["owasp_category"] for f in findings if f["severity"] != "informational")
    by_module = Counter(f["module"] for f in findings)
    return {
        "score": score, "grade": grade(score),
        "top_risks": sorted(top, key=lambda t: -t["penalty"])[:8],
        "by_owasp": dict(by_owasp.most_common()),
        "by_module": dict(by_module),
    }


def _brief(f):
    return {k: f[k] for k in ("severity", "title", "url", "module")}


def compare(current: list, prev_report: dict, prev_meta: dict) -> dict:
    cur = {f["fingerprint"]: f for f in current}
    old = {f["fingerprint"]: f for f in prev_report.get("findings", [])}
    new = [_brief(cur[k]) for k in cur.keys() - old.keys()]
    resolved = [_brief(old[k]) for k in old.keys() - cur.keys()]
    order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    new.sort(key=lambda f: order[f["severity"]])
    resolved.sort(key=lambda f: order[f["severity"]])
    regressed = any(f["severity"] in ("high", "medium") for f in new)
    return {
        "baseline": {"scan_id": prev_meta["id"], "created_at": prev_meta["created_at"], "score": prev_meta.get("score")},
        "new": new, "resolved": resolved, "persisting": len(cur.keys() & old.keys()),
        "status": "regressed" if regressed else ("improved" if resolved and not new else "unchanged" if not new else "minor changes"),
    }
