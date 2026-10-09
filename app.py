"""Security Header Auditor: enter a URL, get a graded report on its HTTP security headers.

Run:  uvicorn app:app --reload      then open http://127.0.0.1:8000
"""

import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from audit_rules import audit
from safe_fetch import BlockedAddressError, fetch_headers

app = FastAPI(title="Security Header Auditor")

# Best-effort limiter kept in memory. It slows casual abuse but is not a hard guarantee; behind a
# proxy or load balancer, key it on a trusted forwarded address instead of the socket address.
WINDOW_SECONDS = 60
MAX_PER_WINDOW = int(os.environ.get("AUDIT_MAX_PER_MINUTE", "8"))
_hits: dict[str, deque] = defaultdict(deque)


def _rate_limited(client: str) -> bool:
    now = time.monotonic()
    recent = _hits[client]
    while recent and now - recent[0] >= WINDOW_SECONDS:
        recent.popleft()
    recent.append(now)
    if len(_hits) > 5000:  # keep memory bounded
        for key in [k for k, v in _hits.items() if not v or now - v[-1] >= WINDOW_SECONDS]:
            del _hits[key]
    return len(recent) > MAX_PER_WINDOW


def _json(body: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


@app.get("/", response_class=HTMLResponse)
async def home():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.post("/api/audit")
async def api_audit(request: Request):
    client = request.client.host if request.client else "unknown"
    if _rate_limited(client):
        return _json({"error": "Too many requests. Please wait a minute and try again."}, 429)

    try:
        raw = (await request.json()).get("url")
    except Exception:
        return _json({"error": 'Send JSON like { "url": "example.com" }.'}, 400)
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 2048:
        return _json({"error": "Please enter a URL (up to 2048 characters)."}, 400)

    raw = raw.strip()
    target = raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else f"https://{raw}"
    try:
        if not urlsplit(target).hostname:
            raise ValueError
    except ValueError:
        return _json({"error": "That doesn't look like a valid URL."}, 400)

    try:
        result = await fetch_headers(target)
    except BlockedAddressError:
        return _json(
            {"error": "That address isn't allowed. Private, local and internal addresses are blocked."}, 400
        )
    except Exception:
        return _json(
            {"error": "Couldn't reach that site (it may be offline, too slow, or have a TLS problem)."}, 502
        )

    is_https = urlsplit(result.final_url).scheme == "https"
    return _json(
        {
            "requestedUrl": target,
            "finalUrl": result.final_url,
            "status": result.status,
            "redirects": result.redirects,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            **audit(result.headers, is_https),
        }
    )
