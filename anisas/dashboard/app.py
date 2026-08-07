"""FastAPI backend — REST API + SSE streaming for the ANISAS dashboard."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .orchestrator import create_scan, get_scan, run_pipeline
from .pdf_export import generate_pdf_report

logger = logging.getLogger(__name__)

app = FastAPI(title="ANISAS Dashboard", version="1.0.0")

# Mount static files
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


# ── Security middleware ──────────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ── Rate limiting ────────────────────────────────────────────────────────

_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_WINDOW = 60.0  # seconds
_RATE_LIMIT_MAX = 10  # requests per window per IP


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if request is allowed, False if rate limited."""
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW
    _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if t > cutoff]
    if len(_rate_limit_store[client_ip]) >= _RATE_LIMIT_MAX:
        return False
    _rate_limit_store[client_ip].append(now)
    return True


# ── Input validation ────────────────────────────────────────────────────

_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
)


def _validate_target_ip(target: str) -> str | None:
    """Validate and sanitize a target IP address. Returns clean string or None."""
    target = target.strip()
    if not target or len(target) > 50:
        return None
    # Allow IP, IP/CIDR, hostname
    if not _IP_PATTERN.match(target):
        # Check if it's a valid hostname
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", target):
            return None
        return target
    # Validate IP parts
    try:
        parts = target.split("/")
        ip_parts = parts[0].split(".")
        for part in ip_parts:
            val = int(part)
            if val < 0 or val > 255:
                return None
        if len(parts) == 2:
            cidr = int(parts[1])
            if cidr < 0 or cidr > 32:
                return None
    except (ValueError, IndexError):
        return None
    return target


def _sanitize_filename(name: str) -> str:
    """Remove path traversal and dangerous chars from filenames."""
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)[:100]


# ── Routes ──────────────────────────────────────────────────────────────

@app.get("/favicon.ico")
async def favicon():
    return JSONResponse(content={}, status_code=204)


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main dashboard page."""
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.isfile(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>ANISAS Dashboard</h1><p>Template not found.</p>")


@app.post("/api/v1/scan/start")
async def start_scan(request: Request):
    """Start a new scan pipeline."""
    # Rate limit check
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return JSONResponse({"error": "Rate limit exceeded. Try again later."}, status_code=429)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    target_ip = body.get("target_ip", "").strip() if isinstance(body.get("target_ip"), str) else ""

    if not target_ip:
        return JSONResponse({"error": "target_ip is required"}, status_code=400)

    validated = _validate_target_ip(target_ip)
    if not validated:
        return JSONResponse({"error": "Invalid target IP address format"}, status_code=400)

    scan_id = create_scan(validated)

    # Launch pipeline in background
    asyncio.create_task(run_pipeline(scan_id))

    return JSONResponse({"scan_id": scan_id, "status": "STARTED"})


@app.get("/api/v1/scan/status/{scan_id}")
async def scan_status(scan_id: str):
    """Get current scan status."""
    # Validate scan_id format (UUID)
    if not re.match(r"^[a-f0-9\-]{36}$", scan_id):
        return JSONResponse({"error": "Invalid scan ID format"}, status_code=400)

    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    return JSONResponse({
        "scan_id": scan["scan_id"],
        "target_ip": scan["target_ip"],
        "status": scan["status"],
        "current_module": scan["current_module"],
        "modules": scan["modules"],
        "created_at": scan["created_at"],
    })


@app.get("/api/v1/scan/stream/{scan_id}")
async def scan_stream(scan_id: str):
    """SSE endpoint for real-time log streaming."""
    if not re.match(r"^[a-f0-9\-]{36}$", scan_id):
        return JSONResponse({"error": "Invalid scan ID format"}, status_code=400)

    async def event_generator():
        last_idx = 0
        while True:
            scan = get_scan(scan_id)
            if not scan:
                yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                break

            logs = scan["logs"]
            while last_idx < len(logs):
                entry = logs[last_idx]
                yield f"data: {json.dumps(entry)}\n\n"
                last_idx += 1

            if scan["status"] == "COMPLETE":
                yield f"data: {json.dumps({'module': 'Orchestrator', 'status': 'COMPLETE', 'log_message': 'Pipeline finished.', 'timestamp': datetime.utcnow().isoformat() + 'Z'})}\n\n"
                break

            if scan["status"] == "CREATED":
                yield f"data: {json.dumps({'module': 'Orchestrator', 'status': 'WAITING', 'log_message': 'Waiting to start...', 'timestamp': datetime.utcnow().isoformat() + 'Z'})}\n\n"

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/v1/scan/results/{scan_id}")
async def scan_results(scan_id: str):
    """Get complete scan results."""
    if not re.match(r"^[a-f0-9\-]{36}$", scan_id):
        return JSONResponse({"error": "Invalid scan ID format"}, status_code=400)

    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    return JSONResponse(scan["results"])


@app.get("/api/v1/export/json/{scan_id}")
async def export_json(scan_id: str):
    """Export complete scan results as JSON."""
    if not re.match(r"^[a-f0-9\-]{36}$", scan_id):
        return JSONResponse({"error": "Invalid scan ID format"}, status_code=400)

    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    content = json.dumps(scan["results"], indent=2, default=str)
    safe_ip = _sanitize_filename(scan["target_ip"])
    safe_date = _sanitize_filename(scan["created_at"][:10])
    filename = f"ANISAS_Report_{safe_ip}_{safe_date}.json"

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/v1/export/pdf/{scan_id}")
async def export_pdf(scan_id: str):
    """Export scan results as PDF."""
    if not re.match(r"^[a-f0-9\-]{36}$", scan_id):
        return JSONResponse({"error": "Invalid scan ID format"}, status_code=400)

    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "output")
    os.makedirs(output_dir, exist_ok=True)
    safe_ip = _sanitize_filename(scan["target_ip"])
    safe_date = _sanitize_filename(scan["created_at"][:10])
    pdf_path = os.path.join(output_dir, f"ANISAS_Report_{safe_ip}_{safe_date}.pdf")

    generate_pdf_report(scan["results"], scan["target_ip"], pdf_path)

    filename = os.path.basename(pdf_path)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=filename,
    )


def run_dashboard(host: str = "127.0.0.1", port: int = 8000):
    """Run the dashboard server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
