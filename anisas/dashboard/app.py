"""FastAPI backend — REST API + SSE streaming for the ANISAS dashboard."""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .orchestrator import create_scan, get_scan, run_pipeline
from .pdf_export import generate_pdf_report

app = FastAPI(title="ANISAS Dashboard", version="1.0.0")

# Mount static files
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


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
    body = await request.json()
    target_ip = body.get("target_ip", "").strip()

    if not target_ip:
        return JSONResponse({"error": "target_ip is required"}, status_code=400)

    scan_id = create_scan(target_ip)

    # Launch pipeline in background
    asyncio.create_task(run_pipeline(scan_id))

    return JSONResponse({"scan_id": scan_id, "status": "STARTED"})


@app.get("/api/v1/scan/status/{scan_id}")
async def scan_status(scan_id: str):
    """Get current scan status."""
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
    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    return JSONResponse(scan["results"])


@app.get("/api/v1/export/json/{scan_id}")
async def export_json(scan_id: str):
    """Export complete scan results as JSON."""
    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    content = json.dumps(scan["results"], indent=2, default=str)
    filename = f"ANISAS_Report_{scan['target_ip']}_{scan['created_at'][:10]}.json"

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/v1/export/pdf/{scan_id}")
async def export_pdf(scan_id: str):
    """Export scan results as PDF."""
    scan = get_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "output")
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = os.path.join(output_dir, f"ANISAS_Report_{scan['target_ip']}_{scan['created_at'][:10]}.pdf")

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
