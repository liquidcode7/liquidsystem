"""LiquidSystem — FastAPI web application.

Exposes:
  POST /api/run              — trigger a new analysis (runs in background)
  GET  /api/run/status       — poll run progress
  GET  /api/reports          — list all saved reports (metadata only)
  GET  /api/reports/latest   — full JSON for the most recent report
  GET  /api/reports/{id}     — full JSON for a specific report
  POST /api/logs/clear       — clear fail2ban logs from selected containers
  POST /api/chat             — send a message; streams SSE tokens from Claude
  POST /api/chat/reset       — clear conversation history for a session
  GET  /                     — serves the dashboard SPA
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import anthropic
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import log_cleaner
import notifier
from assessment import MODEL, build_audit_context
from fail2ban import CONTAINERS
from runner import run_analysis

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DATA_DIR    = Path(os.environ.get("REPORTS_DIR", "data/reports"))
MAX_REPORTS = int(os.environ.get("MAX_REPORTS", "30"))
# 11:00 UTC = 6:00 AM Indianapolis (EST = UTC-5)
SCHEDULE_HOUR = int(os.environ.get("SCHEDULE_HOUR", "11"))

_STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# In-memory run status
# ---------------------------------------------------------------------------

_run_status: dict = {
    "running": False,
    "started_at": None,
    "error": None,
    "last_completed": None,
}

# ---------------------------------------------------------------------------
# Core run logic
# ---------------------------------------------------------------------------


async def _execute_run() -> None:
    try:
        report = await run_analysis()
        _save_report(report)
        _run_status["last_completed"] = report["id"]
        await notifier.notify_report_complete(report)
    except Exception as exc:
        _run_status["error"] = str(exc)
    finally:
        _run_status["running"] = False


def _save_report(report: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / f"{report['id']}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _prune_old_reports()


def _prune_old_reports() -> None:
    reports = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name)
    while len(reports) > MAX_REPORTS:
        reports[0].unlink()
        reports = reports[1:]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

scheduler = AsyncIOScheduler()


async def _scheduled_run() -> None:
    if _run_status["running"]:
        return
    _run_status.update({
        "running": True,
        "started_at": datetime.now().isoformat(),
        "error": None,
    })
    await _execute_run()


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    scheduler.add_job(_scheduled_run, "cron", hour=SCHEDULE_HOUR, minute=0)
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="LiquidSystem", lifespan=lifespan)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post("/api/run")
async def api_run(background_tasks: BackgroundTasks) -> JSONResponse:
    if _run_status["running"]:
        return JSONResponse({"status": "already_running"}, status_code=409)
    _run_status.update({
        "running": True,
        "started_at": datetime.now().isoformat(),
        "error": None,
    })
    background_tasks.add_task(_execute_run)
    return JSONResponse({"status": "started"})


@app.get("/api/run/status")
async def api_run_status() -> dict:
    return _run_status


@app.get("/api/reports")
async def api_reports() -> list:
    reports = []
    for path in sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            reports.append({
                "id": data.get("id", path.stem),
                "created_at": data.get("created_at", ""),
            })
        except Exception:
            pass
    return reports


@app.get("/api/reports/latest")
async def api_reports_latest() -> JSONResponse:
    paths = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True)
    if not paths:
        raise HTTPException(status_code=404, detail="No reports yet")
    try:
        return JSONResponse(json.loads(paths[0].read_text(encoding="utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/reports/{report_id}")
async def api_report(report_id: str) -> JSONResponse:
    if not all(c.isalnum() or c in "-_" for c in report_id):
        raise HTTPException(status_code=400, detail="Invalid report ID")
    path = DATA_DIR / f"{report_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/reports/{report_id}/export")
async def api_report_export(report_id: str) -> HTMLResponse:
    """Render the report as a self-contained HTML file, then delete the stored JSON."""
    if not all(c.isalnum() or c in "-_" for c in report_id):
        raise HTTPException(status_code=400, detail="Invalid report ID")
    path = DATA_DIR / f"{report_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # Reconstruct typed objects from stored JSON
    from bypass import BypassData
    from device_identifier import DeviceInfo, NetworkRiskSummary
    from recommender import RecommenderData
    from report import render_html
    from traffic import TrafficData

    try:
        traffic     = TrafficData(**data["traffic_data"])    if data.get("traffic_data") else None
        bypass      = BypassData(**data["bypass_data"])      if data.get("bypass_data")  else None
        rec         = RecommenderData(**data["rec_data"])     if data.get("rec_data")     else None
        client_names = data.get("client_names") or {}
        raw_devices  = data.get("device_map") or {}
        device_map   = {ip: DeviceInfo(**info) for ip, info in raw_devices.items()}
        raw_risk     = data.get("risk_summary")
        risk_summary = NetworkRiskSummary(**raw_risk) if raw_risk else None
        assessment   = data.get("assessment_text")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse report data: {exc}")

    # Render to an in-memory temp file, read it, then clean up
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        render_html(
            traffic_data=traffic,
            bypass_data=bypass,
            rec_data=rec,
            client_names=client_names,
            output_path=tmp_path,
            assessment_text=assessment,
            device_map=device_map,
            risk_summary=risk_summary,
        )
        html_bytes = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)

    # Delete the stored JSON report
    path.unlink(missing_ok=True)

    filename = f"liquidsystem-{report_id}.html"
    return HTMLResponse(
        content=html_bytes,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Log clear endpoint
# ---------------------------------------------------------------------------

class ClearRequest(BaseModel):
    container_ids: list[str]


@app.post("/api/logs/clear")
async def api_logs_clear(req: ClearRequest) -> JSONResponse:
    """Clear fail2ban logs and active bans from selected containers / Proxmox host."""
    # Build label map from known containers
    labels: dict[str, str] = {ct_id: label for ct_id, (_, label) in CONTAINERS.items()}
    labels["host"] = "proxmox"

    # Validate: only allow known container IDs and "host"
    valid_ids = set(CONTAINERS.keys()) | {"host"}
    unknown = [cid for cid in req.container_ids if cid not in valid_ids]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown container IDs: {unknown}")

    report = await log_cleaner.clear_containers(req.container_ids, labels)

    return JSONResponse({
        "results": [
            {
                "ct_id":           r.ct_id,
                "label":           r.label,
                "success":         r.success,
                "log_bytes_freed": r.log_bytes_freed,
                "error":           r.error,
            }
            for r in report.results
        ],
        "total_bytes_freed": report.total_bytes_freed,
        "errors": report.errors,
    })


# ---------------------------------------------------------------------------
# Chat sessions
# ---------------------------------------------------------------------------

# Keyed by session_id (string). Each value is a list of {role, content} dicts.
_chat_sessions: dict[str, list[dict]] = {}

_CHAT_SYSTEM_PROMPT = """\
You are a network security and privacy analyst who has just completed a full DNS \
audit of the user's home network. The complete audit data is embedded at the end \
of this prompt — reference it directly in every answer.

The user's setup:
  - OPNsense firewall/router
  - Pi-hole v6 DNS filter
  - Proxmox hypervisor
  - Various self-hosted services on a home LAN

Conversation rules:
1. Always reference actual IPs, domains, and counts from the audit data. \
Never give generic advice when real data is available.
2. When generating configs, firewall rules, blocklists, or CLI commands, \
wrap them in fenced code blocks (e.g. ```bash, ```yaml, ```xml).
3. If the user says "do it", "apply that", "make that change", or similar: \
state clearly that OPNsense/Pi-hole API integration is not yet implemented, \
then show exactly what the change would be — the full command, config snippet, \
or API call — so they can copy-paste it themselves.
4. Format responses clearly with headers and lists where helpful. \
Use markdown — the UI renders it.
5. You already gave an initial assessment. Build on it rather than repeating it.

--- AUDIT DATA ---
{audit_context}
"""


def _build_chat_system(report: dict) -> str:
    """Build the system prompt with live audit context from a report dict."""
    from bypass import BypassData
    from device_identifier import DeviceInfo
    from recommender import RecommenderData
    from traffic import TrafficData

    try:
        traffic = TrafficData(**report["traffic_data"]) if report.get("traffic_data") else None
        bypass  = BypassData(**report["bypass_data"])   if report.get("bypass_data")  else None
        rec     = RecommenderData(**report["rec_data"])  if report.get("rec_data")     else None
        raw_devices = report.get("device_map") or {}
        devices = {ip: DeviceInfo(**info) for ip, info in raw_devices.items()}
        context = build_audit_context(traffic, bypass, rec, devices)
    except Exception:
        context = "(Audit data could not be parsed — answer based on general home lab security best practices.)"

    # Also inject the initial assessment so Claude knows what it already said
    assessment = report.get("assessment_text", "")
    if assessment:
        context += f"\n\n--- INITIAL ASSESSMENT ---\n{assessment}"

    return _CHAT_SYSTEM_PROMPT.format(audit_context=context)


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    report_id: str | None = None  # which report to use for context


class ChatResetRequest(BaseModel):
    session_id: str = "default"


@app.post("/api/chat")
async def api_chat(req: ChatRequest) -> StreamingResponse:
    """Stream a Claude response via Server-Sent Events."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not set")

    # Load report for context
    report: dict = {}
    if req.report_id:
        rpath = DATA_DIR / f"{req.report_id}.json"
        if rpath.exists():
            report = json.loads(rpath.read_text(encoding="utf-8"))
    else:
        # Fall back to latest
        paths = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True)
        if paths:
            report = json.loads(paths[0].read_text(encoding="utf-8"))

    system_prompt = _build_chat_system(report)

    history = _chat_sessions.setdefault(req.session_id, [])
    history.append({"role": "user", "content": req.message})

    # Snapshot messages for the thread (history is mutable)
    messages_snapshot = list(history)

    async def event_stream():
        client = anthropic.Anthropic(api_key=api_key)
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def stream_in_thread():
            try:
                with client.messages.stream(
                    model=MODEL,
                    max_tokens=4096,
                    system=system_prompt,
                    messages=messages_snapshot,
                ) as stream:
                    for chunk in stream.text_stream:
                        loop.call_soon_threadsafe(queue.put_nowait, {"token": chunk})
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, {"error": str(exc)})
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

        executor = ThreadPoolExecutor(max_workers=1)
        loop.run_in_executor(executor, stream_in_thread)

        full_text: list[str] = []
        while True:
            item = await queue.get()
            if item is None:
                break
            if "error" in item:
                yield f"data: {json.dumps({'error': item['error']})}\n\n"
                return
            token = item["token"]
            full_text.append(token)
            yield f"data: {json.dumps({'token': token})}\n\n"

        response_text = "".join(full_text)
        history.append({"role": "assistant", "content": response_text})
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/chat/reset")
async def api_chat_reset(req: ChatResetRequest) -> JSONResponse:
    """Clear conversation history for a session."""
    _chat_sessions.pop(req.session_id, None)
    return JSONResponse({"status": "cleared"})


# ---------------------------------------------------------------------------
# Static files and root
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
