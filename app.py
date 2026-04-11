"""LiquidSystem — FastAPI web application.

Exposes:
  POST /api/run            — trigger a new analysis (runs in background)
  GET  /api/run/status     — poll run progress
  GET  /api/reports        — list all saved reports (metadata only)
  GET  /api/reports/latest — full JSON for the most recent report
  GET  /api/reports/{id}   — full JSON for a specific report
  GET  /                   — serves the dashboard SPA
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from runner import run_analysis

load_dotenv()

# ---------------------------------------------------------------------------
# Config (overridable via environment variables)
# ---------------------------------------------------------------------------

DATA_DIR = Path(os.environ.get("REPORTS_DIR", "data/reports"))
MAX_REPORTS = int(os.environ.get("MAX_REPORTS", "30"))
# Hour (0–23 UTC) at which the daily automated run fires.
SCHEDULE_HOUR = int(os.environ.get("SCHEDULE_HOUR", "11"))  # 11:00 UTC = 6:00 AM Indianapolis

_STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# In-memory run status — resets on server restart, intentionally ephemeral.
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
    """Run the full analysis pipeline. Caller must set running=True first."""
    try:
        report = await run_analysis()
        _save_report(report)
        _run_status["last_completed"] = report["id"]
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
    """Delete oldest reports when count exceeds MAX_REPORTS."""
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
# Routes — order matters: literal paths must come before parameterized ones.
# ---------------------------------------------------------------------------


@app.post("/api/run")
async def api_run(background_tasks: BackgroundTasks) -> JSONResponse:
    """Trigger a new analysis run. Returns 409 if one is already in progress."""
    if _run_status["running"]:
        return JSONResponse({"status": "already_running"}, status_code=409)
    # Set running immediately (before background task starts) to prevent
    # a second concurrent request from also starting a run.
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
    """Return a list of {id, created_at} metadata for all saved reports, newest first."""
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
    """Return the full JSON for the most recently saved report."""
    paths = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True)
    if not paths:
        raise HTTPException(status_code=404, detail="No reports yet")
    try:
        return JSONResponse(json.loads(paths[0].read_text(encoding="utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/reports/{report_id}")
async def api_report(report_id: str) -> JSONResponse:
    """Return the full JSON for a specific report by ID."""
    # Sanitize: only allow alphanumeric + hyphens + underscores
    if not all(c.isalnum() or c in "-_" for c in report_id):
        raise HTTPException(status_code=400, detail="Invalid report ID")
    path = DATA_DIR / f"{report_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# Serve static assets (CSS, JS, favicon if added later)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
