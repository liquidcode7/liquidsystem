"""Sends a push notification to the self-hosted ntfy instance after each report run.

Configuration (via .env or environment):
  NTFY_URL   — base URL of your ntfy server (default: http://192.168.1.26:8080)
  NTFY_TOPIC — topic name (default: LiquidLab)
  NTFY_ENABLED — set to "false" to disable without removing config (default: true)
"""

from __future__ import annotations

import os
import re

import httpx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_exec_summary(assessment_text: str) -> str:
    """Return the first paragraph (executive summary) of the assessment."""
    if not assessment_text:
        return "New LiquidLab report available."
    paragraphs = re.split(r"\n{2,}", assessment_text.strip())
    first = paragraphs[0].strip() if paragraphs else assessment_text.strip()
    # Truncate to reasonable notification length
    if len(first) > 300:
        first = first[:297] + "..."
    return first


def _count_severities(assessment_text: str) -> tuple[int, int]:
    """Rough count of Critical and Warning items in the priority actions section."""
    critical = len(re.findall(r"\bCritical\b", assessment_text, re.IGNORECASE))
    warning  = len(re.findall(r"\bWarning\b",  assessment_text, re.IGNORECASE))
    return critical, warning


def _ntfy_priority(critical: int, warning: int, overall_risk: str | None) -> str:
    if critical > 0 or overall_risk in ("high",):
        return "urgent"
    if warning > 0 or overall_risk in ("medium",):
        return "high"
    return "default"


def _ntfy_tags(critical: int, warning: int) -> str:
    if critical > 0:
        return "rotating_light,shield"
    if warning > 0:
        return "warning,shield"
    return "white_check_mark,shield"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def notify_report_complete(report: dict) -> None:
    """POST a summary notification to ntfy after a report run completes.

    Silently swallows errors so a notification failure never breaks the run.
    """
    ntfy_url   = os.environ.get("NTFY_URL",     "http://192.168.1.26:8080")
    ntfy_topic = os.environ.get("NTFY_TOPIC",   "LiquidLab")
    enabled    = os.environ.get("NTFY_ENABLED", "true").lower()

    if enabled not in ("true", "1", "yes"):
        return

    assessment_text = report.get("assessment_text", "")
    overall_risk    = (report.get("risk_summary") or {}).get("overall_risk")

    exec_summary = _extract_exec_summary(assessment_text)
    critical, warning = _count_severities(assessment_text)

    suffix = ""
    if critical or warning:
        suffix = f"\n{critical} critical · {warning} warnings"

    message  = exec_summary + suffix
    priority = _ntfy_priority(critical, warning, overall_risk)
    tags     = _ntfy_tags(critical, warning)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{ntfy_url.rstrip('/')}/{ntfy_topic}",
                content=message.encode(),
                headers={
                    "Title":    "LiquidLab Report",
                    "Priority": priority,
                    "Tags":     tags,
                    "X-Report-Id": report.get("id", ""),
                },
            )
    except Exception as exc:
        print(f"[notifier] ntfy POST failed: {exc}")
