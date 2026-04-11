"""Renders the HTML report from collected audit data."""

from __future__ import annotations

import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from bypass import BypassData
from device_identifier import DeviceInfo, NetworkRiskSummary
from recommender import RecommenderData
from traffic import TrafficData

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
    client_names: dict[str, str] | None = None,
    output_path: Path | None = None,
    assessment_text: str | None = None,
    device_map: dict[str, DeviceInfo] | None = None,
    risk_summary: NetworkRiskSummary | None = None,
    chat_history: list[dict] | None = None,
) -> Path:
    """Render a self-contained HTML report and write it to disk.

    Returns the path to the written file.
    """
    if output_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = Path(f"pihole-audit-{ts}.html")

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    names = client_names or {}
    dmap = device_map or {}

    # Sort devices for the report: high risk first, then by IP
    sorted_devices = sorted(
        dmap.values(),
        key=lambda d: ({"high": 0, "medium": 1, "low": 2, "minimal": 3}.get(d.privacy_risk, 4), d.ip),
    )

    html = template.render(
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        traffic=traffic_data,
        bypass=bypass_data,
        rec=rec_data,
        client_names=names,
        bypass_doh=[f for f in bypass_data.findings if f.method == "doh_lookup"],
        bypass_ptr=[f for f in bypass_data.findings if f.method == "ptr_lookup"],
        bypass_low=[f for f in bypass_data.findings if f.method == "low_query_count"],
        assessment_text=assessment_text,
        device_map=dmap,
        sorted_devices=sorted_devices,
        risk_summary=risk_summary,
        chat_history=chat_history or [],
    )

    output_path.write_text(html, encoding="utf-8")
    return output_path
