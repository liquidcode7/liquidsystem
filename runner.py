"""LiquidSystem runner — orchestrates a full pihole-audit analysis run.

All existing modules (traffic, bypass, recommender, device_identifier, assessment)
are called exactly as before. This module collects their output and serializes
everything to a JSON-compatible dict for storage and API delivery.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime
import os

import assessment
import bypass
import device_identifier
import recommender
import traffic
from client import PiholeClient


async def run_analysis() -> dict:
    """Run the full audit pipeline and return a JSON-serializable report dict.

    This is the async entry point called by the FastAPI app. It performs the
    same data collection as main.py but skips the interactive conversation and
    HTML rendering — those are replaced by the web frontend.

    The AI assessment (synchronous streaming) is run in a thread pool to avoid
    blocking the event loop during the 10–15 second Claude API call.
    """
    aliases_path = os.environ.get("PIHOLE_DEVICES_JSON", "devices.json")

    async with PiholeClient() as client:
        client_names = await client.get_client_names()
        traffic_data, bypass_data, rec_data, device_map = await asyncio.gather(
            traffic.fetch(client, client_names=client_names),
            bypass.fetch(client, client_names=client_names),
            recommender.fetch(client),
            device_identifier.identify_devices(
                client,
                client_names=client_names,
                aliases_path=aliases_path,
            ),
        )

    risk_summary = device_identifier.network_risk_summary(device_map)

    # Run the blocking synchronous streaming call in a thread so the event loop
    # stays free. Output streams to server stdout (shows up in uvicorn logs).
    assessment_text = await asyncio.to_thread(
        assessment.get_ai_assessment,
        traffic_data,
        bypass_data,
        rec_data,
        device_map=device_map,
    )

    now = datetime.datetime.now()
    report_id = now.strftime("%Y%m%d-%H%M%S")

    return {
        "id": report_id,
        "created_at": now.isoformat(),
        "traffic_data": dataclasses.asdict(traffic_data),
        "bypass_data": dataclasses.asdict(bypass_data),
        "rec_data": dataclasses.asdict(rec_data),
        "device_map": {ip: dataclasses.asdict(info) for ip, info in device_map.items()},
        "risk_summary": dataclasses.asdict(risk_summary),
        "client_names": client_names,
        "assessment_text": assessment_text,
    }
