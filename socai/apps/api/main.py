from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from packages.agents.triage_ai import analyze_with_llm
from packages.core.normalize import normalize_event
from packages.detection.engine import DetectionEngine
from packages.detection.rules.default_rules import load_default_rules

app = FastAPI(title="socai backend", version="0.2.0")
engine = DetectionEngine(load_default_rules())


class EventRequest(BaseModel):
    source: str = Field(..., examples=["chronicle_udm", "sentinelone_alert"])
    payload: dict[str, Any]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ingest/logs")
def ingest_logs(data: EventRequest) -> dict[str, Any]:
    try:
        event = normalize_event(data.payload, data.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    detections = engine.run(event)
    return {
        "normalized_event": event.model_dump(mode="json"),
        "detections": [d.model_dump(mode="json") for d in detections],
    }


@app.post("/analyze/alert")
async def analyze_alert(data: EventRequest) -> dict[str, Any]:
    try:
        event = normalize_event(data.payload, data.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    detections = engine.run(event)
    triage = await analyze_with_llm(event, detections)

    return {
        "normalized_event": event.model_dump(mode="json"),
        "detections": [d.model_dump(mode="json") for d in detections],
        "triage": triage.model_dump(mode="json"),
    }
