from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="socai backend", version="0.1.0")


class LogEntry(BaseModel):
    source: str = Field(..., min_length=1)
    level: Literal["debug", "info", "warning", "error", "critical"]
    message: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IngestLogsRequest(BaseModel):
    logs: list[LogEntry] = Field(..., min_length=1)


class AnalyzeAlertRequest(BaseModel):
    logs: list[LogEntry] = Field(..., min_length=1)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ingest/logs")
def ingest_logs(payload: IngestLogsRequest) -> dict[str, int]:
    return {"ingested": len(payload.logs)}


@app.post("/analyze/alert")
def analyze_alert(payload: AnalyzeAlertRequest) -> dict[str, str | int]:
    score = 0
    level_weights = {"debug": 0, "info": 0, "warning": 1, "error": 2, "critical": 3}
    keywords = {
        "failed": 1,
        "unauthorized": 2,
        "malware": 3,
        "ransomware": 4,
        "exfiltration": 4,
        "privilege escalation": 3,
    }

    for entry in payload.logs:
        message = entry.message.lower()
        score += level_weights[entry.level]
        for word, weight in keywords.items():
            if word in message:
                score += weight

    severity = "low"
    if score >= 8:
        severity = "high"
    elif score >= 4:
        severity = "medium"

    return {
        "severity": severity,
        "score": score,
        "log_count": len(payload.logs),
    }
