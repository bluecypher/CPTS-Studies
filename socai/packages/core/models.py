from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    event_id: str = "unknown"
    source_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str = "unknown"
    user: str = "unknown"
    process_name: str = "unknown"
    process_command_line: str = ""
    parent_process_name: str = "unknown"
    event_type: str = "unknown"
    outcome: str = "unknown"
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_domain: str | None = None
    url: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class UDMEvent(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)
    principal: dict[str, Any] = Field(default_factory=dict)
    target: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    security_result: dict[str, Any] = Field(default_factory=dict)
    additional: dict[str, Any] = Field(default_factory=dict)


class S1Alert(BaseModel):
    id: str | None = None
    createdAt: str | None = None
    agent: dict[str, Any] = Field(default_factory=dict)
    threatInfo: dict[str, Any] = Field(default_factory=dict)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    network: dict[str, Any] = Field(default_factory=dict)
    user: str | None = None


class DetectionResult(BaseModel):
    rule_id: str
    rule_name: str
    severity: Literal["low", "medium", "high", "critical"]
    score: int = Field(ge=0, le=100)
    reasoning: str
    tags: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class TriageRecommendation(BaseModel):
    actions: list[str] = Field(default_factory=list)
    priority: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
