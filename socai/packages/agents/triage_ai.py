from __future__ import annotations

import os
from typing import Any

import httpx

from packages.core.models import DetectionResult, NormalizedEvent, TriageRecommendation


async def _openai_triage(event: NormalizedEvent, detections: list[DetectionResult]) -> TriageRecommendation:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        return _deterministic_triage(detections)

    prompt = {
        "event": event.model_dump(mode="json"),
        "detections": [d.model_dump(mode="json") for d in detections],
    }
    headers = {"Authorization": f"Bearer {api_key}"}
    payload: dict[str, Any] = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "messages": [
            {"role": "system", "content": "You are a SOC triage assistant."},
            {"role": "user", "content": str(prompt)},
        ],
        "temperature": 0,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return TriageRecommendation(
            actions=["Review AI summary", "Contain impacted host if needed"],
            priority="high" if any(d.severity in {"high", "critical"} for d in detections) else "medium",
            confidence=0.7,
            rationale=content[:500],
        )
    except Exception:
        return _deterministic_triage(detections)


def _deterministic_triage(detections: list[DetectionResult]) -> TriageRecommendation:
    if not detections:
        return TriageRecommendation(
            actions=["Close as informational", "Continue passive monitoring"],
            priority="low",
            confidence=0.95,
            rationale="No detection rule matched the normalized event.",
        )

    highest = max(detections, key=lambda d: d.score)
    priority = "high" if highest.severity in {"high", "critical"} else "medium"
    return TriageRecommendation(
        actions=[
            "Validate alert context and affected asset",
            "Isolate host if malicious behavior is confirmed",
            "Collect forensic artifacts for incident response",
        ],
        priority=priority,
        confidence=0.85,
        rationale=f"Top hit {highest.rule_id} ({highest.rule_name}) with score {highest.score}.",
    )


async def analyze_with_llm(
    event: NormalizedEvent, detections: list[DetectionResult]
) -> TriageRecommendation:
    enabled = os.getenv("ENABLE_LLM_TRIAGE", "false").lower() == "true"
    if not enabled:
        return _deterministic_triage(detections)
    return await _openai_triage(event, detections)
