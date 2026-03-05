from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from packages.core.models import DetectionResult, NormalizedEvent
from packages.enrichers.mitre import enrich_with_mitre


class Rule(ABC):
    id: str
    name: str
    severity: str
    tags: list[str]

    @abstractmethod
    def match(self, event: NormalizedEvent) -> bool:
        raise NotImplementedError

    def enrich(self, event: NormalizedEvent) -> str:
        return f"Rule {self.id} matched event {event.event_id}."

    def to_detection(self, event: NormalizedEvent) -> DetectionResult:
        tactics, techniques = enrich_with_mitre(self.id, self.tags)
        severity_score = {"low": 25, "medium": 50, "high": 75, "critical": 95}
        return DetectionResult(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            score=severity_score.get(self.severity, 50),
            reasoning=self.enrich(event),
            tags=self.tags,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
        )


class DetectionEngine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def run(self, event: NormalizedEvent) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        for rule in self.rules:
            if rule.match(event):
                detections.append(rule.to_detection(event))
        return detections
