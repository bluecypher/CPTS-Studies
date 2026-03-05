from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from packages.core.models import NormalizedEvent, S1Alert, UDMEvent


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def normalize_event(payload: dict[str, Any], source: str) -> NormalizedEvent:
    if source == "chronicle_udm":
        udm = UDMEvent.model_validate(payload)
        metadata = udm.metadata
        principal = udm.principal
        target = udm.target
        network = udm.network

        return NormalizedEvent(
            event_id=str(metadata.get("id", "unknown")),
            source_type=source,
            timestamp=_parse_timestamp(metadata.get("event_timestamp")),
            hostname=str(principal.get("hostname") or target.get("hostname") or "unknown"),
            user=str(principal.get("user", {}).get("userid") or principal.get("user") or "unknown"),
            process_name=str(target.get("process", {}).get("file", {}).get("full_path") or "unknown"),
            process_command_line=str(target.get("process", {}).get("command_line") or ""),
            parent_process_name=str(target.get("process", {}).get("parent_process", {}).get("file", {}).get("full_path") or "unknown"),
            event_type=str(metadata.get("event_type", "unknown")),
            outcome=str(udm.security_result.get("action", "unknown")),
            src_ip=network.get("src_ip"),
            dest_ip=network.get("dest_ip"),
            dest_domain=network.get("dns", {}).get("questions", [{}])[0].get("name") if isinstance(network.get("dns"), dict) else None,
            url=network.get("http", {}).get("url") if isinstance(network.get("http"), dict) else None,
            raw=payload,
        )

    if source == "sentinelone_alert":
        s1 = S1Alert.model_validate(payload)
        threat_info = s1.threatInfo
        network = s1.network
        return NormalizedEvent(
            event_id=s1.id or "unknown",
            source_type=source,
            timestamp=_parse_timestamp(s1.createdAt),
            hostname=str(s1.agent.get("computerName", "unknown")),
            user=str(s1.user or s1.agent.get("lastLoggedInUserName") or "unknown"),
            process_name=str(threat_info.get("processName") or "unknown"),
            process_command_line=str(threat_info.get("processCmd") or ""),
            parent_process_name=str(threat_info.get("parentProcessName") or "unknown"),
            event_type=str(threat_info.get("classification") or "alert"),
            outcome=str(threat_info.get("mitigationStatus") or "unknown"),
            src_ip=network.get("sourceIp"),
            dest_ip=network.get("destinationIp"),
            dest_domain=network.get("destinationDomain"),
            url=network.get("url"),
            raw=payload,
        )

    raise ValueError(f"Unsupported source: {source}")
