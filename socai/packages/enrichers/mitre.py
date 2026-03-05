from __future__ import annotations

MITRE_BY_RULE: dict[str, tuple[list[str], list[str]]] = {
    "R001": (["TA0002"], ["T1059.001"]),
    "R002": (["TA0006"], ["T1003"]),
    "R003": (["TA0003", "TA0004"], ["T1136.001", "T1078"]),
    "R004": (["TA0011"], ["T1071"]),
    "R005": (["TA0001", "TA0002"], ["T1566", "T1059"]),
    "R006": (["TA0003"], ["T1505.003"]),
}

MITRE_BY_TAG: dict[str, tuple[list[str], list[str]]] = {
    "webshell": (["TA0003"], ["T1505.003"]),
    "credential_access": (["TA0006"], ["T1003"]),
    "command_and_control": (["TA0011"], ["T1071"]),
}


def enrich_with_mitre(rule_id: str, tags: list[str]) -> tuple[list[str], list[str]]:
    tactics: set[str] = set()
    techniques: set[str] = set()

    if rule_id in MITRE_BY_RULE:
        rule_tactics, rule_techniques = MITRE_BY_RULE[rule_id]
        tactics.update(rule_tactics)
        techniques.update(rule_techniques)

    for tag in tags:
        if tag in MITRE_BY_TAG:
            tag_tactics, tag_techniques = MITRE_BY_TAG[tag]
            tactics.update(tag_tactics)
            techniques.update(tag_techniques)

    return sorted(tactics), sorted(techniques)
