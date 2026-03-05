from packages.core.models import NormalizedEvent
from packages.detection.engine import DetectionEngine
from packages.detection.rules.default_rules import load_default_rules


def test_engine_matches_multiple_rules() -> None:
    event = NormalizedEvent(
        source_type="chronicle_udm",
        process_name="powershell.exe",
        process_command_line="powershell -EncodedCommand aaa",
        parent_process_name="winword.exe",
        dest_domain="c2.invalid",
    )

    detections = DetectionEngine(load_default_rules()).run(event)
    hit_ids = {d.rule_id for d in detections}

    assert "R001" in hit_ids
    assert "R004" in hit_ids
    assert "R005" in hit_ids
