from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ingest_logs_success() -> None:
    payload = {
        "source": "chronicle_udm",
        "payload": {
            "metadata": {"id": "evt-123", "event_type": "PROCESS_LAUNCH"},
            "target": {
                "process": {
                    "file": {"full_path": "powershell.exe"},
                    "command_line": "powershell -EncodedCommand AAA",
                }
            },
        },
    }
    response = client.post("/ingest/logs", json=payload)

    assert response.status_code == 200
    assert "normalized_event" in response.json()
    assert isinstance(response.json()["detections"], list)


def test_analyze_alert_success() -> None:
    payload = {
        "source": "sentinelone_alert",
        "payload": {
            "id": "s1-11",
            "threatInfo": {
                "processName": "cmd.exe",
                "processCmd": "procdump -ma lsass.exe",
            },
        },
    }
    response = client.post("/analyze/alert", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert "normalized_event" in body
    assert "detections" in body
    assert "triage" in body
