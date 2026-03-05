from packages.core.normalize import normalize_event


def test_normalize_chronicle_udm() -> None:
    payload = {
        "metadata": {
            "id": "evt-1",
            "event_timestamp": "2025-01-01T00:00:00Z",
            "event_type": "PROCESS_LAUNCH",
        },
        "principal": {"hostname": "host1", "user": {"userid": "alice"}},
        "target": {
            "process": {
                "file": {"full_path": "powershell.exe"},
                "command_line": "powershell -EncodedCommand abc",
                "parent_process": {"file": {"full_path": "winword.exe"}},
            }
        },
        "network": {"dest_ip": "185.227.10.10"},
    }

    normalized = normalize_event(payload, "chronicle_udm")

    assert normalized.event_id == "evt-1"
    assert normalized.hostname == "host1"
    assert normalized.process_name == "powershell.exe"


def test_normalize_sentinelone_alert() -> None:
    payload = {
        "id": "s1-1",
        "createdAt": "2025-01-01T00:00:00Z",
        "agent": {"computerName": "endpoint-1", "lastLoggedInUserName": "bob"},
        "threatInfo": {
            "processName": "cmd.exe",
            "processCmd": "procdump -ma lsass.exe",
            "parentProcessName": "winword.exe",
            "classification": "malware",
            "mitigationStatus": "detected",
        },
        "network": {"destinationDomain": "c2.invalid"},
    }

    normalized = normalize_event(payload, "sentinelone_alert")

    assert normalized.event_id == "s1-1"
    assert normalized.user == "bob"
    assert normalized.dest_domain == "c2.invalid"
