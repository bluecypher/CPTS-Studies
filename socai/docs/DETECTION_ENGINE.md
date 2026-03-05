# SOC AI Detection Engine

## Normalization flow

`POST /ingest/logs` and `POST /analyze/alert` both accept:

```json
{
  "source": "chronicle_udm",
  "payload": { "...": "..." }
}
```

The API calls `normalize_event(payload, source)` and maps source-specific fields into `NormalizedEvent`.
Supported sources:

- `chronicle_udm`
- `sentinelone_alert`

Safe defaults are used when fields are missing (`unknown`, empty string, or `null` for optional network attrs).

## Rules engine design

Rules inherit from `Rule` in `packages/detection/engine.py` and implement:

- `match(event) -> bool`
- optional `enrich(event) -> str`

To add a new rule:

1. Create a class under `packages/detection/rules/`.
2. Set metadata: `id`, `name`, `severity`, `tags`.
3. Implement `match` using normalized fields.
4. Register it in `load_default_rules()`.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env
make run-api
```

## Example request payloads

### Chronicle UDM sample

```json
{
  "source": "chronicle_udm",
  "payload": {
    "metadata": {
      "id": "evt-001",
      "event_timestamp": "2025-01-01T00:00:00Z",
      "event_type": "PROCESS_LAUNCH"
    },
    "principal": {
      "hostname": "workstation-01",
      "user": { "userid": "analyst" }
    },
    "target": {
      "process": {
        "file": { "full_path": "powershell.exe" },
        "command_line": "powershell -EncodedCommand ...",
        "parent_process": { "file": { "full_path": "winword.exe" } }
      }
    },
    "network": {
      "dest_ip": "185.227.10.10"
    }
  }
}
```

### SentinelOne alert sample

```json
{
  "source": "sentinelone_alert",
  "payload": {
    "id": "s1-abc",
    "createdAt": "2025-01-01T00:00:00Z",
    "agent": {
      "computerName": "server-01",
      "lastLoggedInUserName": "admin"
    },
    "threatInfo": {
      "processName": "cmd.exe",
      "processCmd": "procdump -ma lsass.exe",
      "parentProcessName": "winword.exe",
      "classification": "Malware",
      "mitigationStatus": "Detected"
    },
    "network": {
      "destinationDomain": "c2.invalid"
    }
  }
}
```
