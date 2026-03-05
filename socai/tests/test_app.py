from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_health() -> None:
    response = client.get('/health')

    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


def test_ingest_logs() -> None:
    payload = {
        'logs': [
            {
                'source': 'auth-service',
                'level': 'warning',
                'message': 'failed login attempt',
                'timestamp': '2024-01-01T00:00:00Z',
            },
            {
                'source': 'endpoint-agent',
                'level': 'error',
                'message': 'possible malware detected',
                'timestamp': '2024-01-01T00:01:00Z',
            },
        ]
    }

    response = client.post('/ingest/logs', json=payload)

    assert response.status_code == 200
    assert response.json() == {'ingested': 2}


def test_analyze_alert() -> None:
    payload = {
        'logs': [
            {
                'source': 'auth-service',
                'level': 'critical',
                'message': 'unauthorized privilege escalation detected',
                'timestamp': '2024-01-01T00:02:00Z',
            }
        ]
    }

    response = client.post('/analyze/alert', json=payload)

    assert response.status_code == 200
    assert response.json()['severity'] == 'high'
    assert response.json()['log_count'] == 1
