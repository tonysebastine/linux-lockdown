import os
from fastapi.testclient import TestClient

os.environ.setdefault("LOCKDOWN_USERNAME", "test-admin")
os.environ.setdefault("LOCKDOWN_PASSWORD", "test-password-for-tests-only")
from app import app

client = TestClient(app, auth=(os.environ["LOCKDOWN_USERNAME"], os.environ["LOCKDOWN_PASSWORD"]))


def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_requires_auth():
    response = client.get("/", auth=("wrong", "wrong"))
    assert response.status_code == 401


def test_dry_run_does_not_execute():
    response = client.post("/api/run", json={"mode": "dry-run", "scope": "all"})
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "dry-run"
    assert "no commands were executed" in data["message"].lower()


def test_execute_is_disabled():
    response = client.post("/api/run", json={"mode": "execute", "scope": "all"})
    assert response.status_code == 409
    assert "disabled" in response.json()["detail"].lower()


def test_invalid_mode_rejected():
    response = client.post("/api/run", json={"mode": "shell", "scope": "all"})
    assert response.status_code == 422



def test_audit_scope_is_passed_to_script():
    response = client.post("/api/run", json={"mode": "audit", "scope": "ssh"})
    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "ssh"
    assert "Scope: ssh" in data["report"]
    assert "Brute-force protection" in data["report"]
    assert "no packages installed" in data["report"].lower()


def test_audit_script_rejects_invalid_scope():
    import subprocess
    from pathlib import Path

    script = Path(__file__).resolve().parents[1] / "linux-lockdown-audit.sh"
    result = subprocess.run(
        ["bash", str(script), "not-a-scope"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert "Valid scopes" in result.stderr


def test_audit_script_firewall_scope_is_read_only():
    response = client.post("/api/run", json={"mode": "audit", "scope": "firewall"})
    assert response.status_code == 200
    report = response.json()["report"]
    assert "Scope: firewall" in report
    assert "Firewall status" in report
    assert "no packages installed" in report.lower()
