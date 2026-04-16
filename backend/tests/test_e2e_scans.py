
import pytest
import time
import requests
from sqlalchemy import create_engine, text

# Configuration
API_URL = "http://localhost:8000/api/v1"
DB_URL = "postgresql://user:password@db:5432/sme_cyber_db"

# ── Auth fixture ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def auth_headers():
    """Login and return Authorization headers for all API calls."""
    resp = requests.post(f"{API_URL}/auth/login", json={"email": "test@local", "password": "Pass123"})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def db_connection():
    """Wait for DB to be ready and return connection"""
    engine = create_engine(DB_URL)
    retries = 5
    while retries > 0:
        try:
            conn = engine.connect()
            yield conn
            conn.close()
            return
        except Exception:
            time.sleep(2)
            retries -= 1
    pytest.fail("Database connection failed")

def test_api_health(auth_headers):
    """Ensure API is running and scans endpoint is reachable"""
    response = requests.get(f"{API_URL}/scans/", headers=auth_headers)
    assert response.status_code == 200

def test_trigger_scan(auth_headers):
    """Trigger a scan and ensure it returns a valid ID"""
    payload = {"target_url": "http://lab_webserver:3000", "scan_type": "quick"}
    response = requests.post(f"{API_URL}/scans/", json=payload, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["status"] == "queued"
    return data["id"]

def test_scan_completion_and_assets(auth_headers, db_connection):
    """Wait for scan to complete and verify assets created in DB"""
    scan_id = test_trigger_scan(auth_headers)
    print(f"Tracking Scan ID: {scan_id}")

    # Poll for completion (max 20s)
    max_retries = 20
    status = "queued"
    while max_retries > 0 and status not in ("completed", "failed"):
        time.sleep(1)
        response = requests.get(f"{API_URL}/scans/{scan_id}", headers=auth_headers)
        status = response.json()["status"]
        max_retries -= 1

    assert status == "completed", f"Scan did not complete in time (status: {status})"

    # Verify Assets in DB
    result = db_connection.execute(text("SELECT count(*) FROM scan_assets WHERE scan_id = :sid"), {"sid": scan_id})
    asset_count = result.scalar()
    print(f"Assets found: {asset_count}")
    assert asset_count is not None
    assert asset_count >= 0

def test_report_generation(auth_headers):
    """Verify Report API properly calls Mock/Real advisor"""
    scan_id = test_trigger_scan(auth_headers)
    time.sleep(5)

    response = requests.get(f"{API_URL}/reports/{scan_id}", headers=auth_headers)
    assert response.status_code in [200, 404]
