from fastapi.testclient import TestClient

from nixfence.api import app

client = TestClient(app)


def test_about_is_explicit_demo():
    data = client.get("/api/v1/about").json()
    assert data["brand"] == "Byte2craft"
    assert data["remote_execution"] is False
    assert data["auth_enabled"] is False


def test_hosts_are_synthetic():
    data = client.get("/api/v1/hosts").json()
    assert data["demo"] is True
    assert data["total"] >= 1


def test_analyzer_endpoint():
    response = client.post("/api/v1/policies/analyze", json={"name": "demo", "rules": []})
    assert response.status_code == 200
    assert response.json()["analysis_only"] is True


def test_malformed_policy_rejected():
    response = client.post("/api/v1/policies/analyze", json={"name": "demo", "rules": [], "arbitrary": "danger"})
    assert response.status_code == 422


def test_no_commercial_feature_endpoint_in_community():
    response = client.get("/api/v1/enterprise/capabilities")
    assert response.status_code == 404


def test_demo_ui_excludes_commercial_upsell():
    response = client.get("/")
    assert response.status_code == 200
    assert "BYTE2CRAFT PRO" not in response.text
    assert 'id="panel-enterprise"' not in response.text
    assert "BY BYTE2CRAFT" in response.text
