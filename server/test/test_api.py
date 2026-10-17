from server import app
import watermarking_utils as WMUtils


def test_healthz_route():
    resp = app.test_client().get("/healthz")
    assert resp.status_code == 200
    assert resp.is_json
    assert isinstance(resp.get_json().get("message"), str)


def test_create_user_rejects_missing_fields():
    resp = app.test_client().post("/api/create-user", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_login_rejects_missing_fields():
    resp = app.test_client().post("/api/login", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_get_watermarking_methods_matches_registry():
    resp = app.test_client().get("/api/get-watermarking-methods")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == len(WMUtils.METHODS)
    assert [item["name"] for item in body["methods"]] == list(WMUtils.METHODS)
    assert all(isinstance(item["description"], str) for item in body["methods"])
