"""Regression tests for /api/delete-document (V-02).

These tests deliberately do not require a database: the authentication and
routing checks all happen before any SQL is executed.
"""
import server


def _client():
    return server.app.test_client()


def test_delete_requires_authentication():
    r = _client().delete("/api/delete-document/1")
    assert r.status_code == 401


def test_delete_post_requires_authentication():
    r = _client().post("/api/delete-document", json={"id": 1})
    assert r.status_code == 401


def test_delete_injection_in_query_is_not_authenticated():
    # Even an injection attempt must be stopped by the auth layer first.
    r = _client().delete("/api/delete-document?id=1 OR 1=1")
    assert r.status_code == 401


def test_delete_non_numeric_path_is_not_routed():
    # The <int:...> converter means the request never reaches the handler.
    # It falls through to the GET-only catch-all route "/<path:filename>",
    # which answers 405 (or 404 if that catch-all is ever removed) - either
    # way the handler that builds the SQL query is never entered.
    r = _client().delete("/api/delete-document/1%20OR%201=1")
    assert r.status_code in (404, 405)
    assert r.status_code != 200
