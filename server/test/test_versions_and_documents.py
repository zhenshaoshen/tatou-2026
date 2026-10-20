"""Route coverage for the read paths that had no test at all.

The oral-exam gate is that *every* route is reached by at least one test. Four
route families were unreached before this file existed:

    GET /api/list-versions            and /api/list-versions/<id>
    GET /api/list-all-versions
    GET /api/get-document             and /api/get-document/<id>
    GET /api/get-version/<link>

A unit test cannot provide a MariaDB, and a test that tolerates "200 or 503"
proves nothing when it runs inside the compose stack where the database is up.
So the database-backed assertions run against a **deliberately dead** database
(``127.0.0.1:1``), which makes the outcome identical in both places:

* the three authenticated read routes reject an unauthenticated caller with 401
  **before** touching the database;
* a request without a document id is answered 400 **before** the database, so a
  malformed request is never reported as an outage;
* with a valid token and an id, each route reaches its handler and degrades to
  503 rather than 500 when the database cannot be reached - a 500 would leak a
  stack trace;
* ``/api/get-version/<link>`` is deliberately public (the link *is* the
  capability), so it must never answer 401.

The happy paths are covered end-to-end against the real database by
``rmap_e2e.py`` and ``test_ownership_integration.py``.
"""
import pytest
from itsdangerous import URLSafeTimedSerializer

import server


def _token(uid=1, login="tester"):
    serializer = URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    return serializer.dumps({"uid": uid, "login": login, "email": "tester@example.com"})


def _client():
    return server.app.test_client()


def _auth():
    return {"Authorization": f"Bearer {_token()}"}


@pytest.fixture
def dead_database(monkeypatch):
    """Point the app at a port nothing listens on, and drop the cached engine.

    ``get_engine()`` memoises into ``app.config["_ENGINE"]``, so changing the
    host alone would keep using the previous engine. Clearing it is what makes
    these tests independent of whether a real database happens to be running.
    """
    monkeypatch.setitem(server.app.config, "_ENGINE", None)
    monkeypatch.setitem(server.app.config, "DB_HOST", "127.0.0.1")
    monkeypatch.setitem(server.app.config, "DB_PORT", 1)
    monkeypatch.setitem(server.app.config, "DB_USER", "nobody")
    monkeypatch.setitem(server.app.config, "DB_PASSWORD", "nobody")
    yield
    # monkeypatch restores the config entries; the cached engine is rebuilt on
    # the next call, so nothing else has to be tidied up by hand.


# ---------------------------------------------------------------- list-versions

@pytest.mark.parametrize("path", ["/api/list-versions", "/api/list-versions/1"])
def test_list_versions_requires_authentication(path):
    r = _client().get(path)
    assert r.status_code == 401


def test_list_versions_without_an_id_is_rejected_before_the_database():
    """No id in the path, and none in ?id= / ?documentid=.

    The route answers 400, not 503 - and that order is worth asserting. A
    malformed request reported as a database outage would send whoever is on
    call chasing an outage that is not happening.
    """
    r = _client().get("/api/list-versions", headers=_auth())
    assert r.status_code == 400
    assert "id" in r.get_json()["error"].lower()


def test_list_versions_with_an_id_reaches_its_handler_and_reports_a_missing_database(dead_database):
    r = _client().get("/api/list-versions/1", headers=_auth())
    assert r.status_code == 503
    assert "error" in r.get_json()


def test_list_versions_accepts_the_query_parameter_form(dead_database):
    """The route supports ?id= as well as the path parameter; both reach it."""
    r = _client().get("/api/list-versions?id=1", headers=_auth())
    assert r.status_code == 503


# ----------------------------------------------------------- list-all-versions

def test_list_all_versions_requires_authentication():
    r = _client().get("/api/list-all-versions")
    assert r.status_code == 401


def test_list_all_versions_reaches_its_handler_and_reports_a_missing_database(dead_database):
    r = _client().get("/api/list-all-versions", headers=_auth())
    assert r.status_code == 503
    assert "error" in r.get_json()


# ---------------------------------------------------------------- get-document

@pytest.mark.parametrize("path", ["/api/get-document", "/api/get-document/1"])
def test_get_document_requires_authentication(path):
    r = _client().get(path)
    assert r.status_code == 401


def test_get_document_without_an_id_is_rejected_before_the_database():
    """Same ordering as list-versions: 400 for a malformed request, not 503."""
    r = _client().get("/api/get-document", headers=_auth())
    assert r.status_code == 400
    assert "id" in r.get_json()["error"].lower()


def test_get_document_with_an_id_reaches_its_handler_and_reports_a_missing_database(dead_database):
    r = _client().get("/api/get-document/1", headers=_auth())
    assert r.status_code == 503
    assert "error" in r.get_json()


# ------------------------------------------------------------ get-version/<link>

def test_get_version_link_is_public_and_degrades_to_503(dead_database):
    """No token: the link is the capability.

    A 401 here would be a behaviour change - the RMAP flow hands out links that
    the recipient fetches without an account. A 500 would leak internals.
    """
    r = _client().get("/api/get-version/" + "a" * 32)
    assert r.status_code == 503
    assert "error" in r.get_json()


def test_get_version_does_not_accept_an_empty_link():
    r = _client().get("/api/get-version/")
    assert r.status_code == 404
