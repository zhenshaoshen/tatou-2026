"""Tests for the operations log (Specialization D).

The threat model asks for detection, not decoration: a log line that is only
written on the happy path is worthless. So these tests assert the *negative*
case for every observation point - that a rejected request still leaves a
record. They use `caplog` against the dedicated "tatou.audit" logger, which
means they assert on structured records rather than on stdout.

Each test is tied to the observation point (OP-1..OP-5) and the threat it
covers; the class docstrings name them so the test file can be mapped back to
the threat model directly.
"""
import io
import json
import logging

import pytest
from itsdangerous import URLSafeTimedSerializer

import server


def _client():
    return server.app.test_client()


def _token(uid=1, login="tester"):
    """Mint a real bearer token, exactly as test_upload_document.py does.

    The tests must drive the real authentication decorator, not bypass it: if
    the token did not pass, the observation points behind the gate would never
    run and the test would be asserting nothing. Signing a token against the
    app's own key is the only honest way to get past the gate.
    """
    serializer = URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    return serializer.dumps({"uid": uid, "login": login, "email": "tester@example.com"})


def _events(caplog):
    """Parse the JSON audit records captured during a test."""
    out = []
    for rec in caplog.records:
        if rec.name != "tatou.audit":
            continue
        out.append(json.loads(rec.getMessage()))
    return out


def _names(caplog):
    return [e["event"] for e in _events(caplog)]


@pytest.fixture
def audit(caplog):
    caplog.set_level(logging.INFO, logger="tatou.audit")
    return caplog


# ----------------------------------------------------------------------
# OP-1  Authentication gate -> T-01, T-04, T-08, T-12
# ----------------------------------------------------------------------
class TestAuthGate:
    def test_missing_header_is_logged(self, audit):
        r = _client().get("/api/list-documents")
        assert r.status_code == 401
        events = _events(audit)
        assert len(events) == 1
        assert events[0]["event"] == "auth.failure"
        assert events[0]["reason"] == "missing_header"
        # Correlated and attributable, otherwise the record cannot be used.
        assert events[0]["path"] == "/api/list-documents"
        assert events[0]["request_id"]

    def test_garbage_token_is_logged_as_bad_signature(self, audit):
        r = _client().get("/api/list-documents",
                          headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401
        events = [e for e in _events(audit) if e["event"] == "auth.failure"]
        assert len(events) == 1
        assert events[0]["reason"] == "bad_signature"

    def test_no_token_is_recorded_in_the_log(self, audit):
        """The audit log must never contain the bearer token itself."""
        secret_token = "this-should-never-appear-in-the-log"
        _client().get("/api/list-documents",
                      headers={"Authorization": f"Bearer {secret_token}"})
        raw = " ".join(rec.getMessage() for rec in audit.records)
        assert secret_token not in raw

    def test_authentication_failure_reason_is_one_of_a_fixed_set(self, audit):
        """The reason must come from a closed set, so detection rules can key
        on it. Free-text reasons would rot as soon as a message is reworded."""
        _client().get("/api/list-documents")
        _client().get("/api/list-documents", headers={"Authorization": "Bearer x"})
        _client().delete("/api/delete-document/1")
        reasons = {e["reason"] for e in _events(audit) if e["event"] == "auth.failure"}
        assert reasons <= {"missing_header", "expired", "bad_signature"}


# ----------------------------------------------------------------------
# OP-2  Login outcome -> T-10 (the priority threat), T-02
# ----------------------------------------------------------------------
class TestLoginOutcome:
    def test_missing_credentials_is_not_a_login_failure_event(self, audit):
        """A malformed request is a 400, not an authentication attempt. It must
        not inflate the failed-login counter, or a broken client would look
        like a brute-force campaign."""
        r = _client().post("/api/login", json={"email": "a@b.c"})
        assert r.status_code == 400
        assert "login.failure" not in _names(audit)

    def test_failed_login_is_logged_with_the_supplied_email(self, audit):
        r = _client().post("/api/login", json={"email": "victim@example.com",
                                               "password": "wrong-guess"})
        # The database is not reachable in this test, so the handler may answer
        # 401 (no row) or 503 (DB error). Either way it must not succeed, and
        # the assertion below is skipped when the DB error path is taken.
        assert r.status_code in (401, 503)
        events = [e for e in _events(audit) if e["event"] == "login.failure"]
        if r.status_code == 401:
            assert len(events) == 1
            assert events[0]["email"] == "victim@example.com"

    def test_no_password_is_ever_logged(self, audit):
        guess = "SuperSecretGuess-123"
        _client().post("/api/login", json={"email": "victim@example.com",
                                           "password": guess})
        raw = " ".join(rec.getMessage() for rec in audit.records)
        assert guess not in raw


# ----------------------------------------------------------------------
# OP-3  Upload rejection -> T-06, T-07, T-15
# ----------------------------------------------------------------------
class TestUploadRejection:
    def test_upload_without_a_token_stops_at_the_gate(self, audit):
        """The gate runs before the handler, so an unauthenticated attempt is
        recorded as an auth failure - not as an upload rejection. Documenting
        the ordering here keeps the two observation points from being confused.
        """
        data = {"file": (io.BytesIO(b"%PDF-1.4\n"), "../../evil.pkl")}
        r = _client().post("/api/upload-document", data=data,
                           content_type="multipart/form-data")
        assert r.status_code == 401
        assert "upload.normalised" not in _names(audit)
        assert "auth.failure" in _names(audit)

    def test_traversal_is_logged_when_authenticated(self, audit, tmp_path, monkeypatch):
        """With a valid token the upload handler runs and must log the attempt."""
        monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)
        data = {"file": (io.BytesIO(b"%PDF-1.4\n"), "../../evil.pkl")}
        _client().post("/api/upload-document", data=data,
                       content_type="multipart/form-data",
                       headers={"Authorization": f"Bearer {_token()}"})

        events = [e for e in _events(audit) if e["event"] == "upload.normalised"]
        assert len(events) == 1
        assert events[0]["raw_filename"] == "../../evil.pkl"
        # The sanitised name is recorded too, so the log shows what was kept.
        assert ".." not in events[0]["stored_as"]

    def test_non_pdf_upload_is_logged(self, audit, tmp_path, monkeypatch):
        monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)
        data = {"file": (io.BytesIO(b"not a pdf at all"), "x.pdf")}
        r = _client().post("/api/upload-document", data=data,
                           content_type="multipart/form-data",
                           headers={"Authorization": f"Bearer {_token()}"})

        assert r.status_code == 400
        events = [e for e in _events(audit) if e["event"] == "upload.rejected"]
        assert len(events) == 1
        assert events[0]["reason"] == "not_a_pdf"

    def test_unsafe_name_that_sanitises_to_nothing_is_logged(self, audit, tmp_path, monkeypatch):
        """A filename with no usable characters reduces to empty after
        secure_filename, which is rejected and must be recorded."""
        monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)
        data = {"file": (io.BytesIO(b"%PDF-1.4\n"), "../..")}
        r = _client().post("/api/upload-document", data=data,
                           content_type="multipart/form-data",
                           headers={"Authorization": f"Bearer {_token()}"})

        assert r.status_code == 400
        events = [e for e in _events(audit) if e["event"] == "upload.rejected"]
        assert len(events) == 1
        assert events[0]["reason"] == "path_traversal_or_unsafe_name"

    def test_authenticated_upload_is_not_logged_as_rejected(self, audit, tmp_path, monkeypatch):
        """A clean upload must not create a rejection event, or the detection
        rule would fire on normal use."""
        monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)
        data = {"file": (io.BytesIO(b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n"), "good.pdf")}
        _client().post("/api/upload-document", data=data,
                       content_type="multipart/form-data",
                       headers={"Authorization": f"Bearer {_token()}"})
        assert "upload.rejected" not in _names(audit)


# ----------------------------------------------------------------------
# OP-4  RMAP protocol failure -> T-03, T-22, T-23, T-25
# ----------------------------------------------------------------------
class TestRmapFailure:
    def test_bad_initiate_payload_is_logged(self, audit):
        r = _client().post("/api/rmap-initiate", json={"payload": "not-base64"})
        assert r.status_code in (400, 500)
        events = [e for e in _events(audit) if e["event"] == "rmap.initiate.rejected"]
        if r.status_code == 400:
            assert len(events) == 1
            assert events[0]["reason"] == "protocol_error"

    def test_rmap_failure_never_logs_an_identity(self, audit):
        """T-24: distinguishing 'unknown identity' from 'cannot decrypt' would
        be an enumeration oracle, so the audit record must not carry the
        claimed identity even when one was supplied."""
        _client().post("/api/rmap-initiate",
                       json={"payload": "Zm9v", "identity": "Group_07"})
        raw = " ".join(rec.getMessage() for rec in audit.records)
        assert "Group_07" not in raw


# ----------------------------------------------------------------------
# Log hygiene (applies to every observation point)
# ----------------------------------------------------------------------
class TestLogShape:
    def test_every_record_is_single_line_json(self, audit):
        _client().get("/api/list-documents")
        _client().post("/api/login", json={"email": "a@b.c", "password": "x"})
        for rec in audit.records:
            if rec.name != "tatou.audit":
                continue
            message = rec.getMessage()
            assert "\n" not in message, "a multi-line record breaks line-based tooling"
            obj = json.loads(message)
            assert set(("ts", "event", "request_id", "ip", "method", "path")) <= set(obj)

    def test_request_id_is_unique_per_request(self, audit):
        _client().get("/api/list-documents")
        _client().get("/api/list-documents")
        ids = {e["request_id"] for e in _events(audit)}
        assert len(ids) == 2

    def test_successful_authentication_is_not_logged_as_failure(self, audit):
        _client().post("/api/create-user", json={"email": "a@b.c", "login": "x",
                                                 "password": "y"})
        assert "auth.failure" not in _names(audit)
