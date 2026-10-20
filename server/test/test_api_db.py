"""End-to-end coverage for the API routes, against a real database.

Two problems this module solves.

**The routes were dark.** ``test_api.py`` and friends assert 401 for the
authenticated routes, which is a good test - but a 401 is returned by the
decorator, so the route body never executes. Coverage showed exactly that:
``list-documents``, ``delete-document``, ``create-watermark`` and
``read-watermark`` were at 0 % even though each had a test that named the path.

**A unit test cannot provide a MariaDB.** So this module seeds a user, a document
(one real page, so the watermarking methods have something to draw on) and a
version, drives the routes through Flask's test client, and removes everything
afterwards. It skips itself when the database is unreachable, which is what
happens outside the compose network - the database port is deliberately not
published.

What it pins down beyond "returns 200":

* every read filters on the caller's identity, and another user's id gets the
  same answer as a nonexistent one - **no enumeration oracle**;
* a document whose stored path escapes the storage root is refused with 500, not
  served;
* a row that exists but whose file is gone answers **410**, which is a different
  thing from **404** and worth keeping different.
"""
import hashlib
import os
import uuid
from pathlib import Path

import pymupdf
import pytest
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text

import server
import watermarking_utils as WMUtils


def _engine():
    c = server.app.config
    url = (
        f"mysql+pymysql://{c['DB_USER']}:{c['DB_PASSWORD']}"
        f"@{c['DB_HOST']}:{c['DB_PORT']}/{c['DB_NAME']}?charset=utf8mb4"
    )
    return create_engine(url, pool_pre_ping=True, future=True)


def _database_is_reachable() -> bool:
    try:
        with _engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _database_is_reachable(),
    reason="no database on the compose network; unit runs skip this module",
)


def _token(uid, login):
    serializer = URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    return serializer.dumps({"uid": uid, "login": login, "email": f"{login}@example.com"})


def _auth(uid, login):
    return {"Authorization": f"Bearer {_token(uid, login)}"}


def _one_page_pdf() -> bytes:
    """A real single-page PDF, so the watermarking methods have a page to work on."""
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Group 18 - confidential")
    data = doc.tobytes()
    doc.close()
    return data


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    """Two users, one document, one version, one file on disk. All removed after."""
    monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)

    tag = uuid.uuid4().hex[:10]
    pdf_path = Path(tmp_path) / f"{tag}.pdf"
    pdf_bytes = _one_page_pdf()
    pdf_path.write_bytes(pdf_bytes)
    digest = hashlib.sha256(pdf_bytes).hexdigest()

    owner_login = f"owner_{tag}"
    other_login = f"other_{tag}"
    link = f"link{tag}"

    eng = _engine()
    with eng.begin() as conn:
        uid = conn.execute(
            text("INSERT INTO Users (email, hpassword, login) VALUES (:e, :h, :l)"),
            {"e": f"{owner_login}@example.com", "h": "x" * 20, "l": owner_login},
        ).lastrowid
        other_uid = conn.execute(
            text("INSERT INTO Users (email, hpassword, login) VALUES (:e, :h, :l)"),
            {"e": f"{other_login}@example.com", "h": "x" * 20, "l": other_login},
        ).lastrowid

        doc_id = conn.execute(
            text(
                "INSERT INTO Documents (name, path, ownerid, sha256, size) "
                "VALUES (:n, :p, :o, UNHEX(:s), :z)"
            ),
            {"n": f"{tag}.pdf", "p": str(pdf_path), "o": uid, "s": digest, "z": len(pdf_bytes)},
        ).lastrowid

        version_id = conn.execute(
            text(
                "INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path) "
                "VALUES (:d, :l, :f, :s, :m, :pos, :p)"
            ),
            {
                "d": doc_id,
                "l": link,
                "f": "recipient@example.com",
                "s": f"Group_01:{link}",
                "m": "rmc",
                "pos": "{}",
                "p": str(pdf_path),
            },
        ).lastrowid

    yield {
        "uid": uid,
        "other_uid": other_uid,
        "login": owner_login,
        "other_login": other_login,
        "doc_id": doc_id,
        "version_id": version_id,
        "link": link,
        "pdf_path": pdf_path,
    }

    with eng.begin() as conn:
        conn.execute(text("DELETE FROM Users WHERE id IN (:a, :b)"), {"a": uid, "b": other_uid})


# ---------------------------------------------------------------- list-documents

def test_list_documents_returns_the_seeded_document(seeded):
    r = server.app.test_client().get(
        "/api/list-documents", headers=_auth(seeded["uid"], seeded["login"])
    )
    assert r.status_code == 200
    assert seeded["doc_id"] in [d["id"] for d in r.get_json()["documents"]]


def test_list_documents_is_scoped_to_the_caller(seeded):
    r = server.app.test_client().get(
        "/api/list-documents", headers=_auth(seeded["other_uid"], seeded["other_login"])
    )
    assert r.status_code == 200
    assert r.get_json()["documents"] == []


# ---------------------------------------------------------------- list-versions

def test_list_versions_returns_the_seeded_version(seeded):
    r = server.app.test_client().get(
        f"/api/list-versions/{seeded['doc_id']}", headers=_auth(seeded["uid"], seeded["login"])
    )
    assert r.status_code == 200
    assert seeded["link"] in [v["link"] for v in r.get_json()["versions"]]


def test_list_versions_accepts_the_query_parameter_form(seeded):
    r = server.app.test_client().get(
        f"/api/list-versions?id={seeded['doc_id']}",
        headers=_auth(seeded["uid"], seeded["login"]),
    )
    assert r.status_code == 200
    assert seeded["link"] in [v["link"] for v in r.get_json()["versions"]]


def test_list_versions_does_not_reveal_another_users_versions(seeded):
    """The filter is on u.login AND d.id, so the caller cannot tell whether the
    document exists. An error here would be an existence oracle."""
    r = server.app.test_client().get(
        f"/api/list-versions/{seeded['doc_id']}",
        headers=_auth(seeded["other_uid"], seeded["other_login"]),
    )
    assert r.status_code == 200
    assert r.get_json()["versions"] == []


# ----------------------------------------------------------- list-all-versions

def test_list_all_versions_includes_the_seeded_version(seeded):
    r = server.app.test_client().get(
        "/api/list-all-versions", headers=_auth(seeded["uid"], seeded["login"])
    )
    assert r.status_code == 200
    assert seeded["link"] in [v["link"] for v in r.get_json()["versions"]]


def test_list_all_versions_is_scoped_to_the_caller(seeded):
    r = server.app.test_client().get(
        "/api/list-all-versions", headers=_auth(seeded["other_uid"], seeded["other_login"])
    )
    assert r.status_code == 200
    assert r.get_json()["versions"] == []


# ---------------------------------------------------------------- get-document

def test_get_document_serves_the_pdf(seeded):
    r = server.app.test_client().get(
        f"/api/get-document/{seeded['doc_id']}", headers=_auth(seeded["uid"], seeded["login"])
    )
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.data.startswith(b"%PDF")


def test_get_document_for_another_user_is_404_not_403(seeded):
    """404, deliberately: 403 would confirm the document id exists."""
    r = server.app.test_client().get(
        f"/api/get-document/{seeded['doc_id']}",
        headers=_auth(seeded["other_uid"], seeded["other_login"]),
    )
    assert r.status_code == 404


def test_get_document_reports_a_missing_file_on_disk(seeded):
    seeded["pdf_path"].unlink()
    r = server.app.test_client().get(
        f"/api/get-document/{seeded['doc_id']}", headers=_auth(seeded["uid"], seeded["login"])
    )
    assert r.status_code == 410


def test_get_document_refuses_a_path_outside_storage(seeded, tmp_path):
    """A row whose path escapes the storage root must not be served."""
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex[:8]}.pdf"
    outside.write_bytes(b"%PDF-1.4\n%%EOF\n")
    with _engine().begin() as conn:
        conn.execute(
            text("UPDATE Documents SET path = :p WHERE id = :i"),
            {"p": str(outside), "i": seeded["doc_id"]},
        )
    try:
        r = server.app.test_client().get(
            f"/api/get-document/{seeded['doc_id']}", headers=_auth(seeded["uid"], seeded["login"])
        )
        assert r.status_code == 500
        assert "path" in r.get_json()["error"].lower()
    finally:
        outside.unlink(missing_ok=True)


# ------------------------------------------------------------ get-version/<link>

def test_get_version_serves_the_copy_without_a_token(seeded):
    r = server.app.test_client().get(f"/api/get-version/{seeded['link']}")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.data.startswith(b"%PDF")


def test_get_version_unknown_link_is_404(seeded):
    r = server.app.test_client().get("/api/get-version/" + "0" * 32)
    assert r.status_code == 404


def test_get_version_reports_a_missing_file_on_disk(seeded):
    seeded["pdf_path"].unlink()
    r = server.app.test_client().get(f"/api/get-version/{seeded['link']}")
    assert r.status_code == 410


# ------------------------------------------------------------ create-watermark

def _create_payload(secret="recipient-secret", key="test-key", method="toy-eof"):
    return {
        "method": method,
        "intended_for": "recipient@example.com",
        "secret": secret,
        "key": key,
    }


def test_create_watermark_creates_a_version(seeded):
    client = server.app.test_client()
    auth = _auth(seeded["uid"], seeded["login"])

    r = client.post(f"/api/create-watermark/{seeded['doc_id']}", json=_create_payload(), headers=auth)
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["documentid"] == seeded["doc_id"]
    assert len(body["link"]) == 40          # sha1 of the filename
    assert body["intended_for"] == "recipient@example.com"

    # the row is really there, and it points at a new file on disk
    with _engine().connect() as conn:
        row = conn.execute(
            text("SELECT path FROM Versions WHERE link = :l"), {"l": body["link"]}
        ).first()
    assert row is not None
    assert Path(row.path).exists()

    # and it is retrievable through the public route, with no token
    got = client.get(f"/api/get-version/{body['link']}")
    assert got.status_code == 200
    assert got.data.startswith(b"%PDF")


def test_create_watermark_for_another_user_is_404(seeded):
    r = server.app.test_client().post(
        f"/api/create-watermark/{seeded['doc_id']}",
        json=_create_payload(),
        headers=_auth(seeded["other_uid"], seeded["other_login"]),
    )
    assert r.status_code == 404


def test_create_watermark_rejects_a_non_object_body(seeded):
    """The regression that fuzzing found (FZ-01): a list must be a 400, not a 500."""
    r = server.app.test_client().post(
        f"/api/create-watermark/{seeded['doc_id']}",
        json=["not", "an", "object"],
        headers=_auth(seeded["uid"], seeded["login"]),
    )
    assert r.status_code == 400


# ------------------------------------------------------------- read-watermark

def test_read_watermark_recovers_the_secret(seeded):
    """Watermark the document in place, then read it back through the route."""
    secret, key = "recipient-secret", "test-key"
    watermarked = WMUtils.apply_watermark(
        pdf=str(seeded["pdf_path"]), secret=secret, key=key, method="toy-eof", position=None
    )
    seeded["pdf_path"].write_bytes(watermarked)

    r = server.app.test_client().post(
        f"/api/read-watermark/{seeded['doc_id']}",
        json={"method": "toy-eof", "key": key},
        headers=_auth(seeded["uid"], seeded["login"]),
    )
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["secret"] == secret


def test_read_watermark_for_another_user_is_404(seeded):
    r = server.app.test_client().post(
        f"/api/read-watermark/{seeded['doc_id']}",
        json={"method": "toy-eof", "key": "test-key"},
        headers=_auth(seeded["other_uid"], seeded["other_login"]),
    )
    assert r.status_code == 404


# ----------------------------------------------------------- delete-document

def test_delete_document_removes_the_row(seeded):
    r = server.app.test_client().delete(
        f"/api/delete-document/{seeded['doc_id']}",
        headers=_auth(seeded["uid"], seeded["login"]),
    )
    assert r.status_code == 200
    assert r.get_json()["deleted"] is True

    with _engine().connect() as conn:
        still = conn.execute(
            text("SELECT id FROM Documents WHERE id = :i"), {"i": seeded["doc_id"]}
        ).first()
    assert still is None


def test_delete_document_for_another_user_is_404(seeded):
    r = server.app.test_client().delete(
        f"/api/delete-document/{seeded['doc_id']}",
        headers=_auth(seeded["other_uid"], seeded["other_login"]),
    )
    assert r.status_code == 404


# ------------------------------------------------------------------ RMAP e2e

def test_full_rmap_handshake_produces_a_retrievable_copy(tmp_path, monkeypatch):
    """The four-message handshake, end to end, through the HTTP shell.

    This is the one path the unit tests could not reach: ``_rmap_document_id``
    and ``_create_rmap_version`` only run when a handshake *succeeds*, and every
    existing RMAP test drives an error branch.

    ``RMAP_WM_METHOD`` is switched to ``toy-eof`` because the source PDF that
    conftest provides has no pages - the geometry and multi-channel methods need
    a page to draw on, and appending after ``%%EOF`` does not.
    """
    from rmap import RMAPClient

    monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)
    monkeypatch.setitem(server.app.config, "RMAP_WM_METHOD", "toy-eof")

    client = RMAPClient(
        identity="Group_01",
        client_private_key_path=os.environ["TEST_RMAP_CLIENT_PRIV_PATH"],
        server_public_key_path=os.environ["RMAP_SERVER_PUB_PATH"],
    )
    http = server.app.test_client()
    link = None

    try:
        r1 = http.post("/api/rmap-initiate", json=client.build_msg1())
        assert r1.status_code == 200, r1.get_json()
        client.process_resp1(r1.get_json())

        r2 = http.post("/api/rmap-get-link", json=client.build_msg2())
        assert r2.status_code == 200, r2.get_json()
        link = client.process_resp2(r2.get_json())
        assert link == client.expected_link

        # A link must not be handed out unless the copy exists and is recorded.
        copy = tmp_path / "rmap" / "Group_01" / f"{link}.pdf"
        assert copy.exists(), "the per-identity copy was not written"

        with _engine().connect() as conn:
            row = conn.execute(
                text("SELECT intended_for, secret, method FROM Versions WHERE link = :l"),
                {"l": link},
            ).first()
        assert row is not None
        assert row.intended_for == "Group_01"
        assert row.secret == f"Group_01:{link}"    # bound to this handshake
        assert row.method == "toy-eof"

        # and it is served through the public route, with no token
        got = http.get(f"/api/get-version/{link}")
        assert got.status_code == 200
        assert got.data.startswith(b"%PDF")
    finally:
        if link:
            with _engine().begin() as conn:
                conn.execute(text("DELETE FROM Versions WHERE link = :l"), {"l": link})


def test_rmap_get_link_rejects_a_replayed_message_2(tmp_path, monkeypatch):
    """Sessions are one-shot: the same message 2 twice must not yield two links."""
    from rmap import RMAPClient

    monkeypatch.setitem(server.app.config, "STORAGE_DIR", tmp_path)
    monkeypatch.setitem(server.app.config, "RMAP_WM_METHOD", "toy-eof")

    client = RMAPClient(
        identity="Group_01",
        client_private_key_path=os.environ["TEST_RMAP_CLIENT_PRIV_PATH"],
        server_public_key_path=os.environ["RMAP_SERVER_PUB_PATH"],
    )
    http = server.app.test_client()

    r1 = http.post("/api/rmap-initiate", json=client.build_msg1())
    assert r1.status_code == 200
    client.process_resp1(r1.get_json())
    msg2 = client.build_msg2()

    first = http.post("/api/rmap-get-link", json=msg2)
    assert first.status_code == 200, first.get_json()
    link = client.process_resp2(first.get_json())

    replay = http.post("/api/rmap-get-link", json=msg2)
    assert replay.status_code == 400, "a replayed message 2 must be refused, not answered"

    with _engine().begin() as conn:
        conn.execute(text("DELETE FROM Versions WHERE link = :l"), {"l": link})
