"""Regression tests for the document-upload hardening (V-07).

These run without a database: the file-name sanitisation and the PDF content
check both happen *before* anything touches the database.

Ownership enforcement on create-watermark / read-watermark (V-05, V-06) cannot
be covered here because it is expressed as a SQL predicate; it is verified
end-to-end in the docker-compose environment (see deploy-instructions-EN.md).
"""
import io
from pathlib import Path

import pytest
from itsdangerous import URLSafeTimedSerializer

import server

MINIMAL_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def _token(uid=1, login="tester"):
    serializer = URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    return serializer.dumps({"uid": uid, "login": login, "email": "tester@example.com"})


def _upload(filename, content, storage_dir):
    server.app.config["STORAGE_DIR"] = storage_dir
    client = server.app.test_client()
    return client.post(
        "/api/upload-document",
        headers={"Authorization": f"Bearer {_token()}"},
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )


def test_upload_requires_authentication():
    r = server.app.test_client().post(
        "/api/upload-document",
        data={"file": (io.BytesIO(MINIMAL_PDF), "a.pdf")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 401


def test_non_pdf_content_is_rejected(tmp_path):
    r = _upload("notes.txt", b"definitely not a pdf", tmp_path)
    assert r.status_code == 400
    assert "pdf" in r.get_json()["error"].lower()


def test_pdf_extension_alone_is_not_enough(tmp_path):
    """A .pdf name with the wrong content must still be rejected."""
    r = _upload("looks-like.pdf", b"<html>nope</html>", tmp_path)
    assert r.status_code == 400


def test_filename_traversal_cannot_escape_the_storage_root(tmp_path):
    """A "../../../tmp/..." filename must not write outside STORAGE_DIR.

    The database is unavailable in unit tests, so the request itself may end in
    503 - what matters is that nothing was written outside the storage root.
    """
    escape_target = Path("/tmp/pwned_by_traversal.pdf")
    escape_target.unlink(missing_ok=True)

    r = _upload("../../../../../../tmp/pwned_by_traversal.pdf", MINIMAL_PDF, tmp_path)
    assert r.status_code in (201, 503)

    assert not escape_target.exists(), "path traversal escaped the storage root"

    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written, "the upload did not land inside the storage root"
    storage_root = tmp_path.resolve()
    for path in written:
        assert storage_root in path.resolve().parents


def test_sanitised_filename_keeps_the_expected_extension(tmp_path):
    r = _upload("../../evil.pdf", MINIMAL_PDF, tmp_path)
    assert r.status_code in (201, 503)
    written = [p.name for p in tmp_path.rglob("*") if p.is_file()]
    assert written, "no file was stored"
    assert all(name.endswith("evil.pdf") for name in written)
    assert not any(".." in name for name in written)
