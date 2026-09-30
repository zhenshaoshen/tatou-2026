import json
import os
import time
import urllib.error
import urllib.request
import uuid

import pytest

BASE_URL = "http://localhost:5000"
PASSWORD = "SAMMTest123"

# These tests drive the real HTTP API, so they need a running instance *and* its
# database. When nothing is listening they are skipped instead of failing -
# otherwise the whole suite goes red on any machine that has not started the
# stack (a developer's laptop, for instance). CI, where the stack is started on
# purpose, sets TATOU_REQUIRE_INTEGRATION=1 so a missing service is a hard
# failure rather than a silent skip.
pytestmark = pytest.mark.integration


def _service_is_up() -> bool:
    try:
        with urllib.request.urlopen(BASE_URL + "/healthz", timeout=3) as response:
            return response.status == 200
    except Exception:
        return False


if not _service_is_up() and os.environ.get("TATOU_REQUIRE_INTEGRATION") != "1":
    pytestmark = [
        pytest.mark.integration,
        pytest.mark.skip(reason=f"no Tatou instance reachable at {BASE_URL}"),
    ]


def _request(method, path, data=None, headers=None):
    body = None
    request_headers = headers or {}

    if data is not None:
        body = json.dumps(data).encode()
        request_headers = {
            **request_headers,
            "Content-Type": "application/json",
        }

    req = urllib.request.Request(
        BASE_URL + path,
        data=body,
        headers=request_headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def _create_user(label):
    unique = f"{label}_{time.time_ns()}"
    email = f"{unique}@example.com"

    status, body = _request(
        "POST",
        "/api/create-user",
        {
            "email": email,
            "login": unique,
            "password": PASSWORD,
        },
    )

    assert status == 201, body
    return email


def _login(email):
    status, body = _request(
        "POST",
        "/api/login",
        {
            "email": email,
            "password": PASSWORD,
        },
    )

    assert status == 200, body
    return body["token"]


def _upload_pdf(token):
    boundary = f"----TatouTest{uuid.uuid4().hex}"
    pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

    parts = [
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="name"\r\n\r\n'
        "SAMM Ownership Integration Test\r\n",

        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="ownership-test.pdf"\r\n'
        "Content-Type: application/pdf\r\n\r\n"
    ]

    body = "".join(parts).encode() + pdf + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        BASE_URL + "/api/upload-document",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def test_cross_user_document_ownership_is_enforced():
    """
    Security regression test for V-05/V-06.

    A document owned by User A must not be accessible by User B through
    create-watermark or read-watermark.
    """
    owner_email = _create_user("samm_owner")
    attacker_email = _create_user("samm_attacker")

    owner_token = _login(owner_email)
    attacker_token = _login(attacker_email)

    status, document = _upload_pdf(owner_token)

    assert status == 201, document
    document_id = document["id"]

    status, body = _request(
        "POST",
        f"/api/create-watermark/{document_id}",
        {
            "method": "obj-stream-secret",
            "intended_for": "SAMM-test",
            "secret": "test-secret",
            "key": "wrong-key",
        },
        headers={"Authorization": f"Bearer {attacker_token}"},
    )

    assert status == 404
    assert body == {"error": "document not found"}

    status, body = _request(
        "POST",
        f"/api/read-watermark/{document_id}",
        {
            "method": "obj-stream-secret",
            "key": "wrong-key",
        },
        headers={"Authorization": f"Bearer {attacker_token}"},
    )

    assert status == 404
    assert body == {"error": "document not found"}
