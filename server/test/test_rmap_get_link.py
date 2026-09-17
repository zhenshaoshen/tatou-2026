"""Tests for POST /api/rmap-get-link (RMAP handshake, step 2).

Only the failure paths are covered here: a successful handshake has to create
a watermarked file *and* insert a database row, which requires a running
MariaDB - that end-to-end check is done in the docker-compose environment.
"""
import os

from rmap import RMAPClient

import server


def _http():
    return server.app.test_client()


def _rmap_client():
    return RMAPClient(
        identity="Group_01",
        client_private_key_path=os.environ["TEST_RMAP_CLIENT_PRIV_PATH"],
        server_public_key_path=os.environ["RMAP_SERVER_PUB_PATH"],
    )


def test_missing_payload_is_rejected():
    assert _http().post("/api/rmap-get-link", json={}).status_code == 400


def test_non_json_body_is_rejected():
    r = _http().post("/api/rmap-get-link", data="not json", content_type="text/plain")
    assert r.status_code == 400


def test_malformed_payload_is_rejected():
    r = _http().post("/api/rmap-get-link", json={"payload": "not-valid-base64!!"})
    assert r.status_code == 400


def test_message_2_without_a_matching_session_is_rejected():
    """A stale msg2 must map to 400, never to a 500.

    A second handshake for the same identity overwrites the server-side
    nonceServer (one pending session per identity), so the first handshake's
    msg2 no longer matches. This documents that known limitation as a
    well-behaved error rather than a crash.
    """
    first = _rmap_client()
    resp1 = _http().post("/api/rmap-initiate", json=first.build_msg1()).get_json()
    first.process_resp1(resp1)

    second = _rmap_client()
    resp1b = _http().post("/api/rmap-initiate", json=second.build_msg1()).get_json()
    second.process_resp1(resp1b)

    stale_msg2 = first.build_msg2()
    r = _http().post("/api/rmap-get-link", json=stale_msg2)
    assert r.status_code == 400


def test_errors_do_not_reveal_internals():
    """Every client-side failure looks the same: no oracle, no stack details."""
    r_missing = _http().post("/api/rmap-get-link", json={})
    r_malformed = _http().post("/api/rmap-get-link", json={"payload": "not-valid-base64!!"})
    assert r_missing.get_json() == r_malformed.get_json() == {"error": "invalid request"}
