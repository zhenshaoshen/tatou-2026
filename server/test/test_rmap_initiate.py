"""Tests for POST /api/rmap-initiate (RMAP handshake, step 1).

These tests drive the endpoint with a real RMAPClient built from throwaway
keys generated in conftest.py, so they exercise the genuine cryptography
rather than a mock. No database is involved.
"""
import os

from rmap import RMAPClient

import server


def _http():
    return server.app.test_client()


def _rmap_client(identity="Group_01", priv_env="TEST_RMAP_CLIENT_PRIV_PATH"):
    """A client that talks to 'our' server using throwaway keys."""
    return RMAPClient(
        identity=identity,
        client_private_key_path=os.environ[priv_env],
        server_public_key_path=os.environ["RMAP_SERVER_PUB_PATH"],
    )


def test_missing_payload_is_rejected():
    r = _http().post("/api/rmap-initiate", json={})
    assert r.status_code == 400


def test_non_json_body_is_rejected():
    r = _http().post("/api/rmap-initiate", data="not json", content_type="text/plain")
    assert r.status_code == 400


def test_malformed_payload_is_rejected():
    r = _http().post("/api/rmap-initiate", json={"payload": "not-valid-base64!!"})
    assert r.status_code == 400


def test_unknown_identity_is_rejected():
    client = _rmap_client(identity="Group_99", priv_env="TEST_RMAP_UNKNOWN_CLIENT_PRIV_PATH")
    r = _http().post("/api/rmap-initiate", json=client.build_msg1())
    assert r.status_code == 400


def test_errors_do_not_reveal_whether_the_identity_is_known():
    """No oracle: an unknown identity and a malformed payload look identical."""
    unknown = _rmap_client(identity="Group_99", priv_env="TEST_RMAP_UNKNOWN_CLIENT_PRIV_PATH")
    r_unknown = _http().post("/api/rmap-initiate", json=unknown.build_msg1())
    r_malformed = _http().post("/api/rmap-initiate", json={"payload": "not-valid-base64!!"})
    assert r_unknown.status_code == r_malformed.status_code == 400
    assert r_unknown.get_json() == r_malformed.get_json()


def test_known_identity_gets_a_usable_response_1():
    client = _rmap_client()
    r = _http().post("/api/rmap-initiate", json=client.build_msg1())
    assert r.status_code == 200

    resp1 = r.get_json()
    assert isinstance(resp1, dict)
    assert "payload" in resp1

    # The client must be able to decrypt it and get both nonces back.
    nonce_client, nonce_server = client.process_resp1(resp1)
    assert isinstance(nonce_server, int)
    assert nonce_server > 0

    # And the server must have stored that nonceServer for this identity,
    # which is what makes the (yet to come) msg2 step meaningful.
    rmap_server = server.app.extensions["rmap"]
    assert rmap_server.identities["Group_01"].nonceServer == nonce_server
