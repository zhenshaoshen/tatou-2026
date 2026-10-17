"""Regression tests for malformed JSON shapes discovered by fuzzing."""

from itsdangerous import URLSafeTimedSerializer

import server


def _token(uid=1, login="fuzzer"):
    serializer = URLSafeTimedSerializer(
        server.app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    return serializer.dumps(
        {"uid": uid, "login": login, "email": "fuzzer@example.com"}
    )


def test_create_watermark_rejects_non_object_json():
    client = server.app.test_client()
    headers = {"Authorization": f"Bearer {_token()}"}

    malformed_shapes = [
        ["x"],
        "abc",
        123,
        True,
    ]

    for endpoint in ["/api/create-watermark/1", "/api/create-watermark"]:
        for payload in malformed_shapes:
            response = client.post(
                endpoint,
                headers=headers,
                json=payload,
            )
            assert response.status_code == 400, (
                f"Unexpected status for {endpoint}, payload={payload!r}"
            )
            assert response.is_json
