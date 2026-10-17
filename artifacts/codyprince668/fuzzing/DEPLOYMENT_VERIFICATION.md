# Deployment Verification — Specialization A: Fuzzing

Author: Yueming Zhong
Project: Tatou 2026, Group 18
Verification date: 2026-10-17
Environment: softsec-group-18.dsv.local.su.se

## Objective

Verify that the FZ-01 API input-validation fix is present in the
deployed Tatou server and that the application starts successfully.

## Deployment version

Git commit: 9649b16
Branch: main

The server repository was synchronized with origin/main.

The server Docker image was rebuilt and the server container
was recreated using:

    docker compose up -d --build --no-deps server

The database and persistent storage volumes were not intentionally
removed or recreated.

## Verification results

| Check | Result | Evidence |
| --- | --- | --- |
| Git version | PASS | main at commit 9649b16 |
| Docker image build | PASS | Server image built successfully |
| Server container startup | PASS | Server container started |
| Database health | PASS | MariaDB reported healthy |
| phpMyAdmin | PASS | Container running |
| Gunicorn startup | PASS | Listening on 0.0.0.0:5000 |
| HTTP smoke test | PASS | GET / returned HTTP 200 |
| FZ-01 code inspection | PASS | Input-type validation found in deployed container |
| Deployed authenticated API regression | NOT RUN | pytest unavailable in server image |

## FZ-01 fix observed in deployed container

File:

    /app/src/server.py

Relevant code:

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    elif not isinstance(payload, dict):
        return jsonify({"error": "JSON body must be an object"}), 400

The type check occurs before subsequent payload.get() calls.

This confirms that the rebuilt server container contains the
FZ-01 input-validation fix.

## HTTP smoke test

Command:

    curl -sS -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:5000/

Observed result:

    HTTP 200

## Regression-test limitation

The following command was attempted:

    docker compose exec server python -m pytest test/test_watermark_fuzz_regression.py -q

It returned:

    /usr/local/bin/python: No module named pytest

Therefore, the authenticated API regression test was not executed
inside the deployed container.

The regression tests and post-fix API fuzzing were previously run
in the local development environment. Those results are documented
separately in FINDINGS.md and api_results_after_fix.json.

## Conclusion

The updated server image was successfully built and started.
The application responded with HTTP 200, and inspection of the
running container confirmed the FZ-01 validation logic.

A live authenticated API regression test remains outstanding.
The deployment checks do not establish that every API behavior
has been tested in the deployed environment.
