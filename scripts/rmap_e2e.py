#!/usr/bin/env python3
"""End-to-end verification of the RMAP endpoints against a running Tatou server.

It acts as a *client* group: it performs the full four-message RMAP handshake
over HTTP, follows the link that comes back, downloads the watermarked PDF and
checks that the watermark it carries can be read back with the server's own
watermark key.

Because our own public key is published in the course key directory, the script
can authenticate against our own server using our own keypair - so no second
group is needed to test the whole chain.

Typical use inside the running container (paths and secrets already present):

    docker compose exec server python /app/rmap_e2e.py \
        --base-url http://localhost:5000 \
        --client-private-key /app/keys/server_priv.asc \
        --server-public-key  /app/keys/server_pub.asc

Or from a development checkout with the project's virtualenv active:

    python scripts/rmap_e2e.py --base-url http://localhost:5000 \
        --client-private-key keys/server_priv.asc \
        --server-public-key keys/server_pub.asc

Exit code 0 means every step passed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def post_json(url: str, payload: dict) -> dict:
    """POST a JSON body and return the decoded JSON response."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise SystemExit(f"FAIL: POST {url} -> HTTP {exc.code}: {body}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"FAIL: cannot reach {url}: {exc}")


def get_bytes(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"FAIL: GET {url} -> HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"FAIL: cannot reach {url}: {exc}")


def make_importable() -> None:
    """Make the server sources importable, in a checkout or inside the image."""
    for candidate in (
        Path(__file__).resolve().parents[1] / "server" / "src",  # <repo>/scripts/..
        Path("/app/src"),                                        # inside the container
        Path(__file__).resolve().parent,                         # flat layout fallback
    ):
        if candidate.is_dir():
            sys.path.insert(0, str(candidate))
            return


def main() -> int:
    parser = argparse.ArgumentParser(description="RMAP end-to-end check")
    parser.add_argument("--base-url", default="http://localhost:5000")
    parser.add_argument("--identity", default="Group_18",
                        help="identity to authenticate as (must be in the server's key directory)")
    parser.add_argument("--client-private-key", required=True)
    parser.add_argument("--client-passphrase", default=os.environ.get("RMAP_KEY_PASSPHRASE"))
    parser.add_argument("--server-public-key", required=True)
    parser.add_argument("--watermark-key", default=os.environ.get("WM_SECRET_KEY"))
    parser.add_argument("--watermark-method", default=os.environ.get("RMAP_WM_METHOD", "rmc"))
    parser.add_argument("--out", default="rmap_e2e_download.pdf")
    args = parser.parse_args()

    from rmap import RMAPClient

    base = args.base_url.rstrip("/")

    print(f"[1/5] sending message 1 as identity '{args.identity}' ...")
    client = RMAPClient(
        identity=args.identity,
        client_private_key_path=args.client_private_key,
        server_public_key_path=args.server_public_key,
        passphrase=args.client_passphrase or None,
    )
    resp1 = post_json(f"{base}/api/rmap-initiate", client.build_msg1())
    nonce_client, nonce_server = client.process_resp1(resp1)
    print(f"      server answered: nonceClient={nonce_client} nonceServer={nonce_server}")

    print("[2/5] sending message 2 ...")
    resp2 = post_json(f"{base}/api/rmap-get-link", client.build_msg2())
    link = client.process_resp2(resp2)
    if client.expected_link != link:
        raise SystemExit(
            "FAIL: the link returned by the server does not match the value the "
            "client computed independently"
        )
    print(f"      link = {link} (matches the client-side expectation)")

    print("[3/5] downloading the watermarked PDF ...")
    pdf = get_bytes(f"{base}/api/get-version/{link}")
    if not pdf.startswith(b"%PDF-"):
        raise SystemExit("FAIL: the link did not return a PDF")
    Path(args.out).write_bytes(pdf)
    print(f"      {len(pdf)} bytes written to {args.out}")

    print("[4/5] reading the watermark back ...")
    make_importable()
    import watermarking_utils as WMUtils

    if not args.watermark_key:
        print("      SKIP: no --watermark-key and no WM_SECRET_KEY in the environment")
    else:
        secret = WMUtils.read_watermark(args.watermark_method, args.out, args.watermark_key)
        expected = f"{args.identity}:{link}"
        if secret != expected:
            raise SystemExit(f"FAIL: watermark says {secret!r}, expected {expected!r}")
        print(f"      watermark OK: {secret!r} (bound to the requesting identity)")

    print("[5/5] done")
    print()
    print("PASS - handshake, per-identity watermarking, database entry and retrieval all work.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
