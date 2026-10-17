"""Targeted authenticated fuzzing of Tatou's watermark API JSON boundary."""

import argparse
import json
import os
import sys
from pathlib import Path

os.environ.setdefault(
    "SECRET_KEY",
    "tatou-fuzzing-test-secret-key-0123456789abcdef",
)
os.environ.setdefault(
    "WM_SECRET_KEY",
    "tatou-fuzzing-test-watermark-key-0123456789abcdef",
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from itsdangerous import URLSafeTimedSerializer
import tempfile

from rmap.keygen import generate_keypair

_tmp_dir = Path(tempfile.mkdtemp(prefix="tatou-fuzz-keys-"))
_server_key = generate_keypair("Fuzz Server", "fuzz-server@example.com")

(_tmp_dir / "server_priv.asc").write_text(str(_server_key))
(_tmp_dir / "server_pub.asc").write_text(str(_server_key.pubkey))
(_tmp_dir / "clients").mkdir()

os.environ["RMAP_SERVER_PUB_PATH"] = str(_tmp_dir / "server_pub.asc")
os.environ["RMAP_SERVER_PRIV_PATH"] = str(_tmp_dir / "server_priv.asc")
os.environ["RMAP_CLIENTS_DIR"] = str(_tmp_dir / "clients")
os.environ.pop("RMAP_KEY_PASSPHRASE", None)
_source_pdf = _tmp_dir / "source.pdf"
_source_pdf.write_bytes(
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
)
os.environ["RMAP_SOURCE_PDF"] = str(_source_pdf)

import server


def token():
    serializer = URLSafeTimedSerializer(
        server.app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    return serializer.dumps(
        {"uid": 1, "login": "fuzzer", "email": "fuzzer@example.com"}
    )


CASES = {
    "empty_object": {},
    "empty_list": [],
    "nonempty_list": ["x"],
    "string": "abc",
    "integer": 123,
    "boolean": True,
    "null": None,
}


def run(output_path):
    client = server.app.test_client()
    headers = {"Authorization": f"Bearer {token()}"}
    results = []

    for name, payload in CASES.items():
        response = client.post(
            "/api/create-watermark/1",
            headers=headers,
            json=payload,
        )

        results.append(
            {
                "case": name,
                "status": response.status_code,
                "body": response.get_data(as_text=True)[:300],
            }
        )

        print(f"{name:15} -> HTTP {response.status_code}")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fuzz Tatou's watermark creation API JSON boundary."
    )
    parser.add_argument(
        "--output",
        default="server/fuzz/api_results_latest.json",
        help="Path for the generated JSON results.",
    )
    args = parser.parse_args()
    run(args.output)
