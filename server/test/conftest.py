"""Pytest configuration.

The application is fail-closed: it refuses to start without a strong
SECRET_KEY, without a usable RMAP key set, and without a watermark key.
Tests only need *some* valid material, so we generate throwaway keys here
before any test module imports the app.

Everything in this file runs at collection time, i.e. before
`from server import app` in the test modules - which is exactly why the
environment variables have to be set here and not in a fixture.
"""
import os
import tempfile
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-production-0123456789")
os.environ.setdefault("WM_SECRET_KEY", "test-only-watermark-key-not-for-production-012345")

# Throwaway key material for the whole test session.
_TMP_DIR = Path(tempfile.mkdtemp(prefix="tatou-test-keys-"))

from rmap.keygen import generate_keypair  # noqa: E402  (must run after env setup)

_server_key = generate_keypair("Test Server", "test-server@example.com")
# A legitimate client: its public key IS published in the clients directory.
_client_key = generate_keypair("Group_01", "group01@example.com")
# An identity the server must NOT recognise (public key deliberately not published).
_unknown_client_key = generate_keypair("Group_99", "group99@example.com")

(_TMP_DIR / "server_priv.asc").write_text(str(_server_key))
(_TMP_DIR / "server_pub.asc").write_text(str(_server_key.pubkey))
(_TMP_DIR / "clients").mkdir()
(_TMP_DIR / "clients" / "Group_01.asc").write_text(str(_client_key.pubkey))

# Client-side private keys, so tests can drive the handshake as a real client.
(_TMP_DIR / "client_priv.asc").write_text(str(_client_key))
(_TMP_DIR / "unknown_client_priv.asc").write_text(str(_unknown_client_key))

os.environ["RMAP_SERVER_PUB_PATH"] = str(_TMP_DIR / "server_pub.asc")
os.environ["RMAP_SERVER_PRIV_PATH"] = str(_TMP_DIR / "server_priv.asc")
os.environ["RMAP_CLIENTS_DIR"] = str(_TMP_DIR / "clients")
os.environ["TEST_RMAP_CLIENT_PRIV_PATH"] = str(_TMP_DIR / "client_priv.asc")
os.environ["TEST_RMAP_UNKNOWN_CLIENT_PRIV_PATH"] = str(_TMP_DIR / "unknown_client_priv.asc")

# A minimal but structurally valid PDF to stand in for the confidential source
# document that RMAP hands out watermarked copies of.
_source_pdf = _TMP_DIR / "source.pdf"
_source_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
os.environ["RMAP_SOURCE_PDF"] = str(_source_pdf)

# The generated test keys are not passphrase protected.
os.environ.pop("RMAP_KEY_PASSPHRASE", None)
