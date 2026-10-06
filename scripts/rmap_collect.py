"""Collect one RMAP-watermarked PDF per Tatou server and report which step fails.
Usage: python rmap_collect.py 02=10.100.10.54 04=10.100.10.55 ..."""
import json, os, sys, time, urllib.request, urllib.error
from pathlib import Path
from rmap import RMAPClient

IDENTITY = "Group_18"
PRIV = "/app/keys/server_priv.asc"
KEYS = "/app/keys/clients"
OUT = Path("/tmp/collected")
PW = os.environ.get("RMAP_KEY_PASSPHRASE") or None
OUT.mkdir(exist_ok=True)


def call(url, payload=None):
    if payload is None:
        req = urllib.request.Request(url)
    else:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


for arg in sys.argv[1:]:
    num, ip = arg.split("=")
    target = f"Group_{num}"
    base = f"http://{ip}:5000/api"
    step, note = "setup", ""
    try:
        c = RMAPClient(identity=IDENTITY, client_private_key_path=PRIV,
                       server_public_key_path=f"{KEYS}/{target}.asc", passphrase=PW)
        step = "rmap-initiate"
        c.process_resp1(json.loads(call(f"{base}/rmap-initiate", c.build_msg1())))
        step = "rmap-get-link"
        link = c.process_resp2(json.loads(call(f"{base}/rmap-get-link", c.build_msg2())))
        if link != c.expected_link:
            if link.endswith(c.expected_link):
                link, note = c.expected_link, " (server returned a prefixed link)"
            else:
                raise RuntimeError(f"unexpected link format, length {len(link)} instead of 32")
        step = "get-version"
        pdf = call(f"{base}/get-version/{link}")
        if not pdf.startswith(b"%PDF-"):
            raise RuntimeError("response is not a PDF")
        (OUT / f"{target}.pdf").write_bytes(pdf)
        print(f"{target}: OK {len(pdf)} bytes{note}")
    except urllib.error.HTTPError as e:
        print(f"{target}: FAIL at {step}: HTTP {e.code} {e.read()[:100]!r}")
    except Exception as e:
        print(f"{target}: FAIL at {step}: {type(e).__name__}: {str(e)[:90]}")
    time.sleep(1)
