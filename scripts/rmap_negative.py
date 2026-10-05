"""RMAP negative tests: unknown identity, wrong nonce, replay, interleaved handshakes."""
import json, os, sys, urllib.request, urllib.error
from rmap import RMAPClient

BASE = "http://localhost:5000/api"
PRIV, PUB = "/app/keys/server_priv.asc", "/app/keys/server_pub.asc"
PW = os.environ.get("RMAP_KEY_PASSPHRASE") or None
failed = 0

def post(path, payload):
    req = urllib.request.Request(f"{BASE}/{path}", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:120]

def mk(identity="Group_18"):
    return RMAPClient(identity=identity, client_private_key_path=PRIV,
                      server_public_key_path=PUB, passphrase=PW)

def initiate(c):
    code, r1 = post("rmap-initiate", c.build_msg1())
    assert code == 200, f"initiate failed: HTTP {code}"
    return c.process_resp1(r1)  # (nonce_client, nonce_server)

def check(name, ok, detail=""):
    global failed
    failed += 0 if ok else 1
    print(("PASS" if ok else "FAIL"), "-", name, detail)

# 1. Unknown identity must be rejected at message 1
code, _ = post("rmap-initiate", mk("Group_99").build_msg1())
check("unknown identity rejected at message 1", code == 400, f"(HTTP {code})")

# 2. Wrong nonceServer in message 2
c = mk(); _, ns = initiate(c)
hits = [k for k, v in vars(c).items() if v == ns]
if not hits:
    print("SKIP - wrong nonce: could not locate nonceServer inside the client object")
else:
    for k in hits:
        setattr(c, k, (ns + 1) % 2**64)
    code, _ = post("rmap-get-link", c.build_msg2())
    check("wrong nonceServer rejected", code == 400, f"(HTTP {code})")

# 3. Replay of the same message 2
c = mk(); initiate(c); m2 = c.build_msg2()
c1, _ = post("rmap-get-link", m2)
c2, _ = post("rmap-get-link", m2)
check("first message 2 accepted", c1 == 200, f"(HTTP {c1})")
check("replayed message 2 rejected", c2 == 400, f"(HTTP {c2})")

# 4. Same identity, handshakes interleaved: A1, B1, A2, B2.
# KNOWN LIMITATION of the RMAP library: one pending session per identity,
# so B1 supersedes A1 (anyone can send message 1 as any group).
a, b = mk(), mk(); initiate(a); initiate(b)
ca, _ = post("rmap-get-link", a.build_msg2())
cb, rb = post("rmap-get-link", b.build_msg2())
check("same-identity interleave: superseded rejected, latest succeeds (known limitation)",
      ca == 400 and cb == 200, f"(HTTP {ca}/{cb})")

# 5. Sequential handshakes for the same identity give distinct links
links = []
for _ in range(2):
    c = mk(); initiate(c)
    code, r = post("rmap-get-link", c.build_msg2())
    links.append(c.process_resp2(r) if code == 200 else None)
check("sequential handshakes give distinct links",
      None not in links and links[0] != links[1])

print("\nFAILED:", failed)
sys.exit(1 if failed else 0)
