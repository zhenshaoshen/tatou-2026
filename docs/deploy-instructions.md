# Tatou deployment & verification — Group 18

**Audience:** the teammate who can reach the VM.
**Goal:** get the hardened server (with the two RMAP endpoints) running on the VM,
and prove it actually works.

> Everything below assumes the repo is at `~/tatou-2026` on the VM. Adjust if yours differs.

---

## 0. What must be on the VM before starting

| Item | Where it goes | Notes |
|---|---|---|
| Our public key | `keys/server_pub.asc` | same file as `Group_18.asc` from the course key directory |
| Our private key | `keys/server_priv.asc` | passphrase-protected. **Send it over a private channel, never commit it.** |
| Other groups' public keys | `keys/clients/*.asc` | all files from the course key directory (`Group_01.asc` ... `Nicolas.asc`) |
| Our assigned confidential PDF | `confidential/Group_18.pdf` | the document RMAP hands out watermarked copies of. **Verify after copying:** `sha256sum` must be `3ecdcf8f80239e40317ad61b6ac5fa0eb2955720cae24106bcdce3f7fd8efa92` (73685 bytes) |
| Local secrets | `.env` | **never committed** (already in `.gitignore`) |

`keys/` and `confidential/` are git-ignored, so nothing sensitive gets pushed.
Directory layout expected by `docker-compose.yml`:

```
tatou-2026/
├── .env
├── docker-compose.yml
├── flag                      # flag 2 value (this file IS committed, by design)
├── keys/
│   ├── server_pub.asc
│   ├── server_priv.asc
│   └── clients/
│       ├── Group_01.asc
│       └── ...
└── confidential/
    └── Group_18.pdf
```

---

## 1. Get the code

```bash
cd ~/tatou-2026
git pull                       # or: git fetch <bundle> && git merge
git log --oneline -3           # should show the RMAP + watermark commits
```

---

## 2. Configure `.env`

```bash
cp sample.env .env      # only if it does not exist yet
nano .env
```

It must contain all of these:

```
MARIADB_ROOT_PASSWORD=<random 32+ chars>
MARIADB_USER=tatou
MARIADB_PASSWORD=<random 32+ chars>
FLAG_2=<flag 1 value from ILearn feedback>

SECRET_KEY=<random 64 chars>
WM_SECRET_KEY=<random 32+ chars>
RMAP_KEY_PASSPHRASE=<the passphrase of our private key>

RMAP_SOURCE_PDF=../confidential/Group_18.pdf
RMAP_WM_METHOD=rmc
```

Notes:
- `SECRET_KEY` and `WM_SECRET_KEY` must be at least 32 characters — **the server refuses to start otherwise** (that is deliberate).
- `RMAP_KEY_PASSPHRASE` must be the real passphrase; the server cannot decrypt RMAP messages without it.
- `MARIADB_*` are only read when the database volume is created the first time. If the volume already exists, changing them has no effect unless you wipe the volume (`docker compose down -v`, **destroys data**).

Also put the flag 2 value into the repo-root `flag` file and push it (that one is meant to be public).

---

## 3. Bring it up

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f server        # Ctrl+C to stop watching; the service keeps running
```

Expected in the logs: no traceback, and a line about client identities loaded.

---

## 4. Verification

### 4.1 Health

```bash
curl -s localhost:5000/healthz
# {"message":"The server is up and running.","db_connected":true}
```

### 4.2 Core API smoke test

```bash
curl -s localhost:5000/api/get-watermarking-methods
# must list both "toy-eof" and "rmc"

curl -s -X POST localhost:5000/api/create-user \
  -H 'Content-Type: application/json' \
  -d '{"login":"smoke","email":"smoke@example.com","password":"S3cret-passw0rd"}'

TOKEN=$(curl -s -X POST localhost:5000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke@example.com","password":"S3cret-passw0rd"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s localhost:5000/api/list-documents -H "Authorization: Bearer $TOKEN"
# {"documents":[]}
```

### 4.3 RMAP end-to-end (the important one)

Our own public key is in the key directory, so we can authenticate against our
own server using our own keypair — no second group needed.

```bash
docker compose cp scripts/rmap_e2e.py server:/app/rmap_e2e.py

docker compose exec server python /app/rmap_e2e.py \
  --base-url http://localhost:5000 \
  --identity Group_18 \
  --client-private-key /app/keys/server_priv.asc \
  --server-public-key  /app/keys/server_pub.asc
```

Expected last lines:

```
      watermark OK: 'Group_18:<32-hex link>' (bound to the requesting identity)
[5/5] done

PASS - handshake, per-identity watermarking, database entry and retrieval all work.
```

This single check proves: the handshake works, a per-identity watermarked copy
was created, a database row was written, and the link resolves to that copy.

### 4.4 Database check

```bash
docker compose exec db mariadb -utatou -p"$MARIADB_PASSWORD" tatou -e \
  "SELECT id, documentid, intended_for, method, link FROM Versions ORDER BY id DESC LIMIT 5;"
```

You should see one row per retrieval, with `intended_for = Group_18`, `method = rmc`
and a distinct `link` for every handshake.

### 4.5 Flags in place

```bash
docker compose exec server cat /app/flag        # must show flag 1, not the placeholder
cat flag                                        # flag 2 (committed on purpose)
```

---

## 5. Things to keep in mind

- **Keep the service running.** Phase I expects as little downtime as possible. `restart: unless-stopped` is already set, so containers come back after a reboot.
- **Do not add gunicorn workers.** The RMAP handshake keeps per-session state in memory, so a message 1 handled by one worker and message 2 by another would fail. The current CMD runs a single worker on purpose.
- **Do not expose the database or phpMyAdmin.** Ports 3306 and 8080 are currently published in `docker-compose.yml`; that is scheduled to be removed, but until then other groups can reach them.
- **Never commit** `keys/`, `confidential/` or `.env`. `git status` should stay clean after every command in this document.
- If a flag is ever compromised, tell the whole group immediately — it has to be regenerated and disclosed on the course forum.

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits immediately; log says `SECRET_KEY is missing...` | `.env` not loaded or value shorter than 32 chars |
| `RMAP_SERVER_PRIV_PATH does not point to an existing file` | `keys/server_priv.asc` missing, or the volume mount is wrong |
| `RMAP_CLIENTS_DIR does not point to an existing directory` | `keys/clients/` missing or empty |
| `RMAP_SOURCE_PDF does not point to an existing file` | `confidential/Group_18.pdf` missing |
| `RMAP_SOURCE_PDF is not a PDF (missing the %PDF- header)` | the wrong file was copied there — check `sha256sum confidential/Group_18.pdf` against the value below |
| `server configuration error` (HTTP 500) on `rmap-initiate` | wrong or missing `RMAP_KEY_PASSPHRASE` |
| `invalid request` (HTTP 400) on `rmap-initiate` | the caller is not in `keys/clients/`; check the file name matches the identity exactly (e.g. `Group_07.asc` -> identity `Group_07`) |
| `127.0.0.1:5000` refuses connections | `docker compose ps` — the server container is not running; check the logs |
| Warnings about `TripleDES`, `Camellia`, `imghdr`, `CFB` | harmless; they come from the `pgpy` dependency |
