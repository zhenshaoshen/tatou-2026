# Specialization D — Threat Model

**Group 18 · Tatou (SOFTSEC VT 2026) · Phase II**

Scope: our deployment of Tatou on `softsec-group-18` (World 2 of the isolated
course network), the API it exposes on port 5000, its database, its key
material and its flags.

This document is the basis for Specialization D: everything the logging and
detection layer observes is derived from a threat listed here. It states the
assumptions we made, the ones we inherited from the deployment, and the ones we
deliberately did not cover. Per the specification, a threat model copied from a
template earns nothing — the value is in the reasoning below.

---

## 1. Method and assumptions

We used **STRIDE** per trust boundary, driven by the assets we actually hold and
by the 22 findings from our Phase I audit (`security-audit-group18.md`), rather
than by a generic checklist. We did not run a full formal data-flow diagram; we
walked the five flows below and asked STRIDE at each crossing.

| Assumption | Reasoning |
|---|---|
| The attacker is a **peer student group**, not a random internet host | The VM is only reachable from the isolated course network. Every attacker has: the public Tatou source, the API specification, an identical deployment to practise on, and our published RMAP public key. Treat them as a competent, motivated insider with the same code we have. |
| The attacker is **authenticated or can become so** | `/api/create-user` is public. Any attacker can register a valid account in one request. Therefore "authenticated" is not a real barrier and we do not rely on it in the threat ranking. |
| **No confidentiality of the network path** | RMAP messages travel encrypted (PGP) by design, but everything else is plain HTTP. Anyone on the segment can read and replay API traffic. |
| **Client software is not trusted** | Our HTML/JS is served from the same origin, but the attacker talks to the API directly with curl. We never assume the webapp mediates a request. |
| **Availability is a secondary goal** | The rules of Section 4.4 forbid denial of service. We still model it (it is a STRIDE category) but we do not spend detection budget on volumetric attacks, because the rules say they will not be used and a single VM cannot absorb them anyway. |

---

## 2. Assets

Ranked by what losing them costs us in this project.

| # | Asset | Where it lives | Why an attacker wants it |
|---|---|---|---|
| A1 | **Flag 1** | `/app/flag` in the `server` container | Direct project score. Readable by anything that achieves code execution inside the container. |
| A2 | **Flag 2** | `FLAG_2` env var, written into `/app/flag` at start-up by `entrypoint.sh` | Same value class as A1; reachable through env-var disclosure or code execution. |
| A3 | **Flag 3** | Mr Important's PDF, `/confidential/Group_18.pdf` | The teacher's assigned document; its content is the object the whole watermarking exercise protects. |
| A4 | **RMAP server private key** | `keys/server_priv.asc`, mounted read-only, passphrase `Group_18` | Impersonation: an attacker holding it can decrypt RMAP traffic meant for us, and (critically) forge responses to *other* groups in our name. |
| A5 | **RMAP client public keys / identity list** | `keys/clients/*.asc` | Enumerating which groups exist is a reconnaissance win, and the identity list is our trust anchor for RMAP. |
| A6 | **Authentication signing key** (`SECRET_KEY`) | `.env` → env var → `URLSafeTimedSerializer` | Holding it lets an attacker mint a valid bearer token for *any* `uid` — full authentication bypass without a password. |
| A7 | **Watermark secret / `secret` field** | `Versions.secret` in MariaDB | The `secret` is the whole point of attribution. Whoever reads it can reproduce or deny our attribution. |
| A8 | **Watermarked version links** | `Versions.link` | A guessable link lets an attacker download a copy watermarked for someone else — the exact leak the platform exists to detect. |
| A9 | **User credentials** (email + password hash) | `Users` table | Password reuse against other systems; the hashes themselves support offline cracking. |
| A10 | **Stored documents** | `user-files` volume | Confidential client documents; also the raw material for forging a watermark. |
| A11 | **Our watermarking method code** (`rmc`) | `server/src/redundant_multi_channel.py` | Public in our repo by design — but knowing the exact channels tells an attacker which ones to strip. |
| A12 | **Service continuity** | the whole compose stack | Our flags must stay present and the API functional until the end of the project; a dead service is a failed deliverable. |

---

## 3. Trust boundaries

```
        (untrusted peer)                (semi-trusted)
  other groups' VMs ────────────┐
                                │  B1  HTTP :5000
                                ▼
   ┌──────────────────────────────────────────────┐
   │  server container (Flask + gunicorn, 1 worker)│
   │                                               │
   │   webapp (static/) ──┐                        │
   │                      │ B2 same-origin, but     │
   │                      │    browser is hostile   │
   │   /api/*  ───────────┘                        │
   │                                               │
   │   keys/ (ro mount)  ─ ─ ─ ─ ─ ─  A4, A5       │
   │   confidential/ (ro mount) ─ ─ ─  A3          │
   │   /app/flag  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  A1          │
   └───────────────┬───────────────────────────────┘
                   │  B3  MySQL :3306, compose network only
                   ▼
   ┌──────────────────────────┐
   │  db container (MariaDB)  │      B4  named volumes
   │  Users, Documents,       │◄───── db-data, user-files
   │  Versions                │
   └──────────────────────────┘
                   ▲
                   │  B5  ssh / shell as `softsec`
   ┌──────────────────────────┐
   │  VM host ── compose ── .env (A6, A2)
   └──────────────────────────┘
```

| Boundary | Crossing | Trust position we adopt |
|---|---|---|
| **B1** peer VM → HTTP :5000 | Every API call, including unauthenticated ones | **Most hostile.** Full attacker control of method, path, headers, body, and rate. |
| **B2** browser → same-origin API | The webapp's own requests | Hostile. The user of the webapp is not necessarily benign, and nobody stops curl. |
| **B3** server → MariaDB | Internal compose network, no published port (we removed it, V-11) | Assumed not directly reachable from outside. If it ever is, that is itself a finding. |
| **B4** container → named volumes | `db-data`, `user-files` | Contains the durable state. Note: `user-files` is *not* the same volume the code lives in, so file write via V-07 does not by itself reach `server.py`. |
| **B5** operator → VM shell | SSH, `.env`, docker | Out of the attacker model — if they hold this, the game is already lost. Listed for completeness only. |

---

## 4. Threats (STRIDE)

Each row carries an ID, the STRIDE letter, the asset, and — most importantly —
**whether our current logging can see it**. The last column is the bridge to the
observation points we implemented; a threat with "blind" in that column is
either mitigated by design or is an accepted, documented gap.

### 4.1 B1 — peer VM → HTTP API (the main attack surface)

| ID | S | Threat | Asset | Existing control | Can we see it today? |
|---|---|---|---|---|---|
| T-01 | S | **Forge a bearer token** using the default/weak signing key (V-04 class) and act as another user | A6, A9, A10 | Fail-closed `SECRET_KEY` (≥32 chars, no default) | **Blind** — a forged-but-valid token is indistinguishable from a real one at the gate; only the effect is anomalous |
| T-02 | S | **Enumerate the `Users` table** by registering colliding `login` values — no UNIQUE constraint on `login` (V-09) | A9, A7 | none yet | **Blind** — each request looks like a normal registration |
| T-03 | S | **RMAP identity spoofing**: present another group's identity with a key we do not hold | A4 | RMAP requires a successful PGP decryption with the private key matching the claimed identity | Partially — RMAP failures are logged at WARNING, but without the source IP |
| T-04 | T | **Drop or mutate data through the unauthenticated delete endpoint** (V-02 class) | A10, A12 | `require_auth` + ownership predicate now in place | **Blind** — a legitimate-looking DELETE from an authenticated user leaves no trace |
| T-05 | T | **Exploit a watermarking method to execute code** and read A1/A2 (V-01/V-03 class) | A1, A2 | Both offending methods removed from the registry | **Blind** — the removal is the control; if it regressed there is no runtime signal |
| T-06 | T | **Overwrite files through a traversal filename** on upload (V-07 class) | A10, A12 | `secure_filename`, path containment check, `%PDF-` magic check | **Blind** — the attempt simply returns 400 |
| T-07 | T | **Bypass the PDF content check** with a polyglot file (valid `%PDF-` header, malicious tail) | A10 | magic-byte check only, no structural validation | **Blind**, and a real accepted limitation — see §6 |
| T-08 | R | **Corrupt attribution**: create a watermark version for someone else's document and blame them (V-05/V-06 class) | A7 | ownership predicate added | **Blind** — 404 looks identical to a typo'd ID |
| T-09 | R | **Deny a watermark we issued** by claiming the link/secret was forged | A7, A8 | HMAC binds the payload to `WM_SECRET_KEY` | N/A (cryptographic, not observable) |
| T-10 | I | **Brute-force `POST /api/login`** — no rate limit, no lockout (V-12) | A9 | none — **we chose not to add lockout**, see §6 | **Blind** — this is the single clearest blind spot and the main thing we fix |
| T-11 | I | **Enumerate version links**: `link` derived from a guessable filename scheme (V-08) | A8 | not fixed in this round (deferred) | **Blind** — a 404 on `/api/get-version/<guess>` is silent |
| T-12 | I | **Harvest secrets by reading another user's versions** (V-06 class) | A7 | ownership predicate added | **Blind** |
| T-13 | I | **Read internal state from error bodies** — raw SQL error strings returned to the client (V-10) | A3, A9 | none yet | **Blind**, but the leak is *outbound*: it needs a response-side observation point, which we do not have in this round |
| T-14 | I | **Probe `/healthz`** to learn `db_connected` and weaponise timing (V-16) | A12 | field still present | **Blind** |
| T-15 | D | **Fill the disk** with uploads (V-13 class) | A12 | 20 MB body cap, `MAX_CONTENT_LENGTH` | Partially — oversize bodies are rejected by Flask before our code runs, so they are not in the app log |
| T-16 | D | **Exhaust the single gunicorn worker** with slow RMAP requests (1 worker is required for RMAP state) | A12 | 60 s timeout | **Blind** |

### 4.2 B2 — webapp → API (same origin)

| ID | S | Threat | Asset | Note |
|---|---|---|---|---|
| T-17 | T | **Cross-site request forgery** against the API | A8, A10 | The API authenticates with a bearer token in a header, not a cookie, so a plain cross-site form post cannot reach it. The token is typically kept in JS page state; a successful XSS in the served webapp would grant the attacker everything the user can do. Not mitigated, not observed. |
| T-18 | I | **Cache a watermarked response** and reuse it after withdrawal | A8 | We set `Cache-Control: private, max-age=0` on `get-version`. Observed only as absent caching; no log signal. |

### 4.3 B3/B4 — server → database and volumes

| ID | S | Threat | Asset | Note |
|---|---|---|---|---|
| T-19 | T | **Direct database access from the segment** (V-11 class) | A9, A7, A10 | Port 3306 no longer published; phpMyAdmin bound to `127.0.0.1`. Control is configuration, not detection. |
| T-20 | I | **Dump a volume from the host** | everything | Out of the attacker model (B5). |
| T-21 | T | **Persist through the writable `user-files` volume** after a compromise | A12 | Volume is data-only; it is not on the code path, so it cannot yield execution by itself. |

### 4.4 Protocol-specific — RMAP

RMAP is the one multi-message protocol we own, so it deserves its own list.

| ID | S | Threat | Control | Can we see it today? |
|---|---|---|---|---|
| T-22 | S | **Replay message 2** with a captured `nonceServer` to obtain a second link | `nonceServer` is consumed on use (popped from the index, fields cleared) — one-shot session | Partially — the replay lands in the generic `RMAPError` path |
| T-23 | S | **Cross-session confusion**: mix `nonceClient` from session A with `nonceServer` from session B | Library binds both nonces; the server indexes sessions by `nonceServer` only | Partially |
| T-24 | I | **Enumerate valid identities** by comparing error responses | One generic `invalid request` for every client-side failure, deliberately | Blind by design — this threat is *mitigated by* our log discipline, so we must not log the distinction either (only the fact of the failure, never why). |
| T-25 | T | **Force a watermarking run per call** without limit (each `rmap-get-link` writes a PDF) | no rate limit | **Blind** — and this is a resource-amplification path worth watching |
| T-26 | R | **Deny that a link was issued** by a group we served | We persist a `Versions` row *before* answering, with `intended_for = GroupName` | N/A — this is our evidence side, not a detection need |

---

## 5. From threats to observation points

The rule we applied: **add a log line only where a threat is both realistic and
otherwise invisible.** A threat already fully mitigated by a control does not
need telemetry; a threat we cannot mitigate is exactly where telemetry pays.

| Observation point | Where | Threats it covers | What we log |
|---|---|---|---|
| **OP-1 Authentication gate** | inside `require_auth`, on every failure | T-01, T-04, T-08, T-12 | timestamp, request id, source IP, path, method, failure *class* (missing / malformed / expired / bad-signature), and the claimed `uid` when the signature verified but the user is gone |
| **OP-2 Login outcome** | `POST /api/login`, both branches | **T-10** (the priority), T-02 | email (as supplied), source IP, outcome, and a per-IP failure counter |
| **OP-3 Upload rejection** | `POST /api/upload-document` | T-06, T-07, T-15 | source IP, claimed filename, rejection reason (empty name / traversal / not-a-PDF / oversize) |
| **OP-4 RMAP protocol failure** | both RMAP endpoints' `except RMAPError` branches | T-03, T-22, T-23, T-25 | source IP, endpoint, failure count, and *only* the generic class — never which nonce or identity failed (T-24 requires we do not) |
| **OP-5 Destructive/privileged actions** | successful `delete-document`, `create-watermark`, `read-watermark` | T-04, T-05, T-08, T-12 | acting `uid`, document id, method, outcome — an audit trail rather than a detector |

Deliberately **not** instrumented, with reasons:

- Response bodies (T-13): fixing the leak is the action, and we log nothing that
  would help an attacker correlate.
- Volumetric paths (T-15, T-16): the rules forbid DoS and one VM cannot resist
  it; log noise without defensive value.
- Database (T-19, T-21): already closed at configuration level.

---

## 6. Explicit limitations

Stated because the specification asks what we chose **not** to cover.

1. **We did not add login lockout or rate limiting** (T-10). We added the
   *detection* instead. Rationale: a lockout on a public, unauthenticated
   endpoint is itself a denial-of-service vector — an attacker who can guess a
   victim's email can lock the victim out. Detection without automatic
   punishment fits the rules of engagement better than a control that another
   group could turn into a weapon.
2. **We did not detect forged-but-valid tokens** (T-01). By construction, such a
   token passes every check we make; the mitigation is the fail-closed key, and
   the residual risk is accepted. A future version could bind tokens to a
   `token_version` column to make revocation observable.
3. **PDF content is validated only by magic bytes** (T-07). Structural validation
   of a polyglot would need a parser-level check; we noted it and did not build
   it.
4. **Error-message leakage is outbound** (T-13) and is not in the log view.
   Logging our own responses would be a second front we did not open.
5. **The model stops at B4.** Host-level compromise (B5) is out of scope by
   definition — an attacker with shell access does not need to be detected, they
   have already won, and the journal's incident entries cover that case
   operationally instead.
6. **STRIDE is applied per boundary, not as a formal data-flow graph.** We accept
   that a very unusual multi-step attack chaining three boundaries could fall
   between the rows; our journal-based incident process is the backstop.

---

## 7. What this threat model changed in the project

- It is why OP-1 sits in `require_auth` rather than in each route: the decorator
  is the single chokepoint, so one line covers six threats (T-01, T-04, T-08,
  T-12, and the authentication half of T-10) that would otherwise be invisible.
- It is why we **declined** to add lockout (§6.1) even though T-10 is our top
  ranking threat — the threat model produced a decision, not just a list.
- It is why OP-4 logs the failure *class* but never the reason (T-24): an earlier
  draft logged `unknown identity` separately, which our own threat model flagged
  as an enumeration oracle — the model caught a bug in its own logging plan.
- It is why the model says "detection, not prevention" for T-10 and "prevention,
  not detection" for T-05 and T-19: for each threat we named which of the two we
  were buying, instead of buying both and proving neither.
