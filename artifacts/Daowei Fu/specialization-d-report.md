# Specialization D — Operational Security: report section

**Group 18 · Tatou (SOFTSEC VT 2026) · Phase II**
**Author:** the CC/operational-security member of Group 18.

Companion documents:

| Document | What it holds |
|---|---|
| `specialization-d-threat-model.md` | The threat model this work is derived from (assets, trust boundaries, 26 threats, 5 observation points, explicit limitations). |
| `specialization-d-runbook.md` | How to deploy, capture logs, run the detector, and reproduce the drill. |
| `scripts/detect.py` | The detection rules. |
| `server/src/server.py` | The five observation points, in the application. |
| `server/test/test_audit_log.py` | 17 tests asserting the log is written on the failure paths. |
| `tatou-2026/docs/journal.md` | The incident and operations log this feeds into. |

---

## 1. Why operational security, and why these observation points

The specification asks what we expected to learn and what we actually learned.
The honest starting point is that this specialization was chosen because we had
already built the thing it protects and had never once looked at whether we
would *notice* an attack.

That gap was concrete. By the end of Phase I we had found and fixed 22 issues,
including four critical ones. Every single control we added was preventive, and
every one of them was silent:

- `require_auth` answered 401 for a missing header, an expired token and a forged
  signature alike, and wrote nothing.
- `/api/login` had no rate limit and no record of a failed attempt.
- A rejected upload returned 400 and left no trace.

So an attacker working through our API produced **no signal at all**. We could
tell you what we had blocked; we could not tell you that anyone had tried. Worse,
none of the preventive controls is complete. We chose not to add login lockout
(section 6.1 of the threat model explains why: on a public, unauthenticated
endpoint a lockout is itself a denial-of-service vector usable against a victim
whose email the attacker can guess). Where prevention is deliberately partial,
detection is the control that remains.

The threat model drove the placement, and it changed a decision we had already
made. Our first draft of the RMAP observation point logged `unknown identity`
separately from `cannot decrypt`, because that seemed useful for diagnosis.
Writing the threat model surfaced that this distinction is exactly the
enumeration oracle the specification warns about (threat T-24): a caller could
learn which groups we recognise by comparing the two responses. The rule we ship
records only a fixed failure class and never the claimed identity. **The threat
model caught a flaw in its own logging plan** — that is the clearest evidence I
have that the exercise produced reasoning rather than a document.

| Observation point | Where | Threats covered |
|---|---|---|
| OP-1 | inside `require_auth`, on every failure | T-01, T-04, T-08, T-12 |
| OP-2 | `POST /api/login`, both branches | T-10, T-02 |
| OP-3 | `POST /api/upload-document` | T-06, T-07, T-15 |
| OP-4 | both RMAP endpoints | T-03, T-22, T-23, T-25 |
| OP-5 | successful delete / create-watermark / read-watermark | T-04, T-05, T-08, T-12 |

OP-1 sits in the decorator rather than in each route on purpose: `require_auth` is
the single chokepoint every protected endpoint passes through, so one line of
code covers six threats that would otherwise each need their own instrumentation.
Had we not looked at the code first, the obvious (and wrong) approach would have
been to add a log line to each handler and miss the ones we forgot.

---

## 2. What we built, and the two things we refused to log

The log is one JSON object per line on a dedicated `tatou.audit` logger. Line
delimited JSON was chosen over a log stack because the deployment is a single VM
with one gunicorn worker: it stays greppable with plain tools and is still
directly ingestible by the detector. `propagate=False` keeps audit records
independent of Flask's own logging, so raising or lowering the app log level can
never silently drop an audit record.

Every record carries a `ts`, an `event`, a per-request `request_id`, the peer
`ip`, and the `method`/`path`. The `request_id` exists because the access log and
the audit log are separate streams — without it, correlating "one 401 in the
access log" with "which rejection reason" requires guessing from timestamps.

Two things we deliberately do **not** log, both of which cost us something:

**We do not log the value of `X-Forwarded-For`.** There is no reverse proxy in
front of the server, so the header is entirely attacker-controlled. Honouring it
would let an attacker choose which address the log blames, turning our detection
data into a tool for framing another group. We log the peer address, which cannot
be spoofed at this layer. The cost is real: behind a proxy the log would show the
proxy, and we would need to revisit this. There is no proxy, so we take the
accurate answer over the convenient one.

**We do not log the supplied password or the bearer token.** A bad token is
recorded as `reason: bad_signature` and never as text, and the login rule records
the email as supplied but never the password. This is tested
(`test_no_password_is_ever_logged`, `test_no_token_is_recorded_in_the_log`), not
merely intended — an audit log is a file that gets copied into a report, and a
credential that leaks into it leaks into the report.

---

## 3. The drill: what we actually observed

The specification asks for logs of detected attacks, successful or unsuccessful.
No other group had attacked us at that point, so we produced the traffic
ourselves. This is a validation of the detection capability, not a fabricated
finding: the requests are real, the log lines are real, and the detector ran on
them unmodified. The runbook records the exact commands.

Four patterns, framed as the threats from the threat model:

| Threat | Traffic | Events produced |
|---|---|---|
| T-10 password spraying | 8 login attempts, one address | `login.failure` ×8 |
| T-01 token forging / enumeration | forged token against 8 endpoints | `auth.failure` ×5 |
| T-06 path-shaped filenames | 3 uploads as `../../evilN.pkl` | `upload.normalised` ×3 |
| T-07 content-check probing | 1 upload of a non-PDF | `upload.rejected` ×1 |
| T-22 RMAP abuse | 6 malformed `rmap-initiate` bodies | `rmap.initiate.rejected` ×6 |

All 24 audit events came from `172.18.0.1`, our own container gateway — the
drill traffic entered through the published port exactly as another group's
would.

The detector reported five findings across the four classes. The raw output is
kept as `audit-drill.log` and `detect-drill.out` with their sha256 sums.

---

## 4. Two things the drill taught us that design did not

This is the part worth reporting, because both corrections were invisible until
real traffic was replayed through the rules.

### 4.1 A threshold a deliberate attack could not cross

We set the authentication-failure threshold to 10 in the first draft. The drill
sent eight forged-token requests — **fewer than the threshold required**, so the
rule could not have fired whatever happened. The drill is what made that visible:
we had never checked that our own attack was even large enough to reach the
number we had chosen.

A second, separate mistake surfaced at the same time. Only five of the eight
requests produced an `auth.failure` event at all: the other three were refused
earlier (HTTP 405) because they used the wrong method, so they never reached the
authentication gate. **An observation point placed at the gate sees fewer events
than the attacker sends.** A threshold therefore has to be set against what the
gate actually observes, not against the volume of traffic sent at it.

The lesson is not "lower the number". It is that we had chosen 10 without any
basis, and that a threshold a purpose-built attack cannot reach is not
conservative; it is broken, and it would have sat in the code looking like
diligence. We lowered it to 5 — the same value the login rule uses — and wrote
the reason into the source, including the fact that the first value failed. A
future reader who sees `AUTH_FAILURES_PER_IP = 5` and wonders whether 10 would be
safer will find the answer next to the constant instead of rediscovering it.

### 4.2 A finding whose wording was false

The T-06 rule was originally written as "N rejected uploads", and it fired on
`upload.normalised` events. Replaying the drill showed that this description is
**wrong**: a path-shaped filename like `../../evil1.pkl` is not rejected at all.
`secure_filename` rewrites it to `evil1.pkl` and **the upload succeeds**. The
event records that the name changed, not that the request failed.

We split the rule in two, because the two events mean different things and only
one of them is a refusal:

- `upload.rejected` → the request was refused (not a PDF, no usable name) → T-07
- `upload.normalised` → the upload **succeeded** under a rewritten name, which is
  the stronger traversal signal, because it means the sender tried → T-06

Getting the wording wrong mattered more than it sounds. A finding that says
"3 rejected uploads" when three files were in fact accepted would send a reader
looking for an upload that does not exist, and would make the operator distrust
the log. **A detection rule that describes reality incorrectly is worse than no
rule**, because it is confidently wrong.

A third, smaller correction came from the same replay: the first output rendered
the time span as `0:00:00.019000`. That number is the strongest evidence in a
brute-force finding — no human submits five logins in nineteen milliseconds — and
the default formatting buried it. It now reads `19 ms (machine speed)`, which
puts the machine-speed conclusion in front of the reader instead of behind an
arithmetic exercise.

---

## 5. Recovery

Detection without a response is a log file nobody reads. The recovery side is
deliberately small because the project already had most of it, from the Phase I
deployment incidents:

| Failure | Recovery | Where it is documented |
|---|---|---|
| Database credentials no longer match the volume | `docker compose down -v` then `up --build -d` (**destroys data**, only acceptable because the data is throwaway) | `docs/journal.md`, deployment incident 1 |
| A flag is suspected compromised | regenerate, tell the group, disclose on the course forum | `docs/journal.md`, flag integrity log |
| Watermark key or RMAP passphrase rotated | update `.env`, `docker compose up -d --build`; the server is fail-closed, so a missing or short key stops it starting rather than running in a degraded state | `security-audit-group18.md`, V-04 |
| Container is unhealthy or wedged | `restart: unless-stopped` already brings it back after a reboot; the flag file is rehydrated from `FLAG_2` by `entrypoint.sh` on every start | `docker-compose.yml`, `server/entrypoint.sh` |

The property that ties these together is **fail-closed configuration**. Every
secret the server needs — `SECRET_KEY`, `WM_SECRET_KEY`, the RMAP key pair, the
confidential PDF — is checked at start-up, and the server refuses to boot rather
than running with a default or a missing value. That converts a class of
silent-degradation failures into loud ones at the moment of deployment, which is
the operational equivalent of the detection work in this specialization: make the
failure visible instead of hoping it is not happening.

What is **not** automated: there is no alert channel. The detector writes to
stdout and exits non-zero, and the runbook gives the cron line that would mail an
operator. We did not wire it up, because a course deployment has no operator on
call and a mailbox nobody reads is the same as no alert. We would rather state
that limit than pretend a cron entry is a monitoring system.

---

## 6. Limits

Stated explicitly, because the specification asks what we chose not to cover.

1. **The detector does not block.** It reports. This is deliberate: automatic
   blocking on public endpoints is a denial-of-service tool, as section 4.1
   argues, and the rules of engagement forbid us becoming a problem for others.
2. **Thresholds are tuned to one drill.** Five is defensible for a course
   deployment where an attack is a group of students running a script; it would
   be wrong for a production system with organic traffic, where the same five
   failures could be five users mistyping a password. We tuned against evidence
   we had, not evidence we wished we had.
3. **We observe the application, not the network.** No nginx, no firewall logs,
   no packet capture. An attacker who never reaches the Flask worker — port
   scanning, TLS probing, volumetric traffic — is invisible to this layer. We
   noted this in the threat model (T-15, T-16) and did not build it.
4. **A forged token that verifies is undetectable.** Threat T-01's residual risk:
   if `SECRET_KEY` ever leaked, the tokens minted with it would pass every check
   and look exactly like legitimate traffic. The mitigation is the fail-closed
   key, not detection. This is an accepted limitation, not an oversight.
5. **Logs are not tamper-evident.** They are streamed to stdout and to the
   docker log. An attacker who already has code execution can edit what is
   written from that point on. Detection protects against an attacker who is
   probing the API, not against one who has already won.
6. **The correlation is per-IP.** Two addresses cooperating, or one attacker
   rotating addresses, defeats every windowed rule here. The lockout we declined
   would have the same weakness, which is part of why we declined it.

---

## 7. What changed in the project as a result

- `server/src/server.py` gained the five observation points and a per-request id,
  with `SECRET_KEY`-free, token-free content by construction.
- `server/test/test_audit_log.py` (17 tests) was added. These test the
  **negative** case — that a rejected request still leaves a record — because a
  log line that only appears on the happy path detects nothing.
- `scripts/detect.py` was added, carrying the reasoning for each threshold in
  comments, including the value that failed and why.
- `specialization-d-threat-model.md` and `specialization-d-runbook.md` were added.
- `docs/journal.md` gained the drill entry under "Offensive operations", together
  with a note connecting its two findings to deployment incident 4: a control that
  has never been exercised is not a control, it is an intention.

The change that matters most is not a file. It is that we can now answer a
question we could not answer before: **is anyone attacking us, and what are they
trying?** Before this work the answer was always "we would not know". After it,
the answer is a command and five lines of output.
