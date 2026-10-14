# Incident & Operations Journal — Group 18

**Scope:** SOFTSEC VT 2026 group project (Tatou), VM `softsec-group-18`.
**Purpose:** chronological record of incidents (deployment/operational failures, security
incidents) and of the offensive/defensive operations we performed. This is the source
material for the short report required at the end of Phase II, and the evidence base for
the Incident Management practice audited in the Assurance assignment.

**Format:** newest last. Every entry states what happened, the root cause, what we did,
and the impact. `/app/flag` = flag 1, repo-root `flag` = flag 2, Mr Important's PDF = flag 3.

---

## Phase 0 — initial deployment

| Date | Event | Notes |
|---|---|---|
| 2026-09-13 | First deployment of Tatou on the VM; database volume `tatou-2026_db-data` created | Baseline deployment, service reachable, `healthz` responding |
| 2026-09-13 | Flags initialised | flag 1 placed in the container (`/app/flag`), flag 2 committed at the repository root |

> Our public key was registered in the course key directory; that directory is the
> certificate authority of the project, so it is also the list of identities our
> RMAP endpoint accepts.

---

## Phase I — core features

### Deployment incident 1 — application could not reach the database

| Field | Value |
|---|---|
| **When** | 2026-09-17, ~18:24 |
| **Symptom** | `mariadb` inside the db container answered `ERROR 1045 (28000): Access denied for user 'tatou'@'127.0.0.1'`; the application could not connect either |
| **Root cause** | The database volume had been initialised on 2026-09-13 with the passwords `.env` held at that time. MariaDB reads `MARIADB_*` **only when the data directory is created**, so after `.env` was changed to new random passwords the stored credentials no longer matched (`docker volume inspect` → created 09-13T15:45, `stat .env` → modified 09-17T18:24) |
| **Action** | `docker compose down -v` followed by `docker compose up --build -d`, re-initialising the volume from `db/tatou.sql` |
| **Impact** | ~10 minutes of downtime. All database content lost — only throwaway test data at that point |
| **Lesson** | Container-initialised state (databases, volumes) is a *deployment contract*: changing `.env` after the first start does not propagate |

### Deployment incident 2 — RMAP retrieval failed: unknown watermarking method

| Field | Value |
|---|---|
| **When** | 2026-09-17, ~18:45 |
| **Symptom** | `POST /api/rmap-get-link` → HTTP 500 `{"error":"server error"}` |
| **Diagnosis** | Server log: `KeyError: "Unknown watermarking method: 'rmc'. Known: ['toy-eof']"`; `GET /api/get-watermarking-methods` returned `count: 1` |
| **Root cause** | The personal watermarking method (`redundant_multi_channel.py` + registry entry) existed only in a local working copy — never committed or pushed, so the VM ran an older revision |
| **Action** | Committed and pushed, `git pull` + `docker compose up --build -d` on the VM; the method then appeared with `count: 2` |
| **Impact** | RMAP retrieval unavailable until redeployed; handshake unaffected |
| **Lesson** | "It works on my machine" is a deployment defect, not a code defect. Because the failure was fail-closed, the interface returned an explicit error instead of silently falling back to another method — the specification forbids serving a copy that is not individually watermarked, so a silent fallback would have been the real incident |

### Deployment incident 3 — RMAP source document was not a PDF

| Field | Value |
|---|---|
| **When** | 2026-09-17, ~18:49 |
| **Symptom** | `rmap-get-link` → 500; server log `ValueError: Input does not look like a valid PDF (missing %PDF header)` |
| **Diagnosis** | `confidential/Group_18.pdf` on the VM was 2436 bytes and began with `-----BEGIN PGP P...` — a **PGP public key with the same base name**, not the assigned confidential document (73685 bytes) |
| **Root cause** | Two deliverables share the name `Group_18` (group public key and assigned PDF). The file was selected by name and transferred without an integrity check |
| **Action** | Re-transferred the document, verified `sha256` (`3ecdcf8f…`), added a start-up check that refuses to boot unless the file begins with `%PDF-` |
| **Impact** | RMAP retrieval unavailable ~10 minutes; no data loss. The failure would otherwise have surfaced only when another group called us, which is why the check was moved to start-up |
| **Lesson** | An existence check is not a content check. Verify transferred artefacts by checksum — a single `sha256sum` would have prevented ~30 minutes of debugging |

### Deployment incident 4 — the same class of failure recurred on a second machine

| Field | Value |
|---|---|
| **When** | 2026-09-24, ~10:50 |
| **Symptom** | On the developer's local machine the stack came up but `GET /healthz` reported `{"db_connected":false}`; `docker compose logs db` showed a stream of `Access denied for user 'root'@'127.0.0.1'` |
| **Root cause** | **Identical to incident 1**: an older local `db-data` volume initialised with outdated `.env` passwords. No code defect |
| **Action** | `docker compose down -v` + `docker compose up -d`, re-initialising the local volume |
| **Impact** | ~5 minutes; local test instance only |
| **Lesson** | This is the important one: the lesson from incident 1 had been written into a deployment note **that lived outside the repository**, so the second developer never saw it and the class of failure recurred. Logging an incident is not the same as feeding the lesson back into the system. The note has since been moved into this repository (`docs/journal.md`, `docs/deploy-instructions.md`) so that it is part of the artefact everyone actually pulls |

### Security remediation — Phase I code review

Findings, fixes and the reasoning behind them are documented in a separate internal
audit note, deliberately **not** included in this public repository: it enumerates
issues that were not yet fixed at the time of writing, and publishing that list would
hand other groups a map of our remaining weaknesses. What landed in the repository:

| Date | Change | Commit |
|---|---|---|
| 2026-09-17 | Removed command-injection watermark method (RCE) | `2359295` |
| 2026-09-17 | Removed the pickle-based plugin loader (deserialisation RCE) | `2359295` |
| 2026-09-17 | Authentication token key is now fail-closed (no public default) | `2359295` |
| 2026-09-17 | `delete-document`: authentication, parameterised query, ownership | `2359295` |
| 2026-09-17 | RMAP endpoints implemented (`rmap-initiate`, `rmap-get-link`) | `2fdc34a` |
| 2026-09-17 | Personal watermarking method `rmc` (redundant multi-channel) | `bbd2a79` |
| 2026-09-17 | Second personal watermarking method `obj-stream-secret` | `cd0c1fd` |
| 2026-09-17 | Stopped publishing the database and phpMyAdmin to the network; RMAP source PDF validated at start-up | `6315090` |
| 2026-09-24 | Ownership enforced in `create-watermark` / `read-watermark`; upload path and content hardened | `8a1ce37` |
| 2026-09-24 | CI pipeline: unit tests + image build on every push | `d712b57` |
| 2026-09-24 | Cross-user ownership regression test (integration, real database) | `287b664` |
| 2026-09-24 | Dependency vulnerability audit in CI | `6ec4a69`, `da3e02b` |

### Hardening — reduction of exposed surface

| Date | Change | Rationale |
|---|---|---|
| 2026-09-17 | MariaDB port 3306 no longer published; phpMyAdmin bound to `127.0.0.1` only | Both were reachable by every other group on the isolated network. The database needed no published port: the server reaches it over the compose network |
| 2026-09-24 | Request body size capped at 20 MB | Prevents an authenticated client from filling the disk |
| 2026-09-24 | `keys/`, `confidential/` and `.env` are git-ignored | Private key, assigned document and secrets must never enter version control |

---

## Phase II: final delivery

| Date | Change | Commit |
|---|---|---|
| 2026-10-05 | RMAP sessions are one-shot: a replayed message 2 now gets a clean 400 instead of a 500 after a repeated watermarking run; negative RMAP tests added (`scripts/rmap_negative.py`: unknown identity, wrong nonce, replay, sequential handshakes) | `2432649` |
| 2026-10-05 | Gunicorn runs 1 worker with 8 threads, 60 s timeout and an access log (before: 1 sync worker, 30 s, no access log). Worker timeouts were seen during testing and the cause is not proven; one RMAP run, including `rmc` watermarking, takes about 1.5 s. Threads instead of workers because the RMAP session state lives in process memory | `624e249` |
| 2026-10-05 / 06 | Mutation testing of `rmc` with mutmut: 227 of 258 mutants killed, report in `docs/mutation-testing-report.md` | `3691198`, `badf808`, `2ea23fc` |
| 2026-10-06 | Coverage run (45% total) saved in `docs/coverage-report.txt` | `575dba5` |
| 2026-10-06 | `obj-stream-secret`: 21 dedicated tests; two defects fixed (missing `/Root` in the incremental trailer, crash on odd-length hex) | `566a3c9` |
| 2026-10-06 | RMAP client script to collect watermarked PDFs from other groups; `collected/` git-ignored | `0a23b77` |
| 2026-10-07 | Third watermarking method `geo-text` merged | `7920c00`, `f280f4d` |
| 2026-10-10 | De-watermarking tool (rebuild from rasterised pages) and its `--check` mode | `fb6edab`, `2577b7b` |
| 2026-10-10 | Spec-to-test mapping added (`docs/spec-to-test-mapping.md`) | `2b7d928` |
| 2026-10-13 | Coverage rerun under Python 3.13.5: 118 passed, 3 skipped, 55% total; preserved Python 3.12.15 report | Committed evidence; report saved in docs/coverage-report.txt |
| 2026-10-13 | Upgraded to the fixed RMAP library 2.0.0 after the instructor's announcement (wheel pinned in `server/pyproject.toml`; the rebuilt container reports 2.0.0). Library 2.0.0 still reads `data["identity"]` and `data["nonceClient"]` directly, so a validly encrypted message with missing or oddly typed fields could still raise KeyError or TypeError in `rmap-initiate`. Added a catch-all that returns the generic 400, and a check in `rmap-get-link` that the link is exactly 32 lowercase hex characters before any file or database row is written. Two new tests cover both routes (13 RMAP route tests pass). After the rebuild: `healthz` reports `db_connected: true`, `rmap_e2e.py` passes, and `rmap_negative.py` passes 6 of 6 with 0 failures (replay still rejected, distinct links still issued). The link format already matched the instructor's note (bare 32 hex, no URL). Instructor test bench (2026-10-14): eight scenarios passed on fresh reruns. RmapHandshake rerun was blocked by HTTP 409; its latest recorded run passed 19/19 on 2026-10-11. Mr_Important was intentionally not rerun to preserve the flag-3 scenario. Evidence: `artifacts/kaleemullahmalik/test-bench-result.txt`. | `77f5a90` |

---

## Offensive operations

> Every operation we performed against other groups, and every attempt we detected
> against us.

| Date | Target / source | Operation | Result | Evidence |
|---|---|---|---|---|
| 2026-10-06 | Groups 02, 10, 12, 16, 22, 34 | RMAP retrieval of their watermarked PDF (`scripts/rmap_collect.py`) | 6 copies collected, 7 other servers failed on their side (wrong key, no RMAP route, misconfiguration) | `rmap_collect.py` output |
| 2026-10-10 | 14 reachable servers (groups 02, 04, 06, 08, 10, 12, 14, 16, 20, 22, 24, 30, 32, 34) | RMAP retrieval | 7 copies collected (02, 10, 12, 16, 22, 30, 34); 7 failed: 04 key mismatch, 06 no passphrase, 08 method not applicable, 14 and 20 no RMAP route (HTTP 405), 24 key lacks encryption subkey flag, 32 invalid initiation | `rmap_collect.py` output |
| 2026-10-10 | Groups 10, 12, 22 | Rebuilt each PDF from rendered pages at 200 dpi (`scripts/dewatermark.py`), then emailed to the instructor | Structural check clean on all three rebuilt files (re-checked on 2026-10-11 with the fixed checker): no extractable text, no metadata, one `%%EOF`, nothing after it, no XMP. The structural checker reported no extractable traces in all three files; this does not establish whether attribution or re-identification is possible. | `dewatermark.py --check` output |
| 2026-10-06 | Incoming | RMAP retrievals by groups 02, 09, 12, 16, 30 and 34 recorded in the Versions table (checked 2026-10-11) | Expected use of the endpoint | Versions table |

### Defensive drill — operational security (Specialization D, 2026-10-11)

Detection work only counts if it has been shown to fire. No other group had
attacked us at the time, so we produced the traffic ourselves against our own
deployment, through the published port, exactly as another group's requests would
arrive. The requests are real and the log lines are real; the detector ran on
them unmodified. This validates the detection capability — it does not invent a
finding.

| Date | Target / source | Operation | Result | Evidence |
|---|---|---|---|---|
| 2026-10-11 | our own deployment (`172.18.0.1`, via the published port) | 8 login attempts with wrong passwords, one address (threat T-10, password spraying) | detected: `[T-10] 5 failed logins ... in 19 ms (machine speed), 8 total` | `audit-drill.log`, `detect-drill.out` |
| 2026-10-11 | our own deployment | forged bearer token against 8 endpoints (threat T-01, token forging / enumeration) | detected: `[T-01] 5 authentication failures`, and `burst of 5 auth failures across 5 paths in 29 ms` | same |
| 2026-10-11 | our own deployment | 3 uploads with `../../evilN.pkl` filenames (threat T-06) | detected: `[T-06] 3 uploads ... had their filename rewritten by secure_filename`. Note the uploads **succeeded** under the rewritten name — the rule was reworded because of this | same |
| 2026-10-11 | our own deployment | 1 upload of a non-PDF (content-check probing) | `upload.rejected` was logged; no T-07 finding appeared in the detector output | same |
| 2026-10-11 | our own deployment | 6 malformed `rmap-initiate` bodies (threat T-22, RMAP abuse) | detected: `[T-22] 5 RMAP failures ... in 17 ms (machine speed), 6 total` | same |

**Outcome:** 5 findings across 4 threat classes, from 24 audit events.

**The part worth keeping:** two defects in the detector were found by this drill
and by nothing earlier. The authentication-failure threshold was set to 10, and
the drill — eight deliberate attempts — **did not trip it**, because three of the
targeted routes answer 405 before the authentication gate is reached. And the T-06
rule described `upload.normalised` as "rejected uploads" when the upload had in
fact **succeeded** under a rewritten name.

Both corrections are the same lesson as deployment incident 4: a control that has
never been exercised is not a control, it is an intention. Incident 4 was a
deployment lesson that was written down but not fed back; these were detection
rules that were written but never fired. Same failure mode, different layer. See
`specialization-d-report.md` §4.

### Attempts detected against us

| Date | Source | Operation | Result | Evidence |
|---|---|---|---|---|
| 2026-10-06 to 2026-10-11 | Groups 02, 09, 12, 16, 30, 34 | RMAP retrieval of our watermarked copy — expected use, not an attack | served normally; all recorded in the Versions table with `intended_for` set | Versions table |
| — | — | no hostile traffic detected so far | — | — |

<!--
Recording template:

| Date | Target / source | Operation | Result | Evidence |
|---|---|---|---|---|
| 2026-09-xx | Group NN (VM / port) | e.g. attempted to retrieve their confidential PDF through RMAP and strip the watermark | e.g. watermark survived two of three channels; attribution still possible | e.g. sha256 of the retrieved copy, extracted mark |

Rules to respect (from the project specification): no denial of service, no data
deletion, no corrupting another group's platform, no insults, and only tools we
wrote or fully understand. Backdoors for maintaining access are allowed;
destructive actions are not.

Note: other groups are also testing our service. Any successful breach of our
flags must be disclosed on the course forum and the flags regenerated.
-->

---

## Flag integrity log

| Date | Flag | Checked how | Status |
|---|---|---|---|
| 2026-09-24 | flag 1 (container `/app/flag`) | `docker compose exec server cat /app/flag` on the VM | ✅ present, matches ILearn feedback |
| 2026-09-24 | flag 2 (repo-root `flag`) | `cat flag` in the repository | ✅ present (committed to the public repo, see next row) |
| 2026-10-10 | flags 1 and 2 | review of the repository | ⚠️ flag 2 value is in the public git history; `entrypoint.sh` printed the flag 1 value to the container logs until it was changed. Rotation pending |
| — | flag 3 (Mr Important's PDF) | uploaded by the instructor at the end of Phase I | ✅ present  |
| — | any leak notification | course forum / course email | none so far |

---

## Known limitations of this process

- Incidents are still **detected by people**, not by monitoring: there is no alerting
  on the health endpoint, no log aggregation, and no scheduled flag-integrity check.
  This is the difference between our current state and a proactive handling process.
- Recovery from incidents 1 and 4 relied on discarding the database volume. That was
  acceptable only because the data was disposable; for the final deployment, data
  retention would need a real backup path.

## Open items

- [ ] Rotate flags 1 and 2 together (they hold the same value), stop tracking `server/flag`, and note the rotation here.
- [ ] Record the result of the re-identification attempts (until 17 Oct).
- [ ] Re-check flags after any suspected intrusion; regenerate and disclose if leaked.
- [x] Corrected the defensive-drill row: `audit-evidence/detect-drill.out` records `upload.rejected` but shows no T-07 finding.
- [ ] Move the `phase-ii` tag to the final commit.

| 2026-10-14 | Read-only SQL verification of flag 3 | Queried `Documents`, `Versions`, and `Users` in MariaDB. Document ID 44 is `flag_3`, stored under the `Mr_Important` path, owned by login `Mr_Important` (`mr_important@example.com`), size 1,776 bytes. The document has zero associated `Versions` records, so this check confirms database presence and ownership only, not a watermark/version record. The `Mr_Important` test-bench scenario remains at its historical 12/12 pass from 2026-10-04; it was not rerun to preserve flag 3. | Read-only SQL; no database changes or scenario rerun. |
