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
| 2026-09-24 | Stopped publishing the database and phpMyAdmin to the network; RMAP source PDF validated at start-up | `6315090` |
| 2026-09-24 | Ownership enforced in `create-watermark` / `read-watermark`; upload path and content hardened | `8a1ce37` |
| 2026-09-25 | CI pipeline: unit tests + image build on every push | `d712b57` |
| 2026-09-25 | Cross-user ownership regression test (integration, real database) | `287b664` |
| 2026-09-25 | Dependency vulnerability audit in CI | `6ec4a69`, `da3e02b` |
| 2026-10-05 | RMAP sessions are one-shot: a replayed message 2 now gets a clean 400 instead of a 500 after a repeated watermarking run; negative RMAP tests added (`scripts/rmap_negative.py`: unknown identity, wrong nonce, replay, sequential handshakes) | `2432649` |

### Hardening — reduction of exposed surface

| Date | Change | Rationale |
|---|---|---|
| 2026-09-24 | MariaDB port 3306 no longer published; phpMyAdmin bound to `127.0.0.1` only | Both were reachable by every other group on the isolated network. The database needed no published port: the server reaches it over the compose network |
| 2026-09-24 | Request body size capped at 20 MB | Prevents an authenticated client from filling the disk |
| 2026-09-24 | `keys/`, `confidential/` and `.env` are git-ignored | Private key, assigned document and secrets must never enter version control |
| 2026-10-05 | Gunicorn runs 1 worker with 8 threads, 60 s timeout and an access log (was: 1 sync worker, 30 s, no access log) | Worker timeouts were seen during testing; the cause is not proven (one RMAP run, including `rmc` watermarking, takes about 1.5 s). A single sync worker lets one stuck request block the whole service. We use threads, not workers, because RMAP session state lives in process memory. Commit `624e249` |

---

## Offensive operations

> Every operation we performed against other groups, and every attempt we detected
> against us.

| Date | Target / source | Operation | Result | Evidence |
|---|---|---|---|---|
| _pending_ | | | | |

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
| 2026-09-24 | flag 2 (repo-root `flag`) | `cat flag` in the repository | ✅ present, committed |
| — | flag 3 (Mr Important's PDF) | uploaded by the teacher at the end of Phase I | ⏳ pending |
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

- [ ] Record the offensive operations once attacks start.
- [ ] Re-check flags after any suspected intrusion; regenerate and disclose if leaked.
- [ ] Complete the end-to-end ownership check (two accounts, cross-account access must
      return 404) on the VM after the next deploy.
- [ ] Confirm both group members have implemented their own watermarking method
      (individual responsibility) — done: `rmc` and `obj-stream-secret`.
