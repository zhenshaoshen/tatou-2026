# Specification-to-test mapping (Group 18)

Source of requirements: `server/API.md` (MUST/SHOULD statements) and the course
specification (RMAP endpoints, watermarking methods). Status is based on the
test files present at commit `2577b7b`; counts are `def test_` entries unless noted.

How tests are run:
- **Unit** = `cd server && python -m pytest` (uses the Flask test client or calls methods directly).
- **Integration** = `test/test_ownership_integration.py`, marked `integration`; needs a running instance, skipped otherwise unless `TATOU_REQUIRE_INTEGRATION=1`.
- **Script** = `scripts/rmap_e2e.py`, `scripts/rmap_negative.py`, run against a live server; not counted by pytest coverage.

Status: **Covered** (requirement checked by an automated test), **Partial** (checked only indirectly, only by a script, or only part of it), **Gap** (no automated check).

## 1. API routes

| Route | Requirement (API.md) | Tests | Type | Status |
|---|---|---|---|---|
| `GET /healthz` | MUST be reachable without auth; response MUST contain a string `message` | `test_api.py::test_healthz_route` (200 and JSON only) | Unit | Partial: does not assert that `message` is a string |
| `POST /api/create-user` | MUST validate login, password, email; response MUST include id, login, email | Used as a helper in `test_ownership_integration.py` | Integration | Gap: no validation (negative) tests |
| `POST /api/login` | MUST reject missing email or password; response MUST include token and integer TTL | Used as a helper in `test_ownership_integration.py` | Integration | Gap: no negative or response-shape tests |
| `POST /api/upload-document` | MUST accept only PDF | `test_upload_document.py`: `test_upload_requires_authentication`, `test_non_pdf_content_is_rejected`, `test_pdf_extension_alone_is_not_enough`, `test_filename_traversal_cannot_escape_the_storage_root`, `test_sanitised_filename_keeps_the_expected_extension`; success path (201) in the ownership test | Unit and integration | Covered |
| `GET /api/list-documents` | MUST return all documents of the user | none | none | Gap |
| `GET /api/list-versions[/<id>]` | Owner MUST be able to list versions and recipients | none | none | Gap |
| `GET /api/list-all-versions` | Owner lists all versions | none | none | Gap |
| `GET /api/get-document[/<id>]` | Returns the user's document | none (ownership of this route is not in the cross-user test) | none | Gap |
| `DELETE\|POST /api/delete-document[/<id>]` | Only the owner may delete | `test_delete_document.py`: `test_delete_requires_authentication`, `test_delete_post_requires_authentication`, `test_delete_injection_in_query_is_not_authenticated`, `test_delete_non_numeric_path_is_not_routed` | Unit | Partial: authentication only; no owner-success or cross-user test |
| `GET /api/get-watermarking-methods` | MUST return all methods in `watermarking_utils.METHODS` | Indirectly: `test_watermarking_all_methods.py` iterates `METHODS`; `test_redundant_multi_channel.py::test_method_is_registered` | Unit | Partial: the route itself is not tested |
| `POST /api/create-watermark[/<id>]` | Creates a watermarked version for the owner's document | `test_ownership_integration.py::test_cross_user_document_ownership_is_enforced` (attacker gets 404); methods tested directly | Integration and unit | Partial: no happy-path API test |
| `POST /api/read-watermark[/<id>]` | MUST return the secret read in the document | Same cross-user test (404); round trips tested per method | Integration and unit | Partial: no happy-path API test |
| `GET /api/get-version/<link>` | SHOULD point to a watermarked version specific to the requesting group | `scripts/rmap_e2e.py` (downloads the PDF and reads the mark) | Script | Partial: not in pytest |
| `POST /api/rmap-initiate` | SHOULD respond only to known identities; all submitted keys MUST be valid identities | `test_rmap_initiate.py`: `test_missing_payload_is_rejected`, `test_non_json_body_is_rejected`, `test_malformed_payload_is_rejected`, `test_unknown_identity_is_rejected`, `test_errors_do_not_reveal_whether_the_identity_is_known`, `test_known_identity_gets_a_usable_response_1` | Unit (real RMAP client, throwaway keys) | Covered |
| `POST /api/rmap-get-link` | Returns a 32-hex link only after the watermarked copy exists and is recorded | `test_rmap_get_link.py`: `test_missing_payload_is_rejected`, `test_non_json_body_is_rejected`, `test_malformed_payload_is_rejected`, `test_message_2_without_a_matching_session_is_rejected`, `test_errors_do_not_reveal_internals`; scripts: `rmap_e2e.py` (full handshake, link, PDF, mark), `rmap_negative.py` (6 cases: unknown identity, wrong nonceServer, first message 2 accepted, replay rejected, interleaved handshakes, distinct links) | Unit and script | Covered, but replay and distinct-link behaviour are checked only by the script |

## 2. Security and configuration requirements

| Requirement | Tests | Type | Status |
|---|---|---|---|
| App refuses to start without a strong `SECRET_KEY` | `test_auth_config.py`: `test_app_refuses_to_start_without_secret_key`, `test_app_refuses_the_legacy_default_key`, `test_app_refuses_short_secret_key`, `test_app_starts_with_strong_secret_key` | Unit | Covered |
| Document ownership enforced (V-05, V-06, V-07) | `test_ownership_integration.py::test_cross_user_document_ownership_is_enforced` (create-watermark, read-watermark) | Integration | Partial: other routes not covered |
| Upload path cannot be escaped; only PDFs stored | `test_upload_document.py` (see above) | Unit | Covered |
| RMAP replay of message 2 is rejected (fix `2432649`) | `scripts/rmap_negative.py` | Script | Partial: not in pytest |
| RMAP errors reveal no internals | `test_rmap_initiate.py::test_errors_do_not_reveal_whether_the_identity_is_known`, `test_rmap_get_link.py::test_errors_do_not_reveal_internals` | Unit | Covered |

## 3. Watermarking methods (`watermarking_utils.METHODS`)

| Method | Tests | Notes |
|---|---|---|
| all registered methods | `test_watermarking_all_methods.py`: applicability, add-watermark shape, round trip, parametrised over every method | Generic contract |
| `rmc` (group RMAP method) | `test_redundant_multi_channel.py`, 28 tests; mutation tested (227 of 258 mutants killed, 88%); 100% line and branch coverage | See `docs/mutation-testing-report.md` |
| `obj-stream-secret` | `test_object_stream_secret.py`, 18 test functions (21 cases with parametrisation) | Tested for classic xref tables only |
| `geo-text` | `test_geometric_text_watermark.py`, 16 test functions | See issue below |
| `toy-eof` | covered only by the generic suite | Reference method |

## 4. Issues found while building this table

1. **Duplicate test name in `test_geometric_text_watermark.py`.** `test_secret_is_not_stored_as_plaintext` is defined twice (around lines 166 and 176). Python keeps only the second, so the first is silently dropped. The bodies are identical, so nothing is lost today, but it is a test-suite defect: delete one copy.
2. **Most API routes have no automated test.** create-user, login, list-documents, list-versions, list-all-versions, get-document and get-watermarking-methods have none, and create/read-watermark and delete have only negative or authentication cases. `server.py` coverage is 33%.
3. **Integration tests are skipped by default**, so the cross-user ownership check does not run in a plain `pytest`.

## 5. Planned additions (priority order)

1. Flask test-client tests for create-user and login (missing fields, response shape), and for `healthz` asserting that `message` is a string.
2. Happy-path and cross-user tests for list-documents, list-versions, list-all-versions and get-document.
3. A test-client test for get-watermarking-methods that compares the route output with `METHODS`.
4. Move the replay and distinct-link checks from `rmap_negative.py` into pytest.
5. Remove the duplicate test in the geometric watermark suite.
