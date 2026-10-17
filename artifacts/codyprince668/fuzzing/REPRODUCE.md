# Specialization A - Fuzzing: Reproduction Guide

Author: Yueming Zhong
Project: Tatou 2026, Group 18

## Scope

This work tests the robustness of Tatou's PDF watermarking functionality.

Two campaigns were developed:
1. Core-level fuzzing of secrets, keys, and PDF inputs.
2. API-level fuzzing of JSON input shapes.

## Files

- Core fuzzer: server/fuzz/fuzz_watermark.py
- API fuzzer: server/fuzz/fuzz_watermark_api.py
- Core results: server/fuzz/results.json
- API results: server/fuzz/api_results.json
- Findings: server/fuzz/findings.md
- Regression tests: server/test/test_watermark_fuzz_regression.py

## Reproduce core fuzzing

Run from the repository root:

    python server/fuzz/fuzz_watermark.py --method geo-text

The recorded campaign contains 17 cases:
8 accepted, 4 rejected, and 5 exceptions.

## Reproduce API fuzzing

Run from the repository root:

    python server/fuzz/fuzz_watermark_api.py --output /tmp/tatou-api-fuzz.json

The script uses Flask's test client and test-only authentication.
It does not require credentials for the deployed Tatou server.

The seven JSON-shape cases should all return HTTP 400
on the fixed version.

The historical pre-fix results are stored in:

    server/fuzz/api_results.json

The recorded post-fix results are stored in:

    artifacts/codyprince668/fuzzing/api_results_after_fix.json

Do not overwrite the historical pre-fix results.

## Regression tests

Run:

    python -m pytest server/test/test_watermark_fuzz_regression.py -q

Run the complete test suite:

    python -m pytest server/test -q --disable-warnings

## Confirmed finding

FZ-01: Non-object JSON payloads caused HTTP 500 responses
in the watermark creation API.

The fix validates the JSON type before accessing its fields.
Regression tests cover both endpoint forms and four malformed
JSON shapes.

## Limitations

The campaigns use small, deterministic input sets.
Exceptions are not automatically classified as vulnerabilities.
The original API results are retained as pre-fix evidence.
