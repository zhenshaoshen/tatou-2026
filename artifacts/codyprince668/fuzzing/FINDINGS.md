# Specialization A - Fuzzing Findings

Author: Yueming Zhong
Project: Tatou 2026, Group 18

## 1. Why and where

The campaign focused on Tatou's PDF watermarking functionality,
especially the watermark creation API.

The objective was to test whether malformed but valid JSON inputs
could cause unexpected server errors.

## 2. Method

Two deterministic fuzzing campaigns were used:

- Core watermarking: 17 inputs varying secrets, keys, and PDF content.
- API boundary: 7 top-level JSON shapes sent through Flask's test client
  with test-only authentication.

HTTP 500 responses were investigated as potential robustness failures.

## 3. Confirmed finding: FZ-01

Four API inputs caused HTTP 500 before the fix:

- Non-empty JSON list
- JSON string
- JSON integer
- JSON boolean

The other three inputs returned HTTP 400.

All four failures had the same root cause: the API called `.get()`
on JSON values without first checking that they were dictionaries.

This represents one confirmed robustness defect, not four separate bugs.

## 4. Fix and verification

The watermark creation endpoint now validates the top-level JSON
type before accessing its fields.

A regression test covers four malformed JSON shapes against both:

- /api/create-watermark/1
- /api/create-watermark

The eight combinations passed after the fix.

The API fuzzing campaign was also rerun after the fix.
All seven JSON-shape inputs returned HTTP 400.

## 5. Evidence

Pre-fix API results:
server/fuzz/api_results.json

Post-fix API results:
artifacts/codyprince668/fuzzing/api_results_after_fix.json

Core fuzzing results:
server/fuzz/results.json

Regression test:
server/test/test_watermark_fuzz_regression.py

Detailed technical findings:
server/fuzz/findings.md

## 6. Limitations

The campaigns used a small deterministic input set.
They do not provide exhaustive API or PDF-format coverage.

The five exceptions observed in core-level fuzzing were not
confirmed as five independent defects.

No concurrency, performance, or denial-of-service fuzzing was performed.
