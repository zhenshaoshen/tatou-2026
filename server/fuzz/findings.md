# Tatou Fuzzing Findings

Author: Yueming Zhong
Specialization: A — Fuzzing

## Scope and approach

The campaign targeted Tatou's PDF watermarking functionality at two levels:

1. Watermarking core: structured mutations of secrets, keys, and PDF inputs.
2. Watermark creation API: mutations of the top-level JSON structure.

The API campaign used authenticated requests to reach the watermark creation endpoint. HTTP 500 responses were treated as potential failures requiring investigation, rather than automatically classified as separate bugs.

## Campaign results

### Watermarking core

17 test cases were executed:

- 8 accepted
- 4 rejected
- 5 raised exceptions

These exceptions require individual interpretation. An exception caused by an invalid PDF is not necessarily a security vulnerability.

### Watermark creation API

7 JSON input shapes were tested:

| Input | HTTP status before fix |
|---|---|
| Empty object | 400 |
| Empty list | 400 |
| Non-empty list | 500 |
| String | 500 |
| Integer | 500 |
| Boolean | 500 |
| Null | 400 |

## Finding FZ-01: Non-object JSON causes HTTP 500

**Affected component:** `/api/create-watermark`

**Observation:** Four malformed JSON shapes caused HTTP 500 responses.

**Root cause:** The endpoint assumed that the parsed JSON payload was a dictionary and called `.get()` without first checking its type.

**Fix:** Validate that the top-level JSON value is an object before accessing its fields. Non-object values now receive HTTP 400.

**Regression test:** `server/test/test_watermark_fuzz_regression.py`

The regression test checks four malformed JSON shapes against both supported endpoint forms:

- `/api/create-watermark/1`
- `/api/create-watermark`

All eight input combinations passed after the fix.

**Interpretation:** The four HTTP 500 responses represent one underlying robustness defect, not four independent vulnerabilities.

## Limitations

The campaigns used a small, deterministic set of structured inputs rather than exhaustive fuzzing. The results do not establish complete coverage of PDF formats, watermarking methods, authentication behavior, or concurrent requests.

The five core-level exceptions have not yet been established as independent defects.
