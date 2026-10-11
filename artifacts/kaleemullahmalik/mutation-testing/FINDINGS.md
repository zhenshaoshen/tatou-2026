# Mutation Testing Findings

## Purpose
Mutation testing was applied to the redundant multi-channel watermarking
module because tests must verify that individual recovery channels work,
rather than allowing one channel to hide a failure in another.

## Results
- Initial focused tests: 9
- Final focused tests: 28
- Mutants processed: 258
- Mutants killed: 227
- Mutants survived: 31
- Final mutation score: 227 / 258 = approximately 88.0%

## Interesting surviving mutations
The survivor list includes mutations in `add_watermark`, `read_secret`,
`_collect`, `_encode`, `_decode`, and `_mac_hex`. Examples include changes
to PDF text position and font size, codec names, decoding error handling,
and JSON encoding options.

A surviving mutation is not automatically a defect. Python codec names are
case-insensitive, and Latin-1 can decode every byte value. Other changes
need behavioral tests to determine whether they violate the requirements.

## Test improvements
The focused suite was expanded from 9 to 28 tests. The work strengthened
checks around watermark-channel isolation, malformed payloads, MAC
validation, error handling, PDF invisibility, and fallback behavior.

## Confirmed project defects
This campaign did not establish a confirmed production defect. The primary
finding was an opportunity to strengthen the tests. Surviving mutants should
be individually assessed before being classified as defects or equivalent
mutations.

## Limitations
The campaign targets one module and its dedicated tests. An 88.0% mutation
score does not prove the whole application is defect-free, nor does it prove
that every surviving mutation is harmless. The test suite and runtime
environment also constrain what the campaign can reveal.
