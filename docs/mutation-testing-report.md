# Specialization B: Mutation Testing (Group 18)

## Target and tool

We used mutmut 3.8.0 to evaluate `server/src/redundant_multi_channel.py`, which embeds a watermark in a PDF's invisible text layer, metadata, and trailing bytes. We focused on this module because the tests need to verify that the watermark remains recoverable when one or more channels are removed.

Configuration: `server/setup.cfg`
Tests: `server/test/test_redundant_multi_channel.py`

## Environment and reproducibility

The recorded campaign used Python 3.13.5 in a virtual environment under `server/.venv`. It was not run in the Python 3.12 Docker environment. The reported score applies to this recorded campaign and its stated test suite.

## Results

| Measure | Initial (`bbd2a79`) | Intermediate (`3691198`) | Final (`badf808`) |
|---|---:|---:|---:|
| Tests | 9 | 11 | 28 |
| Mutants killed | 143 | 148 | 227 |
| Mutants survived | 108 | 103 | 31 |
| Mutants with no tests | 7 | 7 | 0 |

The initial and intermediate columns were re-run at those commits on 13 Oct (`mutmut-run-at-*.txt`, `mutmut-results-at-*.txt` in the evidence folder). An earlier draft of this table listed a 24-test round that was never committed or saved, so it was dropped.
| Final mutation score | | | 88.0% |

The final run processed 258 mutants (143 killed = 55.4% at the start, 227 = 88.0% at the end). The focused test suite passed all 28 tests.

### Example of a killed mutant

In `_collect`, changing `found += ...` to `found = ...` keeps only the last page's text. The old tests missed it. A new test with the watermark on the first page kills it.

## What we learned

The earlier tests did not adequately isolate all watermark channels. We added tests that check the text layer and metadata independently, remove the trailer or metadata, and verify recovery when only the text layer remains. We also strengthened checks for error messages, malformed payloads, MAC validation, PDF invisibility, and fallback behavior.

Examples of surviving mutations included:
- Changing the PDF text insertion point from `(2, 2)` to `(3, 2)`.
- Changing the invisible text font size from `1` to `2`.
- Changing codec names such as `utf-8` to `UTF-8`.
- Changing the Latin-1 decoding error handler.

These examples do not all indicate defects. Codec names are case-insensitive in Python, and Latin-1 can decode every byte value, so its error handler is not needed. Position and font-size changes may be equivalent for the properties our tests check. These cases show why survivors need investigation rather than being counted automatically as bugs. The per-survivor table is in the analysis file linked below.

## Bugs, weaknesses, and fixes

The main confirmed improvement was to the test suite: channel-isolation tests and stronger assertions now cover behaviors that were previously insufficiently checked. We also corrected the mutmut configuration so the tool can access sibling source modules while mutating only the target file.

No confirmed production defect in `rmc` was established by this campaign.

All 31 survivors were judged one by one in `artifacts/kaleemullahmalik/mutation-testing/surviving-mutants-analysis.md`:

| Disposition | Count | Meaning |
|---|---:|---|
| Equivalent | 20 | Codec-name case, the Latin-1 error handler, JSON options that do not change the current payload, and an unreachable fallback message |
| Acceptable behavior change | 3 | Insertion point and font size of the invisible text; exact values are not part of the contract |
| Equivalent on tested inputs | 8 | The `filetype=` variants passed to PyMuPDF in `add_watermark` and `_collect`: checked on PyMuPDF 1.28.2 with valid, trailing-byte, garbage and empty input, where all behaved like `filetype="pdf"` (`filetype-experiment.txt`); other file types were not tested |

### Separate defects found in `obj-stream-secret`

These were found by the dedicated tests of `server/src/object_stream_secret.py`, not by mutating `rmc`, and are fixed in commit `566a3c91c95aeb07b3f4eb122b9fc2aabb7ab0f8`:

- The incremental trailer left out `/Root`, the reference to the document catalog. The fix keeps the original reference.
- An odd-length hex string made `bytes.fromhex()` raise a raw `ValueError`. It is now caught and raised as `SecretNotFoundError("Malformed Tatou watermark object")`.

Two test gaps were found in these tests and are now closed: `test_odd_length_hex_is_rejected_cleanly` expects `SecretNotFoundError` with the exact message, and `test_new_object_number_xref_and_prev_pointer` asserts that the original `/Root` reference appears in the appended trailer.

## Limitations

The final score is 227 killed mutants out of 258 (approximately 88.0%). This is useful evidence, but it does not prove that the implementation is defect-free. The campaign targeted one module and its dedicated tests, so other test suites may detect additional mutants. Equivalence judgments are based on the current code and runtime and should be revisited if dependencies change.
