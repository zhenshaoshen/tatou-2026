# Specialization B: Mutation Testing (Group 18)

## Target and tool

We used mutmut 3.8.0 to evaluate `server/src/redundant_multi_channel.py`, which embeds a watermark in a PDF's invisible text layer, metadata, and trailing bytes. We focused on this module because the tests need to verify that the watermark remains recoverable when one or more channels are removed.

Configuration: `server/setup.cfg`
Tests: `server/test/test_redundant_multi_channel.py`

## Environment and reproducibility

The recorded campaign used Python 3.13.5 in a virtual environment under `server/.venv`. It was not run in the Python 3.12 Docker environment. The reported score applies to this recorded campaign and its stated test suite.
## Results

| Measure | Initial | Round 1 | Final |
|---|---:|---:|---:|
| Tests | 9 | 24 | 28 |
| Mutants killed | 143 | 217 | 227 |
| Mutants survived | 108 | 34 | 31 |
| Mutants with no tests | 7 | 7 | 0 |
| Final mutation score | | | 88.0% |

The final run processed 258 mutants. The focused test suite passed all 28 tests.

## What we learned

The earlier tests did not adequately isolate all watermark channels. We added tests that check the text layer and metadata independently, remove the trailer or metadata, and verify recovery when only the text layer remains. We also strengthened checks for error messages, malformed payloads, MAC validation, PDF invisibility, and fallback behavior.

Examples of surviving mutations included:
- Changing the PDF text insertion point from `(2, 2)` to `(3, 2)`.
- Changing the invisible text font size from `1` to `2`.
- Changing codec names such as `utf-8` to `UTF-8`.
- Changing the Latin-1 decoding error handler.

These examples do not all indicate defects. Codec names are case-insensitive in Python, and Latin-1 can decode every byte value, so its error handler is not needed. Position and font-size changes may be equivalent for the properties our tests check. These cases show why survivors need investigation rather than being counted automatically as bugs.

## Bugs, weaknesses, and fixes

The main confirmed improvement was to the test suite: channel-isolation tests and stronger assertions now cover behaviors that were previously insufficiently checked. We also corrected the mutmut configuration so the tool can access sibling source modules while mutating only the target file.

No confirmed production defect was established by this campaign. The remaining 31 survivors need to be judged by their actual behavior; some may be equivalent mutations or changes outside the tests' intended contract.

## Limitations

The final score is 227 killed mutants out of 258 (approximately 88.0%). This is useful evidence, but it does not prove that the implementation is defect-free. The campaign targeted one module and its dedicated tests, so other test suites may detect additional mutants. Equivalence judgments are based on the current code and runtime and should be revisited if dependencies change.
