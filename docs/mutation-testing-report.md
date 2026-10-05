# Specialization B: Mutation testing (Group 18)

## Why this target
`server/src/redundant_multi_channel.py` is the `rmc` method. Our RMAP endpoint uses it to watermark the confidential PDF for every other group, and those groups try to remove the mark in the de-watermarking challenge. Its tests decide whether we can still attribute a leak, so we chose it over the rest of the code base. Only this module was mutated.

## Method
- Tool: mutmut 3.8.0 in a Python 3.12 container. Config: `server/setup.cfg`. Tests: `server/test/test_redundant_multi_channel.py`.
- Expectation: coverage was already good, so we expected survivors in error handling and edge cases.
- Reproduce: in `server/`, run `rm -rf mutants .mutmut-cache`, then `mutmut run`, then `mutmut results`.

## Results
| | Start | After round 1 | Final |
|---|---|---|---|
| Tests | 9 | 24 | 28 |
| Killed | 143 | 217 | 227 |
| Survived | 108 | 34 | 31 |
| No tests | 7 | 7 | 0 |
| Score (killed / 258) | 55% | 84% | 88% |

## What the survivors showed
1. **The redundancy was never tested.** The old tests found the mark only through the raw-bytes scan in `_collect`, so breaking the text-layer or metadata channel went unnoticed (13 survivors). New tests isolate each channel: text layer only, metadata only, a decoy trailer, and a mark on the first page only. The last one kills the mutant that used `found = ...` instead of `found += ...` and kept only the last page.
2. **Error messages were not checked.** The old `match=` was a substring search, so a mutated message still matched. The new tests anchor messages with `^...$`.
3. **Other gaps, now tested:** invisibility (pixel comparison), existing metadata kept, the MAC binds the secret, fallback to the trailer for zero-page and unparseable PDFs, newline handling, and `get_usage` and `is_watermark_applicable` (the 7 no-test mutants).
4. **Dead code:** the final fallback in `read_secret` can never run, because `last_error` is always set once there are candidates (4 survivors). We documented it and left it.
5. **No production defect was found.** The result is a stronger test suite.

## The 31 remaining survivors
| Category | Count |
|---|---|
| Equivalent: codec alias or never-used error handler ("UTF-8", "ASCII", "LATIN-1") | 12 |
| Equivalent with the installed PyMuPDF: `filetype` argument | 8 |
| Equivalent: `ensure_ascii` (payload is only hex and base64) | 3 |
| Dead code in `read_secret` | 5 |
| Cosmetic: position or size of invisible text | 3 |

## Limits
- One module only. The equivalence judgement is manual, and the `filetype` mutants depend on the PyMuPDF version.
- The suite checks that the mark is found and valid. It does not test robustness against real de-watermarking tools (re-saving, rasterising, text extraction), which a mutation score cannot measure.
