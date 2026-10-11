# Mutation Testing — Reproduction Guide

## Target
`server/src/redundant_multi_channel.py`

## Configuration and tests
- Configuration: `server/setup.cfg`
- Tests: `server/test/test_redundant_multi_channel.py`
- Tool: mutmut 3.8.0
- Environment: Python 3.13

## Reproduce a clean campaign

From the repository root:

```bash
cd server
rm -rf mutants .mutmut-cache
.venv/bin/mutmut run
.venv/bin/mutmut results
.venv/bin/python -m pytest test/test_redundant_multi_channel.py -q
```

Removing `mutants` and `.mutmut-cache` prevents reuse of the previous mutation campaign's cached results.

## Verified result
The recorded clean run processed 258 mutants: 227 killed and 31 survived.
The focused test suite passed all 28 tests.

See `mutmut-run.txt`, `mutmut-results.txt`, `pytest.txt`, and
`environment.txt` for captured evidence. Results may vary if the source,
tests, dependencies, or tool versions change.
