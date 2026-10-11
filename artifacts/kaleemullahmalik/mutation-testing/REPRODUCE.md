# Mutation Testing — Reproduction Guide

## Target
`server/src/redundant_multi_channel.py`

## Configuration and tests
- Configuration: `server/setup.cfg`
- Tests: `server/test/test_redundant_multi_channel.py`
- Tool: mutmut 3.8.0
- Environment: Python 3.13.5 in a virtual environment at `server/.venv` (same steps as the repository `README.md`; the 3.12 container used for coverage was not used for this campaign)

## Reproduce a clean campaign

From the repository root:

```bash
cd server
python3 -m venv .venv && . .venv/bin/activate
pip install -q -e ".[dev]" mutmut
rm -rf mutants .mutmut-cache
mutmut run
mutmut results
python -m pytest test/test_redundant_multi_channel.py -q
```

Removing `mutants` and `.mutmut-cache` prevents reuse of the previous mutation campaign's cached results.

## Verified result
The recorded clean run processed 258 mutants: 227 killed and 31 survived.
The focused test suite passed all 28 tests.

See `mutmut-run.txt`, `mutmut-results.txt`, `pytest.txt`, and
`environment.txt` for captured evidence. Results may vary if the source,
tests, dependencies, or tool versions change.
