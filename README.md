# Tatou (Group 18 fork)

A web platform for PDF watermarking, used in the SOFTSEC VT 2026 group project. It started from
`nharrand/tatou-2026`, which is meant for teaching and contains security vulnerabilities on purpose.
This fork fixes many of them, but do not deploy it on an open network.

Everything is documented in `docs/`:

| File | What it covers |
|---|---|
| `docs/deploy-instructions.md` | Deployment and verification on the VM |
| `docs/journal.md` | Incidents, changes, offensive operations, flag log |
| `docs/spec-to-test-mapping.md` | Which tests cover which API routes and requirements |
| `docs/mutation-testing-report.md` | Mutation testing of the `rmc` method |
| `docs/coverage-report.txt` | Coverage report and notes on its limits |
| `server/API.md` | API specification |

## Get the code

```bash
git clone https://github.com/zhenshaoshen/tatou-2026.git
cd tatou-2026
```

The end of each phase is tagged `phase-0`, `phase-i` and `phase-ii`.

## Unit tests

```bash
cd server
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

`test/test_ownership_integration.py` needs a running instance and is skipped without one.
Set `TATOU_REQUIRE_INTEGRATION=1` to make it fail instead of skip.

## Deploy

From the root of the repository:

```bash
cp sample.env .env          # then edit .env, see docs/deploy-instructions.md
docker compose up --build -d
docker compose logs -f
curl -s localhost:5000/healthz
```

The server needs the RMAP keys (`keys/`) and the assigned PDF (`confidential/`). Neither is committed.
`docs/deploy-instructions.md` lists every file and variable and has a troubleshooting table.

## API tests (against a running server)

These scripts talk to the live server, so coverage does not see them:

```bash
docker compose cp scripts/rmap_e2e.py server:/app/rmap_e2e.py
docker compose exec server python /app/rmap_e2e.py --base-url http://localhost:5000 \
  --identity Group_18 --client-private-key /app/keys/server_priv.asc \
  --server-public-key /app/keys/server_pub.asc          # full RMAP handshake, expect PASS

docker compose cp scripts/rmap_negative.py server:/app/rmap_negative.py
docker compose exec server python /app/rmap_negative.py 2>&1 | grep -E "PASS|FAIL"
```

## Coverage

The recorded coverage result was produced with Python 3.13.5 in the
virtual environment under `server/.venv`, not inside Docker. To reproduce
the run from the repository root:

```bash
cd server
. .venv/bin/activate
python -m pytest --cov=src --cov-branch 2>&1 | tee ../artifacts/kaleemullahmalik/coverage-testing/coverage-python-3.13.5.txt
```

The recorded summary is in `docs/coverage-report.txt`; the raw output is in
`artifacts/kaleemullahmalik/coverage-testing/coverage-python-3.13.5.txt`.
The separate Python 3.12.15 result is preserved in
`docs/coverage-report-python-3.12.15.txt`.

## Mutation testing

The recorded campaign (`artifacts/kaleemullahmalik/mutation-testing/`) was run in a Python 3.13 virtual environment in `server/`, not in the 3.12 coverage container. From the repository root:

```bash
cd server
python3 -m venv .venv && . .venv/bin/activate
pip install -q -e ".[dev]" mutmut
rm -rf mutants .mutmut-cache
mutmut run
mutmut results            # recorded: 258 mutants, 227 killed, 31 survived
python -m pytest test/test_redundant_multi_channel.py -q   # 28 tests
```

The configuration is in `server/setup.cfg` (target `src/redundant_multi_channel.py`).
The summary is in `docs/mutation-testing-report.md`; the survivor-by-survivor analysis is in `artifacts/kaleemullahmalik/mutation-testing/surviving-mutants-analysis.md`.

## Tools

- `scripts/rmap_collect.py`: runs the RMAP handshake against other groups' servers and saves the PDFs they return.
- `scripts/dewatermark.py`: rebuilds a PDF from its rendered pages and checks the result for leftover traces.
