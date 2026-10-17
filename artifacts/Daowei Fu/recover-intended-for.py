"""Recover the Intended_for identity from the PDFs the instructor returned.

The RMAP watermark secret is "<identity>:<link>" and it is carried in three
independent channels by our own `rmc` method. This script drives that method
exactly as the server does, so whatever it recovers is what our watermarking
actually says - it is not a re-implementation.

    python recover-intended-for.py <folder> [> answers.csv]

Writes CSV to stdout: FileName,Intended_for, with "Unknown" when no channel
authenticates (which is the expected outcome for a copy that was rebuilt from
rendered pixels).
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent / "tatou-2026"
sys.path.insert(0, str(REPO / "server" / "src"))

from redundant_multi_channel import RedundantMultiChannel  # noqa: E402


def load_key(env_path: Path) -> str:
    """Read WM_SECRET_KEY from .env - never hardcode it in the script."""
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("WM_SECRET_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"WM_SECRET_KEY not found in {env_path}")


def main() -> int:
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else "Group_18")
    key = load_key(REPO / ".env")
    method = RedundantMultiChannel()

    writer = csv.writer(sys.stdout)
    writer.writerow(["FileName", "Intended_for"])

    for pdf in sorted(folder.glob("*.pdf")):
        try:
            secret = method.read_secret(pdf=str(pdf), key=key)
        except Exception as exc:                                   # noqa: BLE001
            # Any failure means no channel authenticated: the mark is gone.
            print(f"# {pdf.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            writer.writerow([pdf.name, "Unknown"])
            continue
        # secret is "<identity>:<link>"
        identity = secret.split(":", 1)[0] if ":" in secret else secret
        print(f"# {pdf.name}: recovered {secret!r}", file=sys.stderr)
        writer.writerow([pdf.name, identity])
    return 0


if __name__ == "__main__":
    sys.exit(main())
