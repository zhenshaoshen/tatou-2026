"""Targeted fuzzing campaign for Tatou watermarking methods.

The campaign starts from valid inputs and mutates one input dimension at a
time.  It is deterministic so interesting cases can be reproduced easily.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

# Allow importing modules from server/src when run from the repository root.
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

import watermarking_utils as WMUtils


VALID_SECRET = "fuzz-secret"
VALID_KEY = "fuzz-key"

SECRET_CASES = [
    "",
    "a",
    "hello world",
    "水印测试",
    "🔐" * 10,
    "A" * 1000,
]

KEY_CASES = [
    "",
    "a",
    "wrong-key",
    "水印密钥",
    "K" * 1000,
]

PDF_CASES = {
    "minimal_pdf": (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"%%EOF\n"
    ),
    "empty": b"",
    "plain_text": b"this is not a pdf",
    "header_only": b"%PDF-",
    "truncated_pdf": b"%PDF-1.4\n1 0 obj\n",
    "pdf_header_garbage": b"%PDF-1.4\nTHIS IS NOT A REAL PDF\n",
}


def record(results, method, dimension, case, outcome, detail=""):
    results.append(
        {
            "method": method,
            "dimension": dimension,
            "case": case,
            "outcome": outcome,
            "detail": str(detail)[:300],
        }
    )


def run_campaign(method_name: str, workdir: Path, results: list[dict]) -> None:
    import pymupdf

    doc = pymupdf.open()
    doc.new_page(width=595, height=842)
    valid_pdf = workdir / "valid.pdf"
    doc.save(valid_pdf)
    doc.close()

    # Campaign 1: mutate the secret while keeping the other inputs valid.
    for index, secret in enumerate(SECRET_CASES):
        try:
            output = WMUtils.apply_watermark(
                pdf=str(valid_pdf),
                secret=secret,
                key=VALID_KEY,
                method=method_name,
                position=None,
            )
            record(
                results,
                method_name,
                "secret",
                f"secret_{index}",
                "accepted",
                f"output_bytes={len(output) if output else 0}",
            )
        except Exception as exc:
            record(results, method_name, "secret", f"secret_{index}", "exception", repr(exc))

    # Campaign 2: mutate the key.
    for index, key in enumerate(KEY_CASES):
        try:
            output = WMUtils.apply_watermark(
                pdf=str(valid_pdf),
                secret=VALID_SECRET,
                key=key,
                method=method_name,
                position=None,
            )
            record(
                results,
                method_name,
                "key",
                f"key_{index}",
                "accepted",
                f"output_bytes={len(output) if output else 0}",
            )
        except Exception as exc:
            record(results, method_name, "key", f"key_{index}", "exception", repr(exc))

    # Campaign 3: mutate the PDF structure.
    for case_name, pdf_bytes in PDF_CASES.items():
        candidate = workdir / f"{case_name}.pdf"
        candidate.write_bytes(pdf_bytes)

        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method_name,
                pdf=str(candidate),
                position=None,
            )

            if not applicable:
                record(results, method_name, "pdf", case_name, "rejected", "not applicable")
                continue

            output = WMUtils.apply_watermark(
                pdf=str(candidate),
                secret=VALID_SECRET,
                key=VALID_KEY,
                method=method_name,
                position=None,
            )
            record(
                results,
                method_name,
                "pdf",
                case_name,
                "accepted",
                f"output_bytes={len(output) if output else 0}",
            )
        except Exception as exc:
            record(results, method_name, "pdf", case_name, "exception", repr(exc))


def main() -> int:
    parser = argparse.ArgumentParser(description="Tatou targeted watermark fuzzer")
    parser.add_argument(
        "--method",
        default="geo-text",
        help="Watermark method to fuzz (default: geo-text)",
    )
    parser.add_argument(
        "--output",
        default="server/fuzz/results.json",
        help="JSON file for campaign results",
    )
    args = parser.parse_args()

    if args.method not in WMUtils.METHODS:
        print(f"Unknown method: {args.method}")
        print("Available methods:", ", ".join(WMUtils.METHODS))
        return 2

    results: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="tatou-fuzz-") as tmp:
        run_campaign(args.method, Path(tmp), results)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    accepted = sum(r["outcome"] == "accepted" for r in results)
    rejected = sum(r["outcome"] == "rejected" for r in results)
    exceptions = sum(r["outcome"] == "exception" for r in results)

    print(f"Method:     {args.method}")
    print(f"Cases:      {len(results)}")
    print(f"Accepted:   {accepted}")
    print(f"Rejected:   {rejected}")
    print(f"Exceptions: {exceptions}")
    print(f"Results:    {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
