"""De-watermark a PDF by rebuilding it from rasterised pages.

    python dewatermark.py <input.pdf> <output.pdf> [--dpi 200]
    python dewatermark.py --check <output.pdf> [<output.pdf> ...]

Why rebuilding rather than editing
---------------------------------
Every watermark channel we know of in this project is carried either by the page
content stream (an invisible text run), by the document metadata, by bytes after
the final %%EOF, or by an incremental-update revision. Rebuilding the document
from rendered pixels removes all four at once, instead of removing the ones we
happen to remember:

  content stream   an invisible text run lives here                -> rasterised away
  metadata         DocInfo (/Keywords and friends) and XMP         -> new empty document
  trailing bytes   everything after the last %%EOF                 -> never copied
  revisions        a second %%EOF plus an incremental trailer      -> never copied
  orphan objects   unreferenced objects left by an earlier edit    -> garbage=4
  trailer /ID      a per-document identifier that survives edits   -> regenerated

What this does NOT remove
-------------------------
A mark that is baked into the *rendered pixels* -- a visible or geometric mark,
or a sub-pixel shift of rendered text -- survives rasterising. The --check mode
below cannot detect that either; the only defence is to look at the page. Treat
a clean --check as "no text, metadata, trailer or revision traces", not as
"certainly unattributable".

Keep the pages readable: --dpi 200 is a reasonable default. Raising it makes the
file larger without removing anything extra.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pymupdf

# Strings that would give us away if they survived in the bytes. Extend this list
# if a target's own watermark format is known (for example its method name).
TOKENS = [
    b"Group_18",
    b"group_18",
    b"18@18.com",
    b"Tatou",
    b"TatouWM",
    b"TATOU-WM",
    b"watermark",
    b"obj-stream",
    b"obj_stream",
    b"rmc",
    b"redundant",
]


def dewatermark(src: Path, dst: Path, dpi: int = 200) -> None:
    doc = pymupdf.open(src)
    if doc.needs_pass:
        raise SystemExit(f"{src}: encrypted, cannot process")
    if doc.page_count == 0:
        raise SystemExit(f"{src}: no pages")

    out = pymupdf.open()
    try:
        for page in doc:
            pix = page.get_pixmap(dpi=dpi, alpha=False)
            new = out.new_page(width=page.rect.width, height=page.rect.height)
            new.insert_image(new.rect, pixmap=pix)
        out.set_metadata(
            {
                "title": "",
                "author": "",
                "subject": "",
                "keywords": "",
                "creator": "",
                "producer": "",
                "creationDate": "",
                "modDate": "",
            }
        )
        try:
            out.del_xml_metadata()
        except Exception:
            pass  # no XMP to delete, or the call is unavailable
        out.save(dst, garbage=4, deflate=True, clean=True)
    finally:
        out.close()
        doc.close()

    before = src.stat().st_size
    after = dst.stat().st_size
    print(f"{src.name} -> {dst.name}: {before:,} -> {after:,} bytes, dpi={dpi}")


def check(pdf: Path) -> bool:
    """Report the traces we can detect objectively. Returns True when clean."""
    raw = pdf.read_bytes()
    doc = pymupdf.open(pdf)
    problems: list[str] = []

    text = "".join(p.get_text() for p in doc)
    if text.strip():
        problems.append(f"extractable text remains ({len(text.strip())} chars)")

    # Only the fields a caller can actually set are worth checking. PyMuPDF also
    # reports read-only keys such as 'format' and 'encryption', which are always
    # non-empty and are not metadata written by the producer.
    settable = ("title", "author", "subject", "keywords", "creator", "producer",
                "creationDate", "modDate")
    meta = {k: v for k, v in (doc.metadata or {}).items() if k in settable and v}
    if meta:
        problems.append(f"metadata remains: {meta}")

    eofs = raw.count(b"%%EOF")
    if eofs > 1:
        problems.append(f"{eofs} %%EOF markers -> incremental revisions remain")

    tail = raw[raw.rfind(b"%%EOF") + 5 :]
    if tail.strip(b"\r\n \t\x00"):
        problems.append(f"{len(tail)} bytes after the final %%EOF")

    if b"xpacket" in raw or b"/XMP" in raw or b"xmlns:pdf" in raw:
        problems.append("XMP metadata remains")

    doc.close()

    print(f"{pdf}  ({len(raw):,} bytes, {pdf.stat().st_size:,} on disk)")
    hits = 0
    for token in TOKENS:
        for m in re.finditer(re.escape(token), raw):
            print(f"  TOKEN  {token.decode()!r} at offset {m.start()}")
            hits += 1
    if hits:
        problems.append(f"{hits} watermark-related token(s) found in the bytes")

    for problem in problems:
        print(f"  PROBLEM  {problem}")
    if not problems:
        print("  clean: no text, metadata, trailer, revision or token traces")
    return not problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", nargs="?", help="input PDF (omit with --check)")
    ap.add_argument("dst", nargs="?", help="output PDF")
    ap.add_argument("--dpi", type=int, default=200)
    ap.add_argument("--check", nargs="+", metavar="PDF")
    args = ap.parse_args()

    if args.check:
        return 0 if all(check(Path(p)) for p in args.check) else 1

    if not args.src or not args.dst:
        ap.error("need <input.pdf> <output.pdf>, or --check <pdf> ...")
    dewatermark(Path(args.src), Path(args.dst), dpi=args.dpi)
    return 0


if __name__ == "__main__":
    sys.exit(main())
