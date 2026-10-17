"""Cross-check: is "Unknown" a real removal, or did our reader miss the mark?

For every PDF, search all three channels rmc uses, independently of the rmc
reader, and report what is physically present:
  - the invisible text layer (extracted text)
  - the document metadata (keywords)
  - the bytes after the final %%EOF

If a file shows the magic string in a channel but rmc returned Unknown, the
reader is at fault. If no channel shows it, the mark really is gone.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pymupdf

MAGIC = "TATOU-WM-RMC:v1:"
TRAILER = b"\n%%WM-RMC:v1\n"

folder = Path(sys.argv[1] if len(sys.argv) > 1 else "Group_18")

print(f"{'file':<46} {'text':<6} {'meta':<6} {'trailer':<8} lastEOF")
print("-" * 90)
for pdf in sorted(folder.glob("*.pdf")):
    raw = pdf.read_bytes()
    doc = pymupdf.open(pdf)
    text = "".join(p.get_text() for p in doc)
    meta = str((doc.metadata or {}).get("keywords") or "")
    doc.close()

    in_text = MAGIC in text
    in_meta = MAGIC in meta
    in_trailer = TRAILER in raw
    after_eof = raw[raw.rfind(b"%%EOF") + 5:].strip(b"\r\n \t\x00")
    print(f"{pdf.name:<46} {str(in_text):<6} {str(in_meta):<6} "
          f"{str(in_trailer):<8} {bool(after_eof)}")
