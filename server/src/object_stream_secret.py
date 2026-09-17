"""object_stream_secret.py

Embeds a secret as a new indirect PDF object via a genuine incremental
update (new object + minimal xref + trailer referencing the previous
xref offset). The secret is encrypted with a deterministic SHA-256-based
keystream and authenticated with HMAC-SHA256, both derived from `key`.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import ClassVar

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)

_MARKER = b"/TatouWM"


def _keystream(key: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key.encode("utf-8") + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, key: str) -> bytes:
    ks = _keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _mac(key: str, data: bytes) -> bytes:
    return hmac.new(key.encode("utf-8"), data, hashlib.sha256).digest()


class ObjectStreamSecret(WatermarkingMethod):
    name: ClassVar[str] = "obj-stream-secret"

    @staticmethod
    def get_usage() -> str:
        return (
            "obj-stream-secret: embeds an encrypted, authenticated secret as "
            "a new indirect PDF object appended via an incremental update. "
            "`position` is ignored. Wrong `key` raises InvalidKeyError."
        )

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("secret must not be empty")
        if not key:
            raise ValueError("key must not be empty")

        ciphertext = _xor(secret.encode("utf-8"), key)
        tag = _mac(key, ciphertext)
        payload = ciphertext.hex() + ":" + tag.hex()

        obj_nums = [int(m.group(1)) for m in re.finditer(rb"(?m)^(\d+)\s+\d+\s+obj\b", data)]
        new_obj_num = (max(obj_nums) + 1) if obj_nums else 1

        startxref_matches = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", data))
        prev_xref_offset = int(startxref_matches[-1].group(1)) if startxref_matches else None

        obj_str = f"{new_obj_num} 0 obj\n<< {_MARKER.decode()} ({payload}) >>\nendobj\n"
        obj_bytes = obj_str.encode("latin-1")
        obj_offset = len(data)

        xref_offset = obj_offset + len(obj_bytes)
        xref_table = f"xref\n{new_obj_num} 1\n{obj_offset:010d} 00000 n \n".encode("ascii")

        prev_clause = f" /Prev {prev_xref_offset}" if prev_xref_offset is not None else ""
        trailer = (
            f"trailer\n<< /Size {new_obj_num + 1}{prev_clause} >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")

        return data + obj_bytes + xref_table + trailer

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not key:
            raise ValueError("key must not be empty")

        pattern = re.compile(rb"/TatouWM \(([0-9a-fA-F]+):([0-9a-fA-F]+)\)")
        match = None
        for match in pattern.finditer(data):
            pass  # keep the last match: most recent watermark wins
        if match is None:
            raise SecretNotFoundError("No Tatou watermark object found in PDF")

        ciphertext = bytes.fromhex(match.group(1).decode("ascii"))
        tag = bytes.fromhex(match.group(2).decode("ascii"))

        if not hmac.compare_digest(tag, _mac(key, ciphertext)):
            raise InvalidKeyError("Provided key does not match watermark authentication tag")

        try:
            return _xor(ciphertext, key).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WatermarkingError("Decrypted secret is not valid UTF-8") from exc


__all__ = ["ObjectStreamSecret"]
