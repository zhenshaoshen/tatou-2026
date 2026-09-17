"""redundant_multi_channel.py

A PDF watermarking method that embeds the *same* authenticated payload in
several independent places ("channels"):

1. an invisible text layer drawn on every page (render mode 3),
2. the document metadata (``keywords`` field),
3. trailing bytes appended after the final ``%%EOF`` marker.

Reading the mark tries every channel and returns the first payload that
authenticates with the supplied key. Removing the watermark therefore requires
finding and clearing *all* of the channels; a partially cleaned document still
reveals who it was issued to.

Payload format
--------------
``<MAGIC><base64url(JSON)>`` where the JSON object is::

    {"v":1,"alg":"HMAC-SHA256","mac":"<hex>","secret":"<b64>"}

The MAC is HMAC-SHA256 over ``b"wm:rmc:v1:" + secret_bytes`` keyed with the
caller-provided key. The MAC provides integrity: without the key a third party
cannot forge a mark, nor alter one without invalidating it.

Known limitation
----------------
The secret is base64-encoded, not encrypted: whoever holds the PDF bytes can
read *what* was embedded; the key is only required to *validate* it. This is
the same trade-off the reference ``toy-eof`` method documents.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Final

import fitz  # PyMuPDF

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class RedundantMultiChannel(WatermarkingMethod):
    """Watermark embedded redundantly in three independent places.

    Simple by construction - no crypto beyond HMAC, no compression and no
    image-domain trickery - but strictly harder to erase than a mark that lives
    in a single location.
    """

    name: Final[str] = "rmc"

    _MAGIC: Final[str] = "TATOU-WM-RMC:v1:"
    _TRAILER: Final[bytes] = b"\n%%WM-RMC:v1\n"
    _CONTEXT: Final[bytes] = b"wm:rmc:v1:"
    _PAYLOAD_RE: Final[re.Pattern] = re.compile(
        re.escape(_MAGIC) + r"([A-Za-z0-9_-]+={0,2})"
    )

    # ---------------------
    # Public API overrides
    # ---------------------

    @staticmethod
    def get_usage() -> str:
        return (
            "Watermark embedded redundantly in the invisible text layer of every page, "
            "in the document metadata and after the final %%EOF. position is ignored."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF carrying the same mark in all three channels."""
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        token_body = self._encode(secret, key)
        token = self._MAGIC + token_body

        # Channels 1 and 2 need a document we can restructure. PyMuPDF refuses
        # to re-save a PDF with no pages, so a structurally broken input falls
        # back to the trailer channel rather than failing outright - a weak mark
        # still beats no mark.
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception:
            doc = None

        if doc is not None:
            try:
                if doc.page_count > 0:
                    for page in doc:
                        # render_mode=3 draws nothing, but the text is still
                        # present in the content stream and therefore still
                        # extractable (and still survives a metadata wipe).
                        page.insert_text(
                            fitz.Point(2, 2),
                            token,
                            fontsize=1,
                            render_mode=3,
                        )
                    meta = doc.metadata or {}
                    meta["keywords"] = (
                        (meta.get("keywords") or "") + " " + token
                    ).strip()
                    doc.set_metadata(meta)
                    data = doc.tobytes()
            finally:
                doc.close()

        # Channel 3: cheapest to add, and the first thing a naive
        # "de-watermarking" attempt strips.
        if not data.endswith(b"\n"):
            data += b"\n"
        return data + self._TRAILER + token.encode("ascii") + b"\n"

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        """Always applicable: at worst only the trailer channel is used."""
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Return the embedded secret, using whichever channel still holds it."""
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        candidates = self._collect(data)
        if not candidates:
            raise SecretNotFoundError("No RedundantMultiChannel watermark found")

        # Try every channel: a stripped or corrupted copy of one of them must
        # not hide a perfectly valid mark in another.
        last_error: Exception | None = None
        for body in candidates:
            try:
                return self._decode(body, key)
            except (SecretNotFoundError, InvalidKeyError) as exc:
                last_error = exc
        raise last_error or SecretNotFoundError("No usable watermark payload found")

    # ---------------------
    # Internal helpers
    # ---------------------

    def _collect(self, data: bytes) -> list[str]:
        """Return the distinct payload bodies found in every channel."""
        found: list[str] = []

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception:
            doc = None

        if doc is not None:
            try:
                for page in doc:
                    found += self._PAYLOAD_RE.findall(page.get_text())
                for value in (doc.metadata or {}).values():
                    if value:
                        found += self._PAYLOAD_RE.findall(value)
            finally:
                doc.close()

        # Trailer channel, and a safety net for PDFs PyMuPDF cannot parse.
        found += self._PAYLOAD_RE.findall(data.decode("latin-1", "replace"))

        seen: set[str] = set()
        unique: list[str] = []
        for body in found:
            if body not in seen:
                seen.add(body)
                unique.append(body)
        return unique

    def _encode(self, secret: str, key: str) -> str:
        """Build the base64url-encoded JSON payload body."""
        secret_bytes = secret.encode("utf-8")
        payload = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": self._mac_hex(secret_bytes, key),
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    def _decode(self, token_body: str, key: str) -> str:
        """Validate and decode one payload body."""
        try:
            payload = json.loads(base64.urlsafe_b64decode(token_body))
        except Exception as exc:
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])
            secret_bytes = base64.b64decode(str(payload["secret"]).encode("ascii"))
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        if not hmac.compare_digest(mac_hex, self._mac_hex(secret_bytes, key)):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")
        return secret_bytes.decode("utf-8")

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        return hmac.new(
            key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256
        ).hexdigest()


__all__ = ["RedundantMultiChannel"]
