"""Keyed geometric text watermark for PDF documents.

The watermark encodes an authenticated binary payload through small
geometric differences between invisible text carriers placed on PDF pages.

Unlike watermarking methods that store the secret directly in metadata,
trailing bytes, or a dedicated PDF object, this method uses carrier
geometry as the information channel.
"""

from __future__ import annotations


import hashlib
import hmac
from typing import Final
import fitz
import re

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class GeometricTextWatermark(WatermarkingMethod):
    """Encode watermark bits using small geometric carrier displacements."""

    name: Final[str] = "geo-text"
    _VERSION: Final[int] = 1
    _TAG_SIZE: Final[int] = 16
    _CONTEXT: Final[bytes] = b"wm:geo-text:v1:"

    _MAGIC: Final[str] = "GT"

    _X_START: Final[float] = 20.0
    _Y_START: Final[float] = 20.0

    _X_STEP: Final[float] = 8.0
    _Y_STEP: Final[float] = 8.0

    _BIT_ZERO_OFFSET: Final[float] = 0.10
    _BIT_ONE_OFFSET: Final[float] = 0.20

    _CARRIER_FONT_SIZE: Final[float] = 1.0

    _CARRIER_RE: Final[re.Pattern] = re.compile(r"^GT(\d+)$")

    @staticmethod
    def get_usage() -> str:
        return (
            "Encodes an authenticated secret using geometric positions of "
            "invisible page-level text carriers. position is ignored."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:

        data = load_pdf_bytes(pdf)

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception:
            return False

        try:
            if doc.page_count < 1:
                return False

            page = doc[0]

            # Minimum payload:
            # version + length + at least one secret byte + authentication tag.
            minimum_bits = (3 + 1 + self._TAG_SIZE) * 8

            return len(self._carrier_positions(page, minimum_bits)) == minimum_bits
        finally:
            doc.close()

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)

        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        payload = self._encode_payload(secret, key)
        bits = self._bytes_to_bits(payload)

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError("Unable to open PDF") from exc

        try:
            if doc.page_count < 1:
                raise WatermarkingError(
                    "Geometric watermark requires at least one page"
                )

            page = doc[0]
            positions = self._carrier_positions(page, len(bits))

            if len(positions) != len(bits):
                raise WatermarkingError(
                    "PDF page does not have enough geometric watermark capacity"
                )

            for index, (bit, (base_x, y)) in enumerate(zip(bits, positions)):
                offset = self._BIT_ONE_OFFSET if bit == "1" else self._BIT_ZERO_OFFSET

                page.insert_text(
                    fitz.Point(base_x + offset, y),
                    f"{self._MAGIC}{index}",
                    fontsize=self._CARRIER_FONT_SIZE,
                    render_mode=3,
                )

            return doc.tobytes()
        finally:
            doc.close()

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:
        data = load_pdf_bytes(pdf)

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise SecretNotFoundError(
                "Unable to open PDF while reading geometric watermark"
            ) from exc

        try:
            if doc.page_count < 1:
                raise SecretNotFoundError(
                    "PDF has no page containing a geometric watermark"
                )

            bits_by_index = self._collect_carrier_bits(doc[0])

            # First recover the fixed three-byte header:
            # version (1 byte) + secret length (2 bytes).
            header_bit_count = 3 * 8

            try:
                header_bits = "".join(bits_by_index[i] for i in range(header_bit_count))
            except KeyError as exc:
                raise SecretNotFoundError(
                    "Incomplete geometric watermark header"
                ) from exc

            header = self._bits_to_bytes(header_bits)

            version = header[0]
            if version != self._VERSION:
                raise SecretNotFoundError(
                    f"Unsupported geometric watermark version: {version}"
                )

            secret_length = int.from_bytes(header[1:3], "big")

            total_byte_count = 3 + secret_length + self._TAG_SIZE
            total_bit_count = total_byte_count * 8

            try:
                payload_bits = "".join(bits_by_index[i] for i in range(total_bit_count))
            except KeyError as exc:
                raise SecretNotFoundError(
                    "Incomplete geometric watermark payload"
                ) from exc

            payload = self._bits_to_bytes(payload_bits)

            return self._decode_payload(payload, key)

        finally:
            doc.close()

    def _encode_payload(self, secret: str, key: str) -> bytes:
        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        secret_bytes = secret.encode("utf-8")

        if len(secret_bytes) > 65535:
            raise ValueError("Secret is too large")

        header = bytes([self._VERSION]) + len(secret_bytes).to_bytes(2, "big")
        body = header + secret_bytes

        tag = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + body,
            hashlib.sha256,
        ).digest()[: self._TAG_SIZE]

        return body + tag

    def _decode_payload(self, payload: bytes, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        minimum_size = 1 + 2 + self._TAG_SIZE

        if len(payload) < minimum_size:
            raise SecretNotFoundError("Geometric watermark payload is too short")

        version = payload[0]

        if version != self._VERSION:
            raise SecretNotFoundError(
                f"Unsupported geometric watermark version: {version}"
            )

        secret_length = int.from_bytes(payload[1:3], "big")
        expected_size = 3 + secret_length + self._TAG_SIZE

        if len(payload) != expected_size:
            raise SecretNotFoundError("Malformed geometric watermark payload")

        body = payload[: 3 + secret_length]
        secret_bytes = payload[3 : 3 + secret_length]
        stored_tag = payload[3 + secret_length :]

        expected_tag = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + body,
            hashlib.sha256,
        ).digest()[: self._TAG_SIZE]

        if not hmac.compare_digest(stored_tag, expected_tag):
            raise InvalidKeyError(
                "Provided key failed to authenticate the geometric watermark"
            )

        try:
            return secret_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WatermarkingError(
                "Recovered watermark secret is not valid UTF-8"
            ) from exc

    @staticmethod
    def _bytes_to_bits(data: bytes) -> str:
        return "".join(f"{byte:08b}" for byte in data)

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        if len(bits) % 8 != 0:
            raise SecretNotFoundError(
                "Recovered geometric watermark is not byte-aligned"
            )

        try:
            return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
        except ValueError as exc:  # pylint: disable=broad-exception-raised
            raise SecretNotFoundError(
                "Recovered geometric watermark contains invalid bits"
            ) from exc

    def _carrier_positions(
        self,
        page,
        bit_count: int,
    ) -> list[tuple[float, float]]:
        """Return deterministic base positions for the requested carriers."""

        width = float(page.rect.width)
        height = float(page.rect.height)

        usable_width = width - (2 * self._X_START)
        usable_height = height - (2 * self._Y_START)

        columns = int(usable_width // self._X_STEP)
        rows = int(usable_height // self._Y_STEP)

        if columns <= 0 or rows <= 0:
            return []

        capacity = columns * rows

        if bit_count > capacity:
            return []

        positions: list[tuple[float, float]] = []

        for index in range(bit_count):
            row = index // columns
            column = index % columns

            x = self._X_START + column * self._X_STEP
            y = self._Y_START + row * self._Y_STEP

            positions.append((x, y))

        return positions

    def _collect_carrier_bits(self, page) -> dict[int, str]:
        """Recover carrier index -> encoded bit from page geometry."""
        recovered: dict[int, str] = {}
        width = float(page.rect.width)
        usable_width = width - (2 * self._X_START)
        columns = int(usable_width // self._X_STEP)

        if columns <= 0:
            return recovered

        for word in page.get_text("words"):
            x0, y0, x1, y1, text, *_ = word

            match = self._CARRIER_RE.fullmatch(text)
            if match is None:
                continue

            index = int(match.group(1))

            row = index // columns
            column = index % columns

            base_x = self._X_START + column * self._X_STEP

            distance_zero = abs(x0 - (base_x + self._BIT_ZERO_OFFSET))
            distance_one = abs(x0 - (base_x + self._BIT_ONE_OFFSET))

            recovered[index] = "0" if distance_zero < distance_one else "1"

        return recovered


__all__ = ["GeometricTextWatermark"]
