"""Tests for the personal watermarking method (RedundantMultiChannel / "rmc").

The interesting property of this method is redundancy: clearing one of its
three channels must not destroy traceability. Most tests below therefore
simulate a de-watermarking attempt and then assert the mark is still readable.
"""
import fitz
import pytest

from redundant_multi_channel import RedundantMultiChannel
from watermarking_method import InvalidKeyError, SecretNotFoundError

SECRET = "Group_07:deadbeefcafe"
KEY = "unit-test-key"


@pytest.fixture
def method():
    return RedundantMultiChannel()


@pytest.fixture
def sample_pdf(tmp_path):
    """A realistic single-page PDF with visible text."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text(fitz.Point(72, 72), "Confidential body text.", fontsize=12)
    doc.set_metadata({"title": "Group_18 confidential", "author": "Group_18"})
    path = tmp_path / "sample.pdf"
    path.write_bytes(doc.tobytes())
    doc.close()
    return path


def _watermark(method, sample_pdf, tmp_path, name="wm.pdf"):
    out = tmp_path / name
    out.write_bytes(method.add_watermark(sample_pdf, secret=SECRET, key=KEY))
    return out


def _strip_trailer(src, dest):
    """Remove the trailing-bytes channel."""
    data = src.read_bytes()
    idx = data.rfind(b"%%WM-RMC:v1")
    dest.write_bytes(data[:idx].rstrip(b"\n") + b"\n")
    return dest


def _wipe_metadata(src, dest):
    """Clear the metadata channel and re-save the document."""
    doc = fitz.open(src)
    doc.set_metadata({})
    dest.write_bytes(doc.tobytes())
    doc.close()
    return dest


def test_roundtrip(method, sample_pdf, tmp_path):
    wm = _watermark(method, sample_pdf, tmp_path)
    assert method.read_secret(wm, key=KEY) == SECRET


def test_output_is_still_a_usable_pdf(method, sample_pdf, tmp_path):
    wm = _watermark(method, sample_pdf, tmp_path)
    assert wm.read_bytes().startswith(b"%PDF-")
    doc = fitz.open(wm)
    assert doc.page_count == 1
    # The visible content must be untouched.
    assert "Confidential body text." in doc[0].get_text()
    doc.close()


def test_survives_trailer_removal(method, sample_pdf, tmp_path):
    """Clearing the cheapest channel must not lose traceability."""
    wm = _watermark(method, sample_pdf, tmp_path)
    cleaned = _strip_trailer(wm, tmp_path / "no_trailer.pdf")
    assert method.read_secret(cleaned, key=KEY) == SECRET


def test_survives_metadata_wipe_and_resave(method, sample_pdf, tmp_path):
    """A metadata wipe (plus a full re-save) must not lose traceability."""
    wm = _watermark(method, sample_pdf, tmp_path)
    cleaned = _wipe_metadata(wm, tmp_path / "no_metadata.pdf")
    assert method.read_secret(cleaned, key=KEY) == SECRET


def test_survives_both_trailer_and_metadata_removal(method, sample_pdf, tmp_path):
    """Two of three channels gone - the in-page layer still carries the mark."""
    wm = _watermark(method, sample_pdf, tmp_path)
    step1 = _strip_trailer(wm, tmp_path / "step1.pdf")
    step2 = _wipe_metadata(step1, tmp_path / "step2.pdf")
    assert method.read_secret(step2, key=KEY) == SECRET


def test_non_string_key_is_rejected(method, sample_pdf):
    with pytest.raises(ValueError, match="Key must be a non-empty string"):
        method.add_watermark(sample_pdf, secret=SECRET, key=123)


def test_wrong_key_is_rejected(method, sample_pdf, tmp_path):
    wm = _watermark(method, sample_pdf, tmp_path)
    with pytest.raises(InvalidKeyError):
        method.read_secret(wm, key="a-different-key")


def test_unwatermarked_pdf_reports_no_secret(method, sample_pdf):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(sample_pdf, key=KEY)


def test_malformed_non_dict_payload_is_rejected(method):
    """A decoded watermark payload must have dictionary structure."""
    import base64
    import json

    token = base64.urlsafe_b64encode(
        json.dumps(["not", "a", "dict"]).encode()
    ).decode()

    with pytest.raises(SecretNotFoundError):
        method._decode(token, KEY)


def test_full_rewrite_loses_the_mark(method, sample_pdf, tmp_path):
    """Honest limit: a document rebuilt from scratch carries no mark.

    This documents the boundary of the technique rather than pretending it is
    unbreakable - retyping/re-rendering a document changes it visibly, which is
    itself detectable by the recipient.
    """
    fresh = fitz.open()
    page = fresh.new_page()
    page.insert_text(fitz.Point(72, 72), "Confidential body text.", fontsize=12)
    rebuilt = tmp_path / "rebuilt.pdf"
    rebuilt.write_bytes(fresh.tobytes())
    fresh.close()

    with pytest.raises(SecretNotFoundError):
        method.read_secret(rebuilt, key=KEY)


def test_method_is_registered():
    import watermarking_utils as WMUtils

    assert "rmc" in WMUtils.METHODS
    assert WMUtils.get_method("rmc").name == "rmc"


# ---------------------------------------------------------------------------
# Mutation-driven tests (mutmut survivors): anchored messages, per-channel
# isolation, invisibility, metadata preservation, MAC binding, trailer fallback.
# ---------------------------------------------------------------------------
import base64
import json

import fitz

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    load_pdf_bytes,
)


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()


def _with_meta(sample_pdf, meta):
    doc = fitz.open(stream=load_pdf_bytes(sample_pdf), filetype="pdf")
    doc.set_metadata(meta)
    data = doc.tobytes()
    doc.close()
    return data


def _only_text_layer(method, sample_pdf):
    """Marked PDF where only the invisible text layer carries the payload."""
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    doc = fitz.open(stream=marked, filetype="pdf")
    doc.set_metadata({})
    data = doc.tobytes(garbage=4, deflate=True)
    doc.close()
    return data


def test_add_watermark_validation_messages(method, sample_pdf):
    with pytest.raises(ValueError, match=r"^Secret must be a non-empty string$"):
        method.add_watermark(sample_pdf, secret="", key=KEY)
    for bad in ("", 123):
        with pytest.raises(ValueError, match=r"^Key must be a non-empty string$"):
            method.add_watermark(sample_pdf, secret=SECRET, key=bad)


def test_read_secret_validation_and_not_found(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    for bad in ("", None, 123):
        with pytest.raises(ValueError, match=r"^Key must be a non-empty string$"):
            method.read_secret(marked, bad)
    with pytest.raises(SecretNotFoundError, match=r"^No RedundantMultiChannel watermark found$"):
        method.read_secret(sample_pdf, KEY)
    with pytest.raises(InvalidKeyError):
        method.read_secret(marked, "wrong-key")


def test_decode_error_messages(method):
    with pytest.raises(SecretNotFoundError, match=r"^Malformed watermark payload$"):
        method._decode("!!!", KEY)
    for bad in (["x"], {"v": 2}):
        with pytest.raises(SecretNotFoundError, match=r"^Unsupported watermark version or format$"):
            method._decode(_b64(bad), KEY)
    with pytest.raises(WatermarkingError, match=r"^Unsupported MAC algorithm: 'HMAC-SHA1'$"):
        method._decode(_b64({"v": 1, "alg": "HMAC-SHA1"}), KEY)
    with pytest.raises(SecretNotFoundError, match=r"^Invalid payload fields$"):
        method._decode(_b64({"v": 1, "alg": "HMAC-SHA256"}), KEY)


def test_mac_binds_the_secret(method):
    forged = _b64({
        "v": 1, "alg": "HMAC-SHA256",
        "mac": method._mac_hex(b"original", KEY),
        "secret": base64.b64encode(b"tampered").decode(),
    })
    with pytest.raises(InvalidKeyError, match=r"^Provided key failed to authenticate the watermark$"):
        method._decode(forged, KEY)


def test_encode_is_compact_json(method):
    raw = base64.urlsafe_b64decode(method._encode(SECRET, KEY))
    assert raw.startswith(b'{"v":1,"alg":"HMAC-SHA256","mac":"')
    assert b" " not in raw


def test_watermark_is_invisible(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    before = fitz.open(stream=load_pdf_bytes(sample_pdf), filetype="pdf")
    after = fitz.open(stream=marked, filetype="pdf")
    try:
        for p0, p1 in zip(before, after):
            assert p0.get_pixmap().samples == p1.get_pixmap().samples
    finally:
        before.close()
        after.close()


def test_metadata_channel_keeps_existing_fields(method, sample_pdf):
    prepared = _with_meta(sample_pdf, {"title": "Original title", "keywords": "alpha"})
    marked = method.add_watermark(prepared, secret=SECRET, key=KEY)
    doc = fitz.open(stream=marked, filetype="pdf")
    meta = doc.metadata
    doc.close()
    assert meta["title"] == "Original title"
    assert meta["keywords"].startswith("alpha " + method._MAGIC)


def test_metadata_keywords_without_existing_value(method, sample_pdf):
    prepared = _with_meta(sample_pdf, {"keywords": ""})
    marked = method.add_watermark(prepared, secret=SECRET, key=KEY)
    doc = fitz.open(stream=marked, filetype="pdf")
    meta = doc.metadata
    doc.close()
    assert meta["keywords"].startswith(method._MAGIC)


def test_unparseable_pdf_falls_back_to_trailer(method):
    junk = b"%PDF-1.4\nthis is not a real pdf\n%%EOF"
    marked = method.add_watermark(junk, secret=SECRET, key=KEY)
    assert marked.startswith(junk + b"\n" + method._TRAILER + method._MAGIC.encode("ascii"))
    assert marked.endswith(b"\n")
    assert method.read_secret(marked, KEY) == SECRET


def test_text_layer_alone_is_enough(method, sample_pdf):
    only_text = _only_text_layer(method, sample_pdf)
    assert method._MAGIC.encode() not in only_text, "raw scan must not see the text layer"
    assert method.read_secret(only_text, KEY) == SECRET


def test_metadata_alone_is_enough(method, sample_pdf):
    payload = method._MAGIC + method._encode(SECRET, KEY)
    only_meta = _with_meta(sample_pdf, {"keywords": "\u4e2d " + payload})
    assert method._MAGIC.encode() not in only_meta, "raw scan must not see the metadata"
    assert method.read_secret(only_meta, KEY) == SECRET


def test_decoy_trailer_does_not_hide_real_mark(method, sample_pdf):
    base = _only_text_layer(method, sample_pdf)
    decoy = method._MAGIC + method._encode("someone-else", "other-key")
    forged = base + method._TRAILER + decoy.encode("ascii") + b"\n"
    assert method.read_secret(forged, KEY) == SECRET


def test_collect_returns_unique_payloads(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    assert len(method._collect(marked)) == 1


def test_zero_page_pdf_falls_back_to_trailer(method):
    zero = (b"%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
            b"2 0 obj\n<</Type/Pages/Kids[]/Count 0>>\nendobj\n"
            b"trailer\n<</Root 1 0 R/Size 3>>\n%%EOF\n")
    marked = method.add_watermark(zero, secret=SECRET, key=KEY)
    assert method.read_secret(marked, KEY) == SECRET


def test_trailer_newline_is_not_doubled(method):
    junk = b"%PDF-1.4\nnot a real pdf\n%%EOF\n"
    marked = method.add_watermark(junk, secret=SECRET, key=KEY)
    assert marked.startswith(junk + method._TRAILER + method._MAGIC.encode("ascii"))


def test_payload_on_first_page_only_is_found(method):
    token = method._MAGIC + method._encode(SECRET, KEY)
    doc = fitz.open()
    p1 = doc.new_page()
    p1.insert_text(fitz.Point(2, 2), token, fontsize=1, render_mode=3)
    p2 = doc.new_page()
    p2.insert_text(fitz.Point(72, 72), "plain page")
    data = doc.tobytes(garbage=4, deflate=True)
    doc.close()
    assert method._MAGIC.encode() not in data, "raw scan must not see the text layer"
    assert method.read_secret(data, KEY) == SECRET


def test_get_usage_and_applicability(method):
    assert method.get_usage() == (
        "Watermark embedded redundantly in the invisible text layer of every page, "
        "in the document metadata and after the final %%EOF. position is ignored."
    )
    assert method.is_watermark_applicable(b"not even a pdf") is True
