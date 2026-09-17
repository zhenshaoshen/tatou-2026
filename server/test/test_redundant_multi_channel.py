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


def test_wrong_key_is_rejected(method, sample_pdf, tmp_path):
    wm = _watermark(method, sample_pdf, tmp_path)
    with pytest.raises(InvalidKeyError):
        method.read_secret(wm, key="a-different-key")


def test_unwatermarked_pdf_reports_no_secret(method, sample_pdf):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(sample_pdf, key=KEY)


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
