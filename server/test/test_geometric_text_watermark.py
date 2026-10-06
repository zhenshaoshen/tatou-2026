import pytest
import fitz

from geometric_text_watermark import GeometricTextWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError


SECRET = "Group_18:codyprince668"
KEY = "unit-test-key"


@pytest.fixture
def method():
    return GeometricTextWatermark()


def test_payload_roundtrip(method):
    payload = method._encode_payload(SECRET, KEY)

    assert isinstance(payload, bytes)
    assert method._decode_payload(payload, KEY) == SECRET


def test_payload_wrong_key_is_rejected(method):
    payload = method._encode_payload(SECRET, KEY)

    with pytest.raises(InvalidKeyError):
        method._decode_payload(payload, "wrong-key")


def test_payload_tampering_is_detected(method):
    payload = bytearray(method._encode_payload(SECRET, KEY))

    # Flip one bit inside the encoded secret.
    payload[3] ^= 0x01

    with pytest.raises(InvalidKeyError):
        method._decode_payload(bytes(payload), KEY)


def test_payload_truncation_is_rejected(method):
    payload = method._encode_payload(SECRET, KEY)

    with pytest.raises(SecretNotFoundError):
        method._decode_payload(payload[:-1], KEY)


def test_empty_secret_is_rejected(method):
    with pytest.raises(ValueError):
        method._encode_payload("", KEY)


def test_bytes_bits_roundtrip(method):
    original = b"\x00\x01\x7f\x80\xffTatou"

    bits = method._bytes_to_bits(original)

    assert set(bits) <= {"0", "1"}
    assert len(bits) == len(original) * 8
    assert method._bits_to_bytes(bits) == original


def test_bits_must_be_byte_aligned(method):
    with pytest.raises(SecretNotFoundError):
        method._bits_to_bytes("101")


@pytest.fixture
def sample_pdf(tmp_path):
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text(
        fitz.Point(72, 72),
        "Confidential document body.",
        fontsize=12,
    )

    path = tmp_path / "sample.pdf"
    path.write_bytes(doc.tobytes())
    doc.close()

    return path


# add two tests
def test_watermark_output_is_valid_pdf(method, sample_pdf):
    original = sample_pdf.read_bytes()

    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    assert isinstance(watermarked, bytes)
    assert watermarked.startswith(b"%PDF-")
    assert len(watermarked) > len(original)

    doc = fitz.open(stream=watermarked, filetype="pdf")

    assert doc.page_count == 1
    assert "Confidential document body." in doc[0].get_text()

    doc.close()


def test_method_is_applicable_to_normal_pdf(method, sample_pdf):
    assert method.is_watermark_applicable(sample_pdf) is True


def test_pdf_roundtrip(method, sample_pdf, tmp_path):
    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    output = tmp_path / "geo-watermarked.pdf"
    output.write_bytes(watermarked)

    assert method.read_secret(output, key=KEY) == SECRET


def test_pdf_wrong_key_is_rejected(method, sample_pdf, tmp_path):
    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    output = tmp_path / "geo-watermarked.pdf"
    output.write_bytes(watermarked)

    with pytest.raises(InvalidKeyError):
        method.read_secret(output, key="wrong-key")


def test_unwatermarked_pdf_reports_no_secret(method, sample_pdf):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(sample_pdf, key=KEY)


def test_survives_clean_resave(method, sample_pdf, tmp_path):
    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    doc = fitz.open(stream=watermarked, filetype="pdf")

    rewritten = doc.tobytes(
        garbage=4,
        clean=True,
        deflate=True,
    )

    doc.close()

    output = tmp_path / "rewritten.pdf"
    output.write_bytes(rewritten)

    assert method.read_secret(output, key=KEY) == SECRET


def test_secret_is_not_stored_as_plaintext(method, sample_pdf):
    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    assert SECRET.encode("utf-8") not in watermarked


def test_secret_is_not_stored_as_plaintext(method, sample_pdf):
    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    assert SECRET.encode("utf-8") not in watermarked


def test_incomplete_carriers_are_rejected(
    method,
    sample_pdf,
    tmp_path,
    monkeypatch,
):
    watermarked = method.add_watermark(
        sample_pdf,
        secret=SECRET,
        key=KEY,
    )

    output = tmp_path / "damaged-watermarked.pdf"
    output.write_bytes(watermarked)

    original_collect = method._collect_carrier_bits

    def damaged_collect(page):
        bits = original_collect(page)
        bits.pop(10, None)
        return bits

    monkeypatch.setattr(
        method,
        "_collect_carrier_bits",
        damaged_collect,
    )

    with pytest.raises(SecretNotFoundError):
        method.read_secret(output, key=KEY)
