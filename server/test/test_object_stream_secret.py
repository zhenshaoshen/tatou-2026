"""Dedicated tests for the obj-stream-secret watermarking method."""
import re

import fitz
import pytest

from object_stream_secret import ObjectStreamSecret, _keystream, _mac, _xor
from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError

KEY = "test-key-123"
SECRET = "Group_18:0123456789abcdef0123456789abcdef"
MARKER = b"/TatouWM ("


@pytest.fixture()
def method():
    return ObjectStreamSecret()


@pytest.fixture()
def sample_pdf():
    doc = fitz.open()
    doc.new_page().insert_text((72, 72), "Hello Tatou")
    data = doc.tobytes()
    doc.close()
    return data


def test_name_and_usage(method):
    assert method.name == "obj-stream-secret"
    usage = method.get_usage()
    assert "obj-stream-secret" in usage and "InvalidKeyError" in usage


@pytest.mark.parametrize("secret", [SECRET, "a", "h\u00e9llo \u2713 unicode", "x" * 200])
def test_roundtrip(method, sample_pdf, secret):
    marked = method.add_watermark(sample_pdf, secret=secret, key=KEY)
    assert method.read_secret(marked, KEY) == secret


def test_keystream_covers_requested_length_and_blocks_differ():
    ks = _keystream("k", 100)
    assert len(ks) == 100
    assert ks[:32] != ks[32:64]
    assert _xor(_xor(b"abc", "k"), "k") == b"abc"


def test_same_input_gives_identical_output(method, sample_pdf):
    a = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    b = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    assert a == b
    assert a != method.add_watermark(sample_pdf, secret=SECRET, key="another-key")


def test_secret_is_not_stored_in_plaintext(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    assert SECRET.encode() not in marked
    assert KEY.encode() not in marked


def _flip(data, position):
    buf = bytearray(data)
    buf[position] = ord("0") if buf[position] != ord("0") else ord("1")
    return bytes(buf)


def test_wrong_key_is_rejected(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    with pytest.raises(InvalidKeyError, match=r"^Provided key does not match watermark authentication tag$"):
        method.read_secret(marked, "wrong-key")


def test_tampered_ciphertext_is_detected(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    start = marked.index(MARKER) + len(MARKER)
    with pytest.raises(InvalidKeyError):
        method.read_secret(_flip(marked, start), KEY)


def test_tampered_tag_is_detected(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    colon = marked.index(b":", marked.index(MARKER))
    with pytest.raises(InvalidKeyError):
        method.read_secret(_flip(marked, colon + 1), KEY)


def test_missing_watermark_raises_not_found(method, sample_pdf):
    with pytest.raises(SecretNotFoundError, match=r"^No Tatou watermark object found in PDF$"):
        method.read_secret(sample_pdf, KEY)


def test_empty_inputs_are_rejected(method, sample_pdf):
    with pytest.raises(ValueError, match=r"^secret must not be empty$"):
        method.add_watermark(sample_pdf, secret="", key=KEY)
    with pytest.raises(ValueError, match=r"^key must not be empty$"):
        method.add_watermark(sample_pdf, secret=SECRET, key="")
    with pytest.raises(ValueError, match=r"^key must not be empty$"):
        method.read_secret(sample_pdf, "")


def test_non_utf8_plaintext_raises_watermarking_error(method, sample_pdf):
    ct = _xor(b"\xff\xfe\xfd", KEY)
    tag = _mac(KEY, ct)
    forged = sample_pdf + b"\n/TatouWM (" + ct.hex().encode() + b":" + tag.hex().encode() + b")\n"
    with pytest.raises(WatermarkingError, match=r"^Decrypted secret is not valid UTF-8$"):
        method.read_secret(forged, KEY)


def test_odd_length_hex_is_rejected_cleanly(method, sample_pdf):
    crafted = sample_pdf + b"\n/TatouWM (abc:def)\n"
    with pytest.raises((SecretNotFoundError, InvalidKeyError, WatermarkingError)):
        method.read_secret(crafted, KEY)


def test_incremental_update_keeps_original_bytes(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    assert marked.startswith(sample_pdf)
    assert len(marked) > len(sample_pdf)
    assert marked.endswith(b"%%EOF\n")


def test_result_is_still_a_readable_pdf(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    doc = fitz.open(stream=marked, filetype="pdf")
    try:
        assert doc.page_count == 1
        assert "Hello Tatou" in doc[0].get_text()
    finally:
        doc.close()


def test_new_object_number_xref_and_prev_pointer(method, sample_pdf):
    marked = method.add_watermark(sample_pdf, secret=SECRET, key=KEY)
    tail = marked[len(sample_pdf):]
    top = max(int(m.group(1)) for m in re.finditer(rb"(?m)^(\d+)\s+\d+\s+obj\b", sample_pdf))
    prev = re.findall(rb"startxref\s+(\d+)\s+%%EOF", sample_pdf)[-1].decode()
    new_obj = ("%d 0 obj" % (top + 1)).encode()
    assert tail.startswith(new_obj)
    assert ("/Size %d" % (top + 2)).encode() in tail
    assert ("/Prev %s" % prev).encode() in tail
    xref_pos = int(re.findall(rb"startxref\s+(\d+)\s+%%EOF", marked)[-1])
    xref = marked[xref_pos:]
    assert xref.startswith(b"xref\n%d 1\n" % (top + 1))
    offset = int(xref.split(b"\n")[2][:10])
    assert marked[offset:].startswith(new_obj)


def test_second_watermark_wins_and_old_copy_unchanged(method, sample_pdf):
    first = method.add_watermark(sample_pdf, secret="first", key=KEY)
    second = method.add_watermark(first, secret="second", key=KEY)
    assert method.read_secret(first, KEY) == "first"
    assert method.read_secret(second, KEY) == "second"
    assert second.startswith(first)


def test_pdf_without_objects_or_startxref(method):
    base = b"%PDF-1.4\n"
    marked = method.add_watermark(base, secret=SECRET, key=KEY)
    tail = marked[len(base):]
    assert tail.startswith(b"1 0 obj")
    assert b"/Size 2" in tail
    assert b"/Prev" not in tail
    assert method.read_secret(marked, KEY) == SECRET


def test_is_watermark_applicable(method, sample_pdf, tmp_path):
    assert method.is_watermark_applicable(sample_pdf) is True
    assert method.is_watermark_applicable(tmp_path / "missing.pdf") is False
