"""Tests for the `pdfwm` command-line interface.

This module is not part of the service - nothing in the API imports it - so a
coverage run that only exercises the routes reports it at 0 %, which reads as
"untested code" rather than "code with a different role". It is installed into
the image as a console script (`pdfwm = watermarking_cli:main`), so it is worth
a handful of tests that exercise the commands a person would actually type.

The error contract is worth pinning down because it is what makes the tool safe
to call from a script: `main` never raises, it returns

    2  file not found, or a value the command cannot use
    3  no secret found in the file
    4  the key is wrong
    5  the watermarking method refused the input
"""
import json

import pymupdf

import watermarking_cli as cli
import watermarking_utils as WMUtils


def _pdf(path, text="Group 18 - confidential"):
    """A real single-page PDF, so the methods have a page to work on."""
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    path.write_bytes(doc.tobytes())
    doc.close()
    return path


# ------------------------------------------------------------------- methods

def test_methods_lists_every_registered_method(capsys):
    assert cli.main(["methods"]) == 0
    printed = capsys.readouterr().out.split()
    assert printed == sorted(WMUtils.METHODS)
    assert "toy-eof" in printed and "rmc" in printed


# -------------------------------------------------------------------- embed

def test_embed_writes_a_watermarked_pdf(tmp_path, capsys):
    src = _pdf(tmp_path / "in.pdf")
    out = tmp_path / "out.pdf"

    assert cli.main(["embed", str(src), str(out), "--secret", "s3cret", "--key", "k"]) == 0

    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF")
    assert "Wrote watermarked PDF" in capsys.readouterr().out


def test_embed_reads_the_secret_from_a_file(tmp_path, capsys):
    src = _pdf(tmp_path / "in.pdf")
    out = tmp_path / "out.pdf"
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("from-a-file\n", encoding="utf-8")

    assert cli.main(
        ["embed", str(src), str(out), "--secret-file", str(secret_file), "--key", "k"]
    ) == 0
    capsys.readouterr()          # drop the embed output before reading stdout again

    # read it back to prove the file was parsed rather than passed verbatim
    assert cli.main(["extract", str(out), "--key", "k"]) == 0
    assert capsys.readouterr().out.strip() == "from-a-file"


# ------------------------------------------------------------------ extract

def test_embed_then_extract_round_trip(tmp_path, capsys):
    src = _pdf(tmp_path / "in.pdf")
    out = tmp_path / "out.pdf"

    assert cli.main(["embed", str(src), str(out), "--secret", "s3cret", "--key", "k"]) == 0
    capsys.readouterr()

    assert cli.main(["extract", str(out), "--key", "k"]) == 0
    assert capsys.readouterr().out.strip() == "s3cret"


def test_extract_writes_the_secret_to_a_file(tmp_path, capsys):
    src = _pdf(tmp_path / "in.pdf")
    out = tmp_path / "out.pdf"
    cli.main(["embed", str(src), str(out), "--secret", "s3cret", "--key", "k"])
    capsys.readouterr()

    dest = tmp_path / "secret.out"
    assert cli.main(["extract", str(out), "--key", "k", "--out", str(dest)]) == 0

    assert dest.read_text(encoding="utf-8") == "s3cret"
    assert "Wrote secret" in capsys.readouterr().out


def test_extract_does_not_crash_when_there_is_no_mark(tmp_path, capsys):
    """A clean PDF has no secret.

    The tool may report that (exit 3) or print an empty value (exit 0); what it
    must not do is raise, because a wrapper script cannot catch a traceback.
    """
    plain = _pdf(tmp_path / "plain.pdf")
    code = cli.main(["extract", str(plain), "--key", "k"])
    assert code in (0, 3)
    assert "Traceback" not in capsys.readouterr().err


# ------------------------------------------------------------------ explore

def test_explore_writes_a_json_tree(tmp_path):
    src = _pdf(tmp_path / "in.pdf")
    tree_file = tmp_path / "tree.json"

    assert cli.main(["explore", str(src), "--out", str(tree_file)]) == 0

    data = json.loads(tree_file.read_text(encoding="utf-8"))
    assert data, "the node tree should not be empty"


def test_explore_writes_to_stdout_without_out(tmp_path, capsys):
    src = _pdf(tmp_path / "in.pdf")

    assert cli.main(["explore", str(src)]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data


# -------------------------------------------------------------- error paths

def test_missing_input_file_returns_2(tmp_path, capsys):
    code = cli.main(["explore", str(tmp_path / "does-not-exist.pdf")])
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()
