"""Does fitz.open(stream=..., filetype=X) behave like filetype="pdf"?  (survivors add_watermark 24/26/27/28, _collect 4/6/7/8)"""
import fitz

doc = fitz.open(); doc.new_page().insert_text((72, 72), "Hello Tatou")
good = doc.tobytes(); doc.close()
inputs = {"valid pdf": good, "valid pdf + trailing bytes": good + b"\nTRAILER", "garbage bytes": b"not a pdf at all", "empty bytes": b""}
variants = {"'pdf' (original)": {"filetype": "pdf"}, "None": {"filetype": None}, "omitted": {}, "'PDF'": {"filetype": "PDF"}, "'XXpdfXX'": {"filetype": "XXpdfXX"}}

def run(data, kw):
    try:
        d = fitz.open(stream=data, **kw)
        r = ("opened", d.page_count, d.get_page_text(0).strip() if d.page_count else "", d.is_pdf)
        d.close(); return r
    except Exception as e:
        return ("raised", type(e).__name__, str(e)[:60])

print("PyMuPDF", fitz.VersionBind)
for iname, data in inputs.items():
    ref = run(data, variants["'pdf' (original)"])
    print(f"\ninput: {iname}")
    for vname, kw in variants.items():
        r = run(data, kw)
        print(f"  {vname:18} {'SAME as pdf' if r == ref else 'DIFFERS':12} {r}")
