# Survivor-by-survivor mutation analysis

**Target:** `server/src/redundant_multi_channel.py`  
**Tool:** mutmut 3.8.0  
**Recorded campaign:** 258 mutants; 227 killed; 31 survived; 0 no-tests; mutation score 88.0%; 28 focused tests passed.

A survivor means the test suite did not kill that mutant; survival alone does not prove equivalence. Classifications below are based on the recorded diffs and the existing code/test descriptions. PDF-opening variants remain unresolved pending a direct check with the installed PyMuPDF version.

## Evidence from the existing test suite

Relevant tests in `server/test/test_redundant_multi_channel.py` include `test_text_layer_alone_is_enough`, `test_metadata_alone_is_enough`, `test_unparseable_pdf_falls_back_to_trailer`, `test_zero_page_pdf_falls_back_to_trailer`, `test_watermark_is_invisible`, `test_encode_is_compact_json`, `test_decode_error_messages`, `test_mac_binds_the_secret`, `test_wrong_key_is_rejected`, `test_read_secret_validation_and_not_found`, and `test_collect_returns_unique_payloads`.

## `add_watermark` — 8 survivors

| Mutant | Mutation | Analysis and evidence | Disposition |
|---|---|---|---|
| `add_watermark__mutmut_24` | `filetype="pdf"` → `filetype=None` | Delegates format detection to PyMuPDF. Ordinary PDFs may behave identically, but unusual-input behavior is not proven by survival alone. | **Unresolved** |
| `add_watermark__mutmut_26` | Removes `filetype="pdf"` | Also relies on format autodetection; text/metadata embedding depends on successful parsing. | **Unresolved** |
| `add_watermark__mutmut_27` | `filetype="pdf"` → `filetype="XXpdfXX"` | The invalid hint may cause parsing to fail and leave only the trailer channel, or may be handled differently by the installed library. Needs runtime verification. | **Unresolved** |
| `add_watermark__mutmut_28` | `filetype="pdf"` → `filetype="PDF"` | Likely equivalent if this PyMuPDF version accepts uppercase format hints identically, but not proven by the diff. | **Unresolved** |
| `add_watermark__mutmut_45` | `fitz.Point(2, 2)` → `fitz.Point(3, 2)` | Shifts invisible text one point horizontally. Existing invisibility and text-layer recovery tests cover the relevant intended properties; exact coordinates are not part of the stated contract. | **Acceptable behavior change** |
| `add_watermark__mutmut_46` | `fitz.Point(2, 2)` → `fitz.Point(2, 3)` | Shifts invisible text one point vertically; same rationale as mutant 45. | **Acceptable behavior change** |
| `add_watermark__mutmut_47` | `fontsize=1` → `fontsize=2` | Changes text size while retaining `render_mode=3`; intended properties are invisibility and recoverability, not a specific font size. | **Acceptable behavior change** |
| `add_watermark__mutmut_75` | `.encode("ascii")` → `.encode("ASCII")` | Python codec names are case-insensitive, so the token bytes are unchanged. | **Equivalent** |

## `read_secret` — 5 survivors

| Mutant | Mutation | Analysis and evidence | Disposition |
|---|---|---|---|
| `read_secret__mutmut_17` | `last_error: Exception \| None = None` → `last_error: Exception \| None = ""` | No candidates cause an earlier raise; if a candidate fails, the loop assigns the caught exception before the final fallback. Initial value does not affect ordinary reachable paths. | **Equivalent on reachable normal paths** |
| `read_secret__mutmut_24` | Fallback message → `None` | The fallback is not reached on ordinary paths: no candidates raise earlier, failed candidates set `last_error`, and successful candidates return. | **Equivalent on reachable normal paths** |
| `read_secret__mutmut_25` | Adds `XX` around fallback message | Same effectively unreachable fallback as mutant 24. | **Equivalent on reachable normal paths** |
| `read_secret__mutmut_26` | Lowercases fallback message | Same effectively unreachable fallback as mutant 24. | **Equivalent on reachable normal paths** |
| `read_secret__mutmut_27` | Uppercases fallback message | Same effectively unreachable fallback as mutant 24. | **Equivalent on reachable normal paths** |

## `_collect` — 8 survivors

| Mutant | Mutation | Analysis and evidence | Disposition |
|---|---|---|---|
| `_collect__mutmut_4` | `filetype="pdf"` → `filetype=None` | Uses format autodetection. Text-layer extraction depends on parsing; the raw-byte scan is a separate recovery path. | **Unresolved** |
| `_collect__mutmut_6` | Removes `filetype="pdf"` | Relies on PyMuPDF format recognition; successful parsing is needed for text and metadata extraction. | **Unresolved** |
| `_collect__mutmut_7` | `filetype="pdf"` → `filetype="XXpdfXX"` | If parsing fails, raw scanning remains, but cannot necessarily recover a mark that exists only in the PDF text layer. Check the installed library's behavior. | **Unresolved** |
| `_collect__mutmut_8` | `filetype="pdf"` → `filetype="PDF"` | Likely harmless if uppercase format hints are accepted identically; this is not established by survival alone. | **Unresolved** |
| `_collect__mutmut_24` | `decode("latin-1", "replace")` → `decode("latin-1")` | Latin-1 maps every byte value, so decoding does not require a replacement handler. | **Equivalent** |
| `_collect__mutmut_26` | `"latin-1"` → `"LATIN-1"` | Codec names are case-insensitive. | **Equivalent** |
| `_collect__mutmut_27` | Error handler `"replace"` → `"XXreplaceXX"` | The handler would be consulted only on decoding errors; Latin-1 decoding has no invalid byte sequences. | **Equivalent** |
| `_collect__mutmut_28` | Error handler `"replace"` → `"REPLACE"` | Same reasoning: Latin-1 decoding never needs the error handler. | **Equivalent** |

## `_encode` — 7 survivors

| Mutant | Mutation | Analysis and evidence | Disposition |
|---|---|---|---|
| `_encode__mutmut_4` | `secret.encode("utf-8")` → `secret.encode("UTF-8")` | Codec names are case-insensitive; secret bytes are unchanged. | **Equivalent** |
| `_encode__mutmut_24` | Base64 secret `.decode("ascii")` → `.decode("ASCII")` | Same ASCII decoding; base64 output is ASCII. | **Equivalent** |
| `_encode__mutmut_29` | `ensure_ascii=True` → `ensure_ascii=None` | `None` is falsey; however all current payload values are ASCII (fixed labels, hexadecimal MAC, base64 secret, integer version), so the JSON text remains the same for this schema. | **Equivalent for current payload schema** |
| `_encode__mutmut_32` | Removes `ensure_ascii=True` | `json.dumps` defaults to `ensure_ascii=True`; omission preserves the default. | **Equivalent** |
| `_encode__mutmut_35` | `ensure_ascii=True` → `ensure_ascii=False` | All values in the current payload schema are ASCII, so this option does not change its serialized text. | **Equivalent for current payload schema** |
| `_encode__mutmut_37` | JSON `.encode("utf-8")` → `.encode("UTF-8")` | Codec names are case-insensitive. | **Equivalent** |
| `_encode__mutmut_41` | Base64url `.decode("ascii")` → `.decode("ASCII")` | Base64url encoding produces ASCII bytes; decoding is unchanged. | **Equivalent** |

## `_decode` — 2 survivors

| Mutant | Mutation | Analysis and evidence | Disposition |
|---|---|---|---|
| `_decode__mutmut_44` | Secret field `.encode("ascii")` → `.encode("ASCII")` | Same encoded bytes; base64 decoding is unchanged. | **Equivalent** |
| `_decode__mutmut_64` | `secret_bytes.decode("utf-8")` → `secret_bytes.decode("UTF-8")` | Codec names are case-insensitive; decoded text is unchanged. | **Equivalent** |

## `_mac_hex` — 1 survivor

| Mutant | Mutation | Analysis and evidence | Disposition |
|---|---|---|---|
| `_mac_hex__mutmut_9` | `key.encode("utf-8")` → `key.encode("UTF-8")` | Same UTF-8 key bytes, so HMAC input and digest are unchanged. | **Equivalent** |

## Summary

| Disposition | Count | Interpretation |
|---|---:|---|
| Equivalent | 20 | Codec-name changes, Latin-1 error-handler changes, current-schema JSON options, and unreachable fallback initialization/message changes. |
| Acceptable behavior change | 3 | Two insertion-coordinate changes and one invisible font-size change; exact values are not part of the stated contract. |
| Unresolved | 8 | PDF opening/file-type variants need direct verification against the installed PyMuPDF runtime. |
| Missing test | 0 confirmed | No survivor has yet been shown to violate a concrete requirement solely because a needed test is absent. |
| **Total** | **31** | All survivors in the recorded final campaign are accounted for. |

## Conclusion

The recorded mutation score is **88.0% (227/258 killed)**. Most survivors are codec/serialization equivalents or small watermark-placement parameter changes. Keep the eight PDF-opening/file-type variants explicitly **unresolved** until checked in the recorded runtime; do not claim they are proven equivalent merely because they survived. This score and analysis do not establish that the implementation is defect-free.
