# Offensive reconnaissance — 2026-10-16

**Group 18 · SOFTSEC VT 2026 · Phase II**
**Authorization:** section 4.4 of the project instructions — *"As part of the offensive
operations in this project, you are expected to focus on two main objectives:
(i) stealing flags …"* — and section 4.1.2, which makes *"Capture other groups'
flags and defend yours"* a group responsibility for Phase II.

**Outcome in one line: no flag was captured, and no target executed our payload.**

---

## 1. What we tested, and why this vector

The base Tatou repository ships with several planted vulnerabilities. Our Phase I
audit catalogued 22 of them; finding **V-01** is a command injection in the
`bash-bridge-eof` watermarking method:

```python
cmd = "cat " + str(pdf.resolve()) + " &&  printf \"" + secret + "\""
res = subprocess.run(cmd, shell=True, check=True, capture_output=True)
```

`secret` comes straight from the JSON body of `/api/create-watermark` and is
concatenated into a shell command without escaping. Closing the `printf` quote
lets the caller append arbitrary commands, and `res.stdout` — the command's
output — is then written out as the "watermarked" file, which the caller can
download through the version link. That makes it a route to any file readable by
the server process, including flag 1 at `/app/flag`.

We chose it because it is the shortest path from an anonymous caller to code
execution: one account, one document, one request. **We fixed this vulnerability
in our own repository during Phase I** (commit `2359295`), so the same reasoning
that lets us test others also protects us.

## 2. Method

Per target, five steps — all of them ordinary API use:

| # | Call | Purpose |
|---|---|---|
| 1 | `POST /api/create-user` | the endpoint is public; one account of our own |
| 2 | `POST /api/login` | obtain a bearer token |
| 3 | `POST /api/upload-document` | upload a small PDF **we** generated |
| 4 | `GET /api/get-watermarking-methods` | **is `bash-bridge-eof` still registered?** If not, the target has been fixed and we stop |
| 5 | `POST /api/create-watermark/<id>` | send the injection as `secret` |

Payload:

```
"; (echo RCE_PROOF_$((7*191)); id; pwd; ls -l /app; cat /app/flag; env | grep -i flag); #
```

The server-side command becomes:

```
cat <pdf> &&  printf ""; (echo RCE_PROOF_$((7*191)); ...); #"
```

Two details were needed to make the test meaningful, and both were found by
running it rather than by reasoning:

- **The payload has to exit 0.** `subprocess.run(..., check=True)` turns any
  non-zero exit into an HTTP 500, which hides the result. Every command in the
  payload therefore ends in `|| echo` fallbacks and a final `true`.
- **The upload has to be a real PDF.** `add_watermark` calls `load_pdf_bytes`
  *before* it builds the command, so a hand-written PDF is rejected before the
  injection point is ever reached. The script embeds a PyMuPDF-generated
  815-byte PDF instead.

The success marker is deliberately something the payload cannot contain: the
request carries the literal text `$((7*191))`, so `RCE_PROOF_1337` can only
appear in the response if a shell actually evaluated the arithmetic.

## 3. Tooling

`probe-flag1.py` — standard library only, so it runs on the VM unchanged. It is
written from our own audit: the injection, the parameter names and the vulnerable
command's shape all come from the code we analysed in Phase I, not from a
third-party tool. Section 4.4 requires that any tool used be *"written or clearly
understood"*.

## 4. Results

Fourteen reachable instances were probed.

| Result | Count | Meaning |
|---|---|---|
| `bash-bridge-eof` no longer registered | **6** | vulnerability removed — fully remediated |
| method registered, secret returned **verbatim** | **2** | injection neutralised (the secret is quoted or passed as an argument); the method is still exposed but not exploitable this way |
| method registered, error at the watermarking step | **3** | undetermined — the request failed before the outcome could be judged |
| failed before the method check (login rejected) | **2** | — |
| host unreachable | **1** | — |
| **flag captured** | **0** | — |

Full per-target output is in `flag-probe2.json`; the script is `probe-flag1.py`.

## 5. What this tells us

1. **The remediation worked, widely.** Six of fourteen instances had removed the
   method outright, and two more had neutralised the injection while leaving the
   method registered. The planted RCE is not a soft target any more, which is
   exactly what the course intends: everybody is expected to have fixed it in
   Phase I.
2. **Leaving a dangerous method registered is the more interesting failure.**
   The two instances that still expose `bash-bridge-eof` are safe *today*
   because the secret is quoted — but they are one refactor away from being
   unsafe again, and the method has no legitimate use. Removing it is the
   control; escaping it is a mitigation.
3. **A negative result is a result.** We now know that this vector is closed on
   the network, which is worth recording: a later group reading this journal does
   not have to repeat the work.

## 6. Rules of engagement

Section 4.4 forbids destructive or disruptive actions. This operation respected
that:

- **Nothing was deleted, modified or overwritten on any target.**
- The only state created was one account and one document **of our own**, per
  target — the minimum needed to exercise the endpoint, and the same thing any
  ordinary user of the platform does.
- No denial of service, no flooding, no repeated retries.
- No third-party tooling.

## 7. Reproduce

```bash
# on the VM
python3 probe-flag1.py --targets 02 04 06 08 10 12 14 16 20 22 24 30 32 34 \
    --out flag-probe2.json --verbose
```

Expect: `0 flag(s) recovered | 0 target(s) with code execution | 14 probed`.
