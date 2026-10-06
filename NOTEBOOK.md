# Lab notebook

One entry per session: hypothesis, what was run, result, conclusion.

---

## 2026-10-06 — Project setup

**Hypothesis:** the ClientHello can be parsed and re-emitted byte for byte
without implementing any cryptography.

**Done:** project scaffold, data model, hex I/O, capture tool, failing tests
defining the parser and differ APIs.

**Next:** implement `parser.parse_client_hello`.

**Open questions:**
- Does this Firefox build send GREASE?
- Is Firefox's ClientHello stable across connections, or does any part vary?
- With post-quantum disabled, how large is it, and does it fit in one segment?

---

## 2026-10-06 — Phase 0 complete

**Done:** `parse_client_hello` and `diff`. 20/20 tests pass.

**Design decisions, and why:**
- The parser accepts both a full TLS record and a bare handshake message. Both
  shapes turn up: `tools/catch_hello.py` yields a record, Wireshark's
  "copy as hex stream" on the handshake layer yields a bare message.
- The differ compares `session_id` by length only. In TLS 1.3 compatibility
  mode it holds 32 random bytes, so its content is noise.
- `session_ticket`, `pre_shared_key` and `key_share` are compared by payload
  length only: they carry per-connection material.
- GREASE extension types collapse to a single identity. The value is drawn at
  random per connection, so comparing it literally would report a difference
  on every run. Presence or absence of GREASE is still reported.

**Verified beyond the unit tests:** swapped ciphers, missing extension, extra
extension, reordering with an identical set, payload mismatch, two different
GREASE values (0 differences, correct), GREASE present vs absent (reported).

**Next:** phase 1, capture real Firefox. Still unanswered: is Firefox's
ClientHello stable across connections?

---

## 2026-10-06 — Phase 1, first real capture

Firefox 157.0 on Windows, default settings, against
`https://pybrws.127.0.0.1.nip.io:4443`. 1901 bytes, one record, no trailing
bytes. The parser handled it unchanged.

**Firefox sends no GREASE.** Neither in the cipher list (15 suites) nor among
the 17 extension types. The GREASE normalisation in the differ is therefore
inert for this target; it stays for Chrome comparisons.

**Extension order as sent:**

    0 server_name, 23 extended_master_secret, 65281 renegotiation_info,
    10 supported_groups, 11 ec_point_formats, 35 session_ticket, 16 alpn,
    5 status_request, 34 delegated_credentials,
    18 signed_certificate_timestamp, 51 key_share, 43 supported_versions,
    13 signature_algorithms, 45 psk_key_exchange_modes, 28 record_size_limit,
    27 compress_certificate, 65037 encrypted_client_hello

`delegated_credentials` and `record_size_limit` are present,
`application_settings` is absent: NSS, not BoringSSL.

**key_share carries three offers**, 1327 bytes total:

    X25519MLKEM768   1216
    x25519             32
    secp256r1          65

`supported_groups` lists X25519MLKEM768, x25519, secp256r1, secp384r1,
secp521r1. ALPN is `h2, http/1.1`.

**ECH is greased.** No HTTPS DNS record exists for the target, so the 282-byte
`encrypted_client_hello` is a decoy Firefox sends by default. Hypothesis: its
payload is random per connection and must join `VOLATILE_EXTENSIONS`, or every
comparison between two Firefox captures reports 282 bytes of noise. Unconfirmed
until repeated captures exist.

**SNI measured:** capturing against the bare IP produced 1869 bytes and no
`server_name`; against the nip.io hostname, 1901 bytes with a 28-byte payload.
The 32-byte delta is the extension plus its header, exactly as predicted.

**Next:** five consecutive captures, then diff them. Expected to vary: `random`,
`session_id`, `key_share` payload, `encrypted_client_hello` payload. Anything
else, especially extension order, changes what "correct" means.

---

## 2026-10-06 — Five captures: what varies

Five consecutive captures, same conditions. All 1901 bytes.

**Extension order is identical across all five.** Firefox does not shuffle it,
unlike Chrome. The target is a fixed sequence, which makes byte-identity a
well-defined goal.

Cipher list identical. Every extension payload constant except two:

| Field | Behaviour |
|---|---|
| `random` | varies, 32B |
| `session_id` | varies, 32B |
| `key_share` | payload varies, length stable at 1327B |
| `encrypted_client_hello` | payload varies, length stable at 282B |

The ECH hypothesis holds, so 65037 joins `VOLATILE_EXTENSIONS`. With that, the
differ reports zero differences between any two captures of the same browser,
which is the property the emitter will be tested against.

**Inside the greased ECH**, decoded across the five captures:

| Field | Value |
|---|---|
| type | 0 (outer), constant |
| kdf_id | HKDF-SHA256, constant |
| aead_id | **varies**: AES-128-GCM or ChaCha20-Poly1305 |
| config_id | **varies**: 0x2a, 0x87, 0x94, 0xc4, 0x6f |
| enc | 32 bytes, constant length |
| payload | 240 bytes, constant length |

So the earlier conclusion needs refining: Firefox sends no RFC 8701 GREASE in
the cipher list or extension list, but it does grease ECH, and that decoy has
randomised fields inside it.

This matters for the emitter. Hardcoding one `aead_id` and one `config_id`
produces a client that is individually correct but distinguishable over many
connections, since a real Firefox varies both. Same failure mode as emitting a
fixed GREASE value.

**Next:** phase 2, the emitter.

---

## 2026-10-06 — Phase 2, emitter

`build_client_hello()` produces 1901 bytes that the differ finds identical to
the reference capture.

**Verified byte-for-byte, not just structurally.** The emitter takes an `rng`
callable. Feeding it the capture's own per-connection material in consumption
order — `random`, `session_id`, the three key shares, the ECH aead selector,
config_id, enc and payload — reproduces the reference file exactly, all 1901
bytes, with the script fully consumed and nothing left over. The leftover check
matters: it proves the emitter reads exactly as much randomness as Firefox
spends, in the same places.

Bronze follows from silver: identical bytes imply an identical JA4.

**Design notes:**
- `wire.py` holds the primitive encoders so the profile and the emitter can
  both use them without a circular import.
- A profile is a Python module, not a data file. Four of the seventeen
  extensions need generation logic rather than constants, which a JSON schema
  could only express by inventing a mini-language.
- Every length is computed, none are hardcoded. Changing the hostname shifts
  the total by exactly the delta, which is asserted.
- `aead_id` is drawn per connection. A test builds 64 hellos and asserts both
  values appear, so a future refactor cannot silently freeze it.

**Next:** phase 3. The ClientHello is now correct but inert; nothing has been
sent to a real server yet.

---

## 2026-10-06 — Phase 3, key exchange

First contact with real servers. Six hosts, ClientHello sent over plain TCP,
ServerHello parsed by hand.

**Finding 1: a malformed key share is fatal, and only to the servers that
matter.** With random bytes in place of real keys, `tls.peet.ws` and
`github.com` completed fine while `www.cloudflare.com` and `example.com`
returned `decode_error` and `www.google.com` returned `illegal_parameter`. The
split is not arbitrary: the first two selected x25519, where any 32 bytes is a
valid input, and the rest tried to use the post-quantum share.

**Finding 2: post-quantum is mandatory for this fingerprint.** Dropping the
X25519MLKEM768 entry from `key_share` while leaving the group in
`supported_groups` made Cloudflare, Google and example.com answer with a
HelloRetryRequest demanding 0x11ec. Removing it from `supported_groups` too
would change the fingerprint, so there is no way to impersonate Firefox 157
without implementing ML-KEM-768.

**Finding 3: byte order in the hybrid share, measured not looked up.** Sending
`ML-KEM || X25519` produced a ServerHello; `X25519 || ML-KEM` produced
`decode_error` from Cloudflare and `illegal_parameter` from Google. The server
share is 1120 bytes: 1088 of ML-KEM ciphertext plus 32 of X25519.

**Finding 4: no new dependency.** `cryptography` 50.0.2 on OpenSSL 4.0.3
exposes `MLKEM768PrivateKey` with `generate`, `public_bytes_raw` and
`decapsulate`.

**Live result**, with real keys for all three groups:

| Host | Selected group | Shared secret |
|---|---|---|
| www.cloudflare.com | X25519MLKEM768 | 64 B |
| www.google.com | X25519MLKEM768 | 64 B |
| example.com | X25519MLKEM768 | 64 B |
| www.amazon.com | X25519MLKEM768 | 64 B |
| tls.peet.ws | x25519 | 32 B |
| github.com | x25519 | 32 B |

The concatenation order of the two shared secrets is assumed to match the
order of the public keys. That is unverified: nothing checks it until the
server's Finished verifies against our transcript.

**Next:** record layer, then the key schedule.

---

## 2026-10-06 — Phase 3 complete: full handshake

`connect()` completes a TLS 1.3 handshake against tls.peet.ws, github.com,
www.cloudflare.com, www.google.com, example.com and www.amazon.com. All
negotiate TLS_AES_128_GCM_SHA256 and ALPN h2.

**The server Finished verifies.** That single check validates the whole chain
at once: transcript handling, HKDF-Expand-Label, the three-stage key schedule,
the AEAD nonce construction, and the open assumption from the previous entry
that the hybrid shared secret concatenates ML-KEM first. If any of those were
wrong the HMAC would not match.

**Compressed certificates.** Cloudflare and example.com send handshake message
0x19, CompressedCertificate from RFC 8879, because the profile advertises
`compress_certificate` with zlib, brotli and zstd. RFC 8879 puts the compressed
message into the transcript as sent, so with certificate verification out of
scope it needs no decompression, only acceptance. Decompression becomes
necessary the day certificates are verified.

**First end-to-end result.** A hand-rolled minimal HTTP/2 GET to
`tls.peet.ws/api/all`, using literal HPACK with no Huffman coding, returned:

    ja3_hash       9d42e90b0225e779f03141ddcd699df2
    ja4            t13d1517h2_8daaf6152771_3cbfd9057e0d
    peetprint_hash a4bbbc7e3adf3db97d276fd0adb1efc4
    http_version   h2
    akamai fp      |00|0|m,p,s,a

The JA4 decodes as TCP, TLS 1.3, SNI present, 15 ciphers, 17 extensions, ALPN
h2 — the Firefox ClientHello, as intended.

The Akamai fingerprint is the opposite. `|00|0|m,p,s,a` means an empty SETTINGS
frame, no WINDOW_UPDATE and no PRIORITY frames. Firefox sends specific SETTINGS
values, an initial WINDOW_UPDATE and a set of PRIORITY frames. So the TLS layer
now says Firefox while the HTTP/2 layer says hand-written client, which is
worse than not disguising at all: no real browser produces that combination.
Phase 4 exists to fix exactly this, and the measurement is the proof it was
needed.

**To get the target**, open `https://tls.peet.ws/api/all` in Firefox and record
the `akamai_fingerprint` and header order it reports.

**Not yet measured:** whether any of this defeats bot detection. Nothing here
has been tested against a protected endpoint.

---

## 2026-10-06 — Phase 4: HTTP/2, and the gold bar

Reference captured by opening tls.peet.ws/api/all in Firefox 157. Target:

    1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s

Four things the capture revealed that guessing would have missed:

- **Pseudo-header order is `m,p,a,s`**, not `m,p,s,a`. Authority precedes
  scheme. The throwaway client from the previous entry had it wrong.
- **The first stream id is 3, not 1.**
- **Priority travels in the HEADERS frame**, with flag 0x20, weight 42,
  depends_on 0, exclusive 0. Firefox sends no standalone PRIORITY frames,
  which is why that section of the Akamai fingerprint is empty. Expecting
  separate frames there would have been the obvious wrong guess.
- **The wire carries weight minus one** (RFC 7540). peet.ws reports 42, so the
  byte is 41.

Result: `akamai_fingerprint` and its hash both match, and the HEADERS frame is
**286 bytes, the same as Firefox's**. That last number was not a target, it
fell out of letting `hpack` encode with Huffman. It is the strongest available
evidence that the HPACK layer is also faithful, since the Akamai fingerprint
says nothing about header block size.

`tools/verify.py` now automates the comparison, **18 of 18 checks pass**:
ja3, ja3_hash, ja4, ja4_r, peetprint, peetprint_hash, both TLS versions, the
Akamai fingerprint and its hash, stream id, HEADERS length, flags, priority,
the full ordered header list, http_version, user_agent, and the TCP/IP p0f
signature.

**The p0f match is borrowed, not earned.** It comes from the Windows TCP stack
this runs on, which happens to be the same stack the reference browser used.
Move this into a Linux container and that check fails while every other one
still passes. Worth keeping in the output precisely because it will break.

**Still not measured:** whether any of this defeats bot detection. Every check
here is a protocol fingerprint reported by a cooperating endpoint. Nothing has
been tested against a protected site, and no JavaScript challenge is solvable
by this client by construction.

**Known gaps:** HTTP/3 is never attempted, though Cloudflare, Google and
example.com all advertise `alpn=h3,h2` in their HTTPS DNS records, so a real
Firefox may reach them over QUIC first. Sessions are never resumed. The header
set is the one Firefox sends for a top-level navigation; an XHR or a subresource
request sends different `accept` and `sec-fetch-*` values.

---

## 2026-10-06 — Testing against bot detection

**First attempt used the wrong instruments.** Four targets, pybrws and httpx
side by side:

| Target | pybrws | httpx |
|---|---|---|
| scrapingcourse.com/antibot-challenge | 403 challenge | 403 challenge |
| scrapingcourse.com/cloudflare-challenge | 403 challenge | 403 challenge |
| nowsecure.nl | 200 | 200 |
| cloudflare.com/cdn-cgi/trace | 200 | 200 |

Identical in all four, so the experiment measured nothing. Two targets issue a
JavaScript challenge to every visitor including real browsers, which no HTTP
client can clear by construction. The other two serve everyone. Neither is
sensitive to protocol fingerprint, which is the variable under test. An
experiment needs a target where a plain client is blocked and a browser is not.

**Finding such targets.** Scanning ten sites with httpx produced six that
return 403 to a plain client: g2, zillow, indeed, glassdoor, ticketmaster and
etsy, the last behind DataDome rather than Cloudflare. Those discriminate.

**Result**, one GET each, repeated twice with byte-identical responses:

| Host | Protection | httpx | pybrws |
|---|---|---|---|
| www.zillow.com | CloudFront | 403, 5776 B | 200, 433736 B |
| www.ticketmaster.com | - | 403, 20 B | 200, 562285 B |
| www.indeed.com | Cloudflare | 403, 25741 B | 302, 71 B |
| www.glassdoor.com | Cloudflare | 403, 9 B | 308, 10 B |
| www.g2.com | Cloudflare | 403, 1704 B | 403, 1707 B |
| www.etsy.com | DataDome | 403, 776 B | 403, 779 B |
| www.crunchbase.com | Cloudflare | 200 | 200 |

The two 200s carry genuine page titles, so they are real pages rather than
block pages served with a 200. The two redirects replace a block page with
ordinary routing, which is also a change in how the client is classified.

Four of six discriminating targets stop blocking. The protocol fingerprint is
doing measurable work.

**What this does not show.** One client IP, so address reputation is
uncontrolled; the same test from a datacentre range would likely read
differently. Two sites still block, and nothing here isolates why. g2 runs
Cloudflare at a stricter setting and etsy runs DataDome, and both plausibly
want JavaScript-derived signals that no HTTP client can produce.

**An aside, and a useful control.** tls.browserleaks.com, tools.scrapfly.io and
www.howsmyssl.com all terminate HTTP/2 with GOAWAY and error code 0 before
responding. They negotiate h2 over ALPN, and the same hosts answer over
HTTP/1.1. Installing httpx and reproducing the identical GOAWAY established
that this is not a defect in this client. Without that control the obvious
move would have been to spend hours debugging working code.

**Gap this exposed:** bot.incolumitas.com, a purpose-built bot detection test
site, serves HTTP/1.1 only, and this client speaks HTTP/2 exclusively. A real
Firefox falls back. That is a fingerprint-visible difference and a reason to
implement HTTP/1.1.
