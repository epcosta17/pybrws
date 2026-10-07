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

---

## 2026-10-06 — HTTP/1.1

Added because bot.incolumitas.com, a purpose-built bot detection test site,
offers only http/1.1 over ALPN. A client that speaks solely HTTP/2 cannot
reach it, while Firefox falls back. `pybrws.client.get()` now dispatches on
the negotiated ALPN, so both paths are covered.

Result: `https://bot.incolumitas.com/` returns 200, HTTP/1.1, 44650 bytes
after gzip decoding.

**Header order and capitalisation differ from HTTP/2**, which is why the
profile carries a separate list rather than reusing the h2 one with different
casing. From the plaintext capture: `Connection: keep-alive` sits between
`Accept-Encoding` and `Upgrade-Insecure-Requests`, and there is no `te` header.

**Open: the tail of H1_HEADERS is unconfirmed.** The capture it came from was
truncated at 400 characters, so everything from `Sec-Fetch-Site` onward is a
guess, including whether `Priority` is sent at all over HTTP/1.1. Re-capture
with tools/catch_hello.py and a plaintext navigation before trusting it.

**Bug found and fixed:** the chunked terminator. After the zero-length chunk
come optional trailer fields and a single CRLF, not a double one. Waiting for
four bytes where two arrive hangs until the socket times out. Caught because
the real server used chunked encoding and the unit tests had not covered it
yet; there are now four chunked tests, including trailers and chunk
extensions.

**peet.ws failures were transient.** Requests timed out and
`tools/verify.py` failed; httpx failed against the same host while the TLS
handshake still succeeded. That ruled out a regression in this client, and
the conclusion drawn from it, that the address was being throttled, went
further than the evidence supported. Retested minutes later: both clients get
200, and the browser never stopped working. Cause unknown and not pursued.

---

## 2026-10-06 — The HTTP/1.1 reference was captured wrong

Firefox 157 over cleartext to `http://pybrws.127.0.0.1.nip.io:4443`:

    GET / HTTP/1.1
    Host: pybrws.127.0.0.1.nip.io:4443
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.9
    Accept-Encoding: gzip, deflate
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Priority: u=0, i

Three guesses in the profile were wrong, and the two interesting ones are not
about HTTP/1.1 at all:

- `Accept-Encoding` is `gzip, deflate`, without `br` or `zstd`. Firefox offers
  those two only over TLS.
- There are **no `Sec-Fetch-*` headers**. Fetch metadata goes only to
  trustworthy origins, and a hostname resolving to 127.0.0.1 is not one.
- `Priority: u=0, i` is sent, and here it directly follows
  `Upgrade-Insecure-Requests`.

So a cleartext capture cannot serve as the reference for an HTTPS client. Over
TLS the header list should regain `br, zstd` and the `Sec-Fetch-*` block, and
their position relative to `Priority` is still unknown.

`tools/catch_hello.py` cannot produce the right capture by construction: it
reads raw bytes and never completes a handshake, so an HTTPS request stays
encrypted. Added `tools/catch_request.py`, which serves a generated
self-signed certificate and dumps the decrypted request. ALPN is selectable,
so it can force HTTP/1.1 or capture the HTTP/2 preamble.

Two things the smoke test caught before a browser was ever involved: on
Windows a client that closes without close_notify raises `ConnectionResetError`
rather than returning empty, and a client that closes immediately after
sending can have its request discarded by the RST. The first needed a fix in
the tool; the second was an artifact of the test, since a browser holds the
connection open waiting for a response.

**H1_HEADERS stays unconfirmed** until a capture over TLS exists.

---

## 2026-10-06 — HTTP/1.1 reference, captured over TLS

Firefox 157 navigation to `https://pybrws.127.0.0.1.nip.io:4443`, decrypted by
tools/catch_request.py. Two speculative connections failed with
bad_certificate before the warning page appeared; the third carried the
request.

    GET / HTTP/1.1
    Host: pybrws.127.0.0.1.nip.io:4443
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.9
    Accept-Encoding: gzip, deflate, br, zstd
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: none
    Sec-Fetch-User: ?1
    Priority: u=0, i

`br, zstd` and the Sec-Fetch block are both back, which confirms the earlier
reading: their absence was a property of the cleartext origin, not of
HTTP/1.1. The header order guessed from the truncated capture turned out to
be right, and `Priority` does sit last, after the Sec-Fetch block.

The relationship to HTTP/2 is clean: the same sequence, plus `Host` at the
front and `Connection` after `Accept-Encoding`, minus `te`.

`build_request()` now reproduces the capture byte for byte, 462 bytes, and a
test asserts it. A second test asserts the fixture contains `br, zstd` and a
Sec-Fetch header, so that replacing it with a cleartext capture fails loudly
rather than silently degrading the profile.

---

## 2026-10-06 — Phases 5 and 6: CLI and proxy

**Redirects.** `client.get` takes `follow_redirects`, and the CLI exposes it
as `-L`. This changes an earlier result: glassdoor.com was recorded as
returning 308 rather than a block, and following the chain reaches 200 with
684 KB of real page. The earlier table understated the outcome.

One fidelity gap worth recording: a real browser changes `Sec-Fetch-Site`
from `none` to `same-origin` or `cross-site` when following a redirect, and
this client keeps sending the navigation header set unchanged.

**The proxy terminates TLS; it does not tunnel.** A plain CONNECT tunnel is
useless here, because the caller performs its own handshake through it and
presents its own fingerprint, which is the thing being replaced. So the proxy
has to sit inside the encryption, which costs a certificate authority the
caller must trust. That tradeoff is the whole design, and it is why
`HTTPS_PROXY` alone is not enough: the CA has to be trusted too.

**Measured, same endpoint, three callers:**

| Caller | JA4 | Akamai fingerprint |
|---|---|---|
| httpx direct | t13d1712h1_ab0a1bf427ad_8e6e362c5eac | 1:4096;2:0;4:65535;5:16384;3:100;6:65536\|16777216\|0\|m,a,s,p |
| node direct | t13d5212h1_b262b3658495_8e6e362c5eac | 2:0;4:262144\|458753\|0\|a,m,p,s |
| curl direct | t13d2013h1_2b729b4bf6f3_e24568c0d440 | - |
| **any of them, proxied** | **t13d1517h2_8daaf6152771_3cbfd9057e0d** | **1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s** |
| Firefox 157 | t13d1517h2_8daaf6152771_3cbfd9057e0d | 1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s |

No caller was modified. Only an environment variable and a trusted CA.

**Two certificate problems, both found by running it:**

- OpenSSL 4 rejects a leaf without an Authority Key Identifier matching the
  issuer's Subject Key Identifier: `certificate verify failed: Missing
  Authority Key Identifier`. Both extensions are now issued, and a stored CA
  lacking the subject key id is regenerated rather than reused, since every
  leaf it signs would fail.
- `curl --cacert` fails with exit 60 on this machine. That curl is built
  against Schannel, which consults the Windows certificate store and ignores
  the flag. `-k` works, or the CA goes in the Windows store.

**Known limits of the proxy:** GET only, one request per tunnel, HTTP/1.1
toward the caller. The fingerprinted hop is the outbound one, so the inner
protocol does not matter, but it does mean the caller cannot exercise
HTTP/2-specific behaviour through it.

---

## 2026-10-06 — A finding that did not replicate

While following a redirect on glassdoor.com.mx, `/index.htm` fetched directly
returned 200 while the same URL reached through the redirect returned 403.
The suspected cause was the known fidelity gap: this client keeps sending
`Sec-Fetch-Site: none` on the second hop, which claims the user typed the URL
even though a request to the same host just preceded it.

Four header combinations, three interleaved rounds:

| Case | Rounds | |
|---|---|---|
| A  site=none, no referer | 200, 403, 403 | unstable |
| B  site=same-origin, no referer | 403, 403, 403 | blocked |
| C  site=same-origin, + referer | 200, 200, 200 | served |
| D  site=none, + referer | 403, 403, 200 | unstable |

B against C looked decisive: identical requests differing in one header, one
deterministically blocked and the other deterministically served. The obvious
reading was a consistency check, with `Sec-Fetch-Site: same-origin` and a
missing `Referer` forming a combination no browser produces.

**Five more interleaved rounds dissolved it.**

    B  same-origin, no referer : 403, 200, 200, 403, 403
    C  same-origin, + referer  : 403, 403, 200, 403, 403

No signal. The site scores requests rather than deciding, the score for this
address has been degrading all session, and n=3 was noise shaped like a
result. Had the first run been written up, it would have been a confident,
well-argued, wrong blog post.

**The headline result was re-checked with the same discipline** and survives.
Four interleaved rounds per host, crunchbase.com added as a negative control
so that "pybrws always gets 200" would show up:

| Host | pybrws | httpx |
|---|---|---|
| www.zillow.com | 200, 200, 200, 200 | 403, 403, 403, 403 |
| www.ticketmaster.com | 200, 200, 200, 200 | 403, 403, 403, 403 |
| www.crunchbase.com | 200, 200, 200, 200 | 200, 200, 200, 200 |

glassdoor has been removed from the README table. It is no longer a usable
instrument from this address.

**What measuring this properly would need:** a deterministic target rather
than a scored one, a fresh address per sample so reputation cannot drift, a
control case inside every round, and enough rounds that a three-sample streak
cannot pass for a result.

**And the code change this started from was never justified.** Firefox may
well keep `Sec-Fetch-Site: none` through a redirect on a user-typed
navigation, since the request's initiator origin does not change. Whether it
does is measurable: teach tools/catch_request.py to answer the first request
with a 308 and capture the second. Until that capture exists, the current
behaviour stays.

---

## 2026-10-06 — A harness, after the third anecdote

"It works now, oddly right after curl errored." Measured instead, five
interleaved rounds against glassdoor.com:

    pybrws : 403, 308, 403, 403, 403
    httpx  : 403, 403, 403, 403, 403

A roughly one-in-five pass rate makes an occasional success expected without
any cause, so curl had nothing to do with it. But the comparison is not empty
either: this client sometimes passes where the plain one never does. The
protection scores rather than decides, the fingerprint moves the score, and
this address's reputation has been dragging it down all session.

That is three separate occasions now where a single observation suggested
something that measurement did not support. Built `tools/ab_test.py`:
interleaved rounds, pass rates rather than verdicts, a control host forced
into every run, and every sample appended to a JSONL log with timestamps so a
change next week reads as a change.

**The harness had the same bug as the anecdotes.** Its first version counted
any non-403 as served, so glassdoor scored 3/3 while actually returning a 308
that led to a block one hop later. Both clients now follow redirects, because
the question is whether the page arrives. The reading changed from
"pybrws passes" to "1/3, flapping", which is the truth.

    host                pybrws                 httpx         reading
    www.crunchbase.com  3/3 served             3/3 served    control
    www.etsy.com        0/3 served             0/3 served    no difference
    www.glassdoor.com   1/3 served flapping    0/3 served    better, not deterministic
    www.zillow.com      3/3 served             0/3 served    passes, baseline blocked

**CLI default changed.** `-L` is now on, with `--no-location` to opt out. curl
requires the flag; a browser always follows and never shows a 308. This tool
imitates a browser, so following is the coherent default. The library keeps
`follow_redirects=0`, where an explicit caller should decide.

---

## 2026-10-06 — etsy, a query string, and a flow control bug

Reported: `https://www.etsy.com/?dd_referrer=` is served where `/` is blocked.
`dd_referrer` is a DataDome parameter and etsy runs DataDome, so the obvious
reading was that the parameter means something to the protection.

Five arms, five interleaved rounds, zero variance anywhere:

| Arm | Result |
|---|---|
| `/` pybrws | 0/5 served |
| `/?dd_referrer=` pybrws | 5/5 served |
| `/?nonsense=` pybrws | 5/5 served |
| `/?nonsense=` httpx | 0/5 served |
| `/c/jewelry` httpx | 0/5 served |

The report is right about the effect and wrong about the cause. **Any query
string works**, not `dd_referrer` specifically, so the rule is attached to the
bare `/` path rather than to the parameter. The httpx arm matters just as
much in the other direction: with the same query string it is still blocked
5/5, so the query string is not a bypass anyone can use. Both the fingerprint
and the path are necessary.

A plausible reading is that the most-scraped URL on the site carries the
strictest rule, and a query string produces a different cache key or rule
match. That is a guess, and it is not tested.

**The fifth arm found a defect in this client.** `/c/jewelry` timed out 5/5
for pybrws while httpx got a clean 403, so the failure was ours. Cause: the
HTTP/2 reader replenished only the connection window, never the stream
window. The profile advertises `INITIAL_WINDOW_SIZE = 131072`, so any response
whose **compressed** size passes that stalls forever.

It had been invisible because every success so far was small on the wire.
zillow's 433 KB is the figure after brotli; compressed it fits the window.
etsy's category page does not.

Fixed by sending WINDOW_UPDATE on both the connection and the stream, and not
on a stream already closed by END_STREAM. `/c/jewelry` now returns 200 with
roughly 990 KB in 2.1 seconds, three for three, and also passes where httpx is
blocked. Three tests cover it, driving the reader from scripted frames.

The initial WINDOW_UPDATE is the only one in the Akamai fingerprint, so this
does not change it. The *pattern* of later updates is still a signal, and
Firefox batches them rather than answering every DATA frame. Not measured.

---

## 2026-10-06 — Outbound proxies

HTTP CONNECT and SOCKS5, with optional credentials, threaded through
`handshake.connect`, `client.get`, the CLI as `-x`, and the sidecar as
`--upstream` so a Ruby caller can reach a residential exit without knowing
either exists.

The design claim was that nothing above the socket changes. Verified against
tls.peet.ws through pass-through proxies running on loopback:

    direct            ja4=t13d1517h2_8daaf6152771_3cbfd9057e0d  akamai=1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
    via HTTP CONNECT  ja4=t13d1517h2_8daaf6152771_3cbfd9057e0d  akamai=1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
    via SOCKS5        ja4=t13d1517h2_8daaf6152771_3cbfd9057e0d  akamai=1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s

**What does change is below the socket.** The TCP/IP signature a server sees
becomes the proxy's. `tools/verify.py` checks `tcpip.p0f` against a Firefox
capture taken from this machine, so that single check is expected to fail
through a proxy while the other seventeen keep passing. That is the honest
behaviour: the fingerprint this project controls stops at the socket.

**SOCKS5 sends the target as a name**, never an address, so the exit resolves
it. Resolving locally would leak every target to this machine's resolver and
would also break any proxy whose value is where it resolves from. A test
asserts the request carries `example.test` rather than an address.

Sixteen tests, all offline: fake proxies on loopback that record what this
client sends and replay scripted answers. One of them asserts that data sent
immediately after a SOCKS5 reply is still readable, which only holds if the
variable-length bound address was consumed exactly.

---

## 2026-10-06 — Re-measuring the results table, and two corrections

The README table had gone stale: it predated redirect following and the
HTTP/2 flow control fix, so indeed was recorded as "302 redirect" and etsy as
a flat 403. Regenerated from `tools/ab_test.py`, four interleaved rounds,
both clients following redirects, crunchbase as control. indeed is 4/4 served.

**Correction: it is not "any query string".** The earlier entry concluded
that etsy's rule was attached to the bare `/` path because `?dd_referrer=`
and `?nonsense=` both passed. Measuring more parameters:

| URL | Served |
|---|---|
| `/` | 0/4 |
| `/?q=` | 0/4 |
| `/?q=ring` | 0/4 |
| `/?nonsense=` | 4/4 |
| `/?dd_referrer=` | 4/4 |
| `/c/jewelry` | 4/4 |

`q` is etsy's search parameter. The protected endpoints are the homepage and
search, the two most worth scraping; an ordinary category page is served. The
earlier conclusion came from testing two parameters that both happened to be
inert and generalising from them.

**Free proxies, measured rather than argued.** 2753 addresses from two public
SOCKS5 lists, 14 sampled:

    2/14 usable
    37.27.112.71:9050   exit 80.67.167.81   ja4 t13d1517h2_8daaf6152771_3cbfd9057e0d
    199.58.185.9:4145   exit 199.58.185.9   ja4 t13d7310_613d769af9d7_4837e640254d

The second is not this client's fingerprint. That proxy terminated the TLS
and re-originated it with its own stack: a transparent MITM, able to read
everything that passed through it. **Half of the working free proxies
silently destroyed the thing this project exists to produce**, and did so
undetected because certificate verification is off.

That caveat has been in the README since phase 3 as a laboratory decision.
This is what it costs, measured. Verifying certificates would have caught it
immediately, which moves it up the list from "nice for production" to "the
defence against the proxies you do not control".

Free proxy lists are unusable for measurement for a second reason anyway:
their addresses are already burned, so a run through them measures the
proxy's reputation rather than this client's fingerprint.

---

## 2026-10-06 — Crossing fingerprint against address

A BrightData static ISP exit, verified first for interception: the JA4 and
Akamai fingerprint it reports are this client's, so the proxy is not
inspecting.

Routing the pybrws arm of `ab_test.py` through it dropped every previously
passing target to 0/4: zillow, ticketmaster, indeed and the etsy category
page. The run also exposed a claim in the tool, written earlier in this
session, that proxying one arm "isolates the fingerprint and not the
address". It does the opposite. Changing the exit changes both variables at
once, so nothing in that output can be attributed to either. The tool now
prints a warning saying so.

The experiment that does isolate them crosses both factors, three rounds each:

| Target | pybrws direct | pybrws proxied | httpx direct | httpx proxied |
|---|---|---|---|---|
| www.zillow.com | 3/3 | 0/3 | 0/3 | 0/3 |
| www.crunchbase.com | 3/3 | 3/3 | 2/3 | 3/3 |
| www.glassdoor.com | 0/3 | 0/3 | 0/3 | 0/3 |
| www.g2.com | 0/3 | 0/3 | 0/3 | 0/3 |
| www.etsy.com | 0/3 | 0/3 | 0/3 | 0/3 |

zillow is the only discriminating row and it is unambiguous. **One cell out
of four passes.** The fingerprint alone does not do it, and the address alone
does not either; both are required, which is an interaction rather than two
additive effects.

**The commercial exit was worse than a domestic line.** Not what was expected
when it was bought for this. A static ISP range belonging to a known proxy
vendor is itself a signal, and anti-bot vendors buy those ranges and label
them. "Clean IP" means unburned by *you*, not untainted.

**This reframes the project's own results.** Every number in the README comes
from one residential connection. The protocol work is real and measurable,
and it buys one of the two things a request needs. Stated plainly in the
README rather than left as a footnote.

glassdoor is now 0/3 from both addresses, so it is finished as an instrument
rather than merely degraded here.

`tools/isolate.py` keeps the crossed design available, since the single-arm
comparison is the easier thing to reach for and the wrong one.

---

## 2026-10-06 — Cookies and sessions

`CookieJar` follows RFC 6265: default path from the request, domain widening
only to a suffix of the response host, Max-Age beating Expires, Secure
withheld from insecure requests, and the send order longest-path-first then
oldest-first. A replacement keeps the original creation time, or an update
would silently reorder the header.

`Session` holds the jar, a connection pool keyed by host, port and proxy, and
the per-request defaults. Verified live: two requests to zillow, cookies
collected and the second served off the pooled connection.

**Connection reuse needed a retry path.** The second request to peet.ws over
a pooled connection died with GOAWAY, code 0: the server closes after one
response and the pool handed out a corpse. Retrying is correct here and the
retry list did not include the HTTP-level errors, only the socket ones. Now
it covers `Http1Error` and `Http2Error` too, guarded on the connection having
been reused, so the same failure on a fresh connection still propagates
rather than being retried into a loop.

Reuse is not only about speed. A browser carries many requests over one
connection; a client that performs a fresh handshake for every request has a
rhythm of its own no matter how right the bytes are.

**The Cookie header's slot is unmeasured and marked as such.** It currently
goes before `upgrade-insecure-requests`, which is a guess. Verified through
peet.ws that the placement works and changes neither the JA4 nor the Akamai
fingerprint, but that only shows the mechanism, not the position.

`tools/catch_request.py --set-cookie` now answers the first request with two
Set-Cookie headers and a self-reloading page, then captures the reload, which
carries the Cookie header. That is the only way to learn the slot from the
browser itself.

Building it turned up a real bug in the tool: the reply was being sent after
the `with tls:` block had already closed the socket, so `sendall` raised and
was swallowed by a bare `except OSError: pass`. The capture still looked like
it worked, because the second request arrived from a client that had been
told the cookie by hand. Against a browser it would have hung forever with no
error. The reply now happens inside the block, and the server waits for the
peer to hang up before moving on.

Also unmeasured: whether Firefox splits several cookies into separate
`cookie` headers over HTTP/2. HPACK makes that worthwhile and the single
header emitted here would not reproduce it.

---

## 2026-10-06 — A fake README example turns up two real bugs

The session example in the README used `example.com/login`, which does not
exist. Looking for a real endpoint that sets and echoes cookies broke the
client twice:

**`httpbingo.org`: `Encoder exceeded max allowable table size`.** The profile
advertises `HEADER_TABLE_SIZE = 65536` in SETTINGS, which is Firefox's value
and tells the peer how large a dynamic table our decoder will accept. The
`hpack` decoder was left at its 4096 default, so a server that took the
advertisement at its word broke us. Copying a browser's SETTINGS values
without honouring them is its own kind of inconsistency: the numbers were
right for the fingerprint and wrong for the implementation.

Fixed in both directions. The decoder now accepts what the profile
advertises, and the peer's own `HEADER_TABLE_SIZE` is applied to our encoder,
which was never read before.

**`httpbin.org`: `server did not select TLS 1.3`.** That server negotiates
TLS 1.2. The ClientHello offers both versions because Firefox does, and
dropping 1.2 would change the fingerprint, so the honest position is that
this client advertises a version it cannot speak and fails when a server
takes it up. Recorded in the README as a limitation rather than papered over.

The example now uses httpbingo.org and is runnable: set a cookie, fetch it
back over the same connection, and the response echoes it.

---

## 2026-10-06 — The cookie capture caught a favicon

Asked for the navigation reload carrying a cookie, got this instead:

    GET /favicon.ico HTTP/1.1
    Host: pybrws.127.0.0.1.nip.io:4443
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
    Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
    Accept-Language: en-US,en;q=0.9
    Accept-Encoding: gzip, deflate, br, zstd
    Connection: keep-alive
    Referer: https://pybrws.127.0.0.1.nip.io:4443/
    Cookie: pybrws_probe=1; pybrws_second=2
    Sec-Fetch-Dest: image
    Sec-Fetch-Mode: no-cors
    Sec-Fetch-Site: same-origin
    Priority: u=6

A browser fetches the favicon the moment a page loads, and that request beat
the reload to the listener. The tool now answers subresources with a 404 and
keeps waiting, recognising them by `Sec-Fetch-Dest`; `--any-request` turns
that off.

**What it settles.** Two cookies arrive in one `Cookie` header, so there is
no crumbling over HTTP/1.1. The header sits after `Connection` and before the
`Sec-Fetch` block, which both profile anchors already matched.

**What it leaves open.** A subresource carries no
`Upgrade-Insecure-Requests`, and that header occupies the same gap between
`Connection` and `Sec-Fetch-Dest`. So the relative order of Cookie and
Upgrade-Insecure-Requests on a navigation is still unknown. The uncertainty
is now one pair rather than the whole slot.

**What it gave for free.** A measured header set for an image subresource,
which is one of the four request types the project was missing. Against a
navigation it differs in `Accept`, all three `Sec-Fetch` values and
`Priority: u=6` rather than `u=0, i`, and it carries a `Referer` that a
typed-URL navigation does not. Stored as `H1_IMAGE_HEADERS` and as its own
fixture.

The `Referer` and `Sec-Fetch-Site: same-origin` pairing is the combination
guessed at during the glassdoor experiment, here observed rather than
assumed. That experiment found no effect; this says nothing about effect,
only that the pairing is what the browser actually sends.

---

## 2026-10-06 — The cookie slot, settled

The navigation reload, captured once the tool stopped letting the favicon
take its place:

    Connection: keep-alive
    Cookie: pybrws_probe=1; pybrws_second=2
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document

**Cookie precedes Upgrade-Insecure-Requests.** That was the last open pair,
and the guessed anchor turns out to have been right. Generating the request
through a Session with those two cookies now reproduces the capture byte for
byte, all 503, and a test holds it there.

The HTTP/2 anchor stays inferred rather than measured. The two orders are the
same sequence apart from Host, Connection and te, which is good reason to
believe it, and capturing it would need an HTTP/2 server that
tools/catch_request.py is not.

Worth noting in the capture: `Sec-Fetch-Site: none` and no `Referer`, even
though the page had been loaded a moment earlier. A reload is still a
user-initiated navigation with no initiator origin, so the pairing holds in
the other direction too: the subresource had both, this has neither.

Three header sets are now measured rather than assumed: navigation,
navigation with cookies, and an image subresource.

---

## 2026-10-06 — The same trick, two sites, opposite meanings

Reported: g2.com serves a request with a random query string, the way etsy
does. The reading offered was that this is another target the client beats.

Five interleaved rounds, the same parameter on both sites:

| | pybrws | httpx |
|---|---|---|
| `g2.com/?x=` | 5/5 served | **5/5 served** |
| `etsy.com/?x=` | 5/5 served | 0/5 served |

Zero variance in any arm. The observation was right and the reading was not.
On g2 the query string opens the door to everybody, this client included but
not because of it. On etsy the same parameter is not enough on its own, and
the fingerprint is what decides.

Without the httpx column both rows look identical, and adding g2 to the demo
would have shown a green row earned by nothing. The baseline arm is the only
thing that separates them, which is the third time in this session it has
changed a conclusion.

Also measured: `g2.com/products/slack/reviews` refuses both clients, so the
rule is not simply "a path other than the homepage".

Added to the demo as its own section rather than dropped, since the pair is a
better argument for running a control than any explanation of one.

---

## 2026-10-06 — Widening the sweep

Scanned 24 public homepages with both clients, then re-measured the promising
ones over three interleaved rounds. Seven more targets discriminate, all of
them 3/3 for this client and 0/3 for httpx with no variance in any cell:

| Target | Protection |
|---|---|
| www.yelp.com | DataDome |
| www.homedepot.com | Akamai |
| www.macys.com | Akamai |
| www.sephora.com | Akamai |
| www.stubhub.com | CloudFront |
| www.quora.com | Cloudflare |
| seatgeek.com | not disclosed |

Akamai is new: until now every result came from Cloudflare, DataDome or
CloudFront, and a vendor named in the job posting had no evidence behind it.

**Candidates rejected from the first pass**, which is where the scan earned
its keep. `redfin.com` answered 405 Method Not Allowed, which the `served`
helper counted as a pass because it only tests for 403, 429 and 503; a 405 is
not a served page. `expedia`, `vrbo` and `wayfair` had httpx at 429 rather
than 403, which is rate limiting and not a judgement about the client, so the
contrast could be an artefact of the scan's own traffic. `bestbuy` had httpx
failing with a protocol error, the same GOAWAY class seen earlier and not a
block either. None of those are evidence and none were kept.

The sweep in the demo now carries a protection column, so the spread across
vendors is visible rather than asserted.

---

## 2026-10-06 — Protection is per endpoint, not per site

Asked why the homepages fail. Four of the passing targets are homepages, so
they do not: zillow, yelp, homedepot and quora all serve `/`. Only etsy and
g2 refuse theirs, and for unrelated reasons.

**etsy refuses exactly two endpoints**, two rounds each:

| Path | |
|---|---|
| `/` | blocked |
| `/search?q=ring` | blocked |
| `/?x=` | served |
| `/c/jewelry` | served |
| `/c/jewelry?x=` | served |
| `/market/handmade_gifts` | served |
| `/featured/gifts-for-her` | served |

The homepage and search, which are the two most worth scraping and the two
most expensive to serve. The rest of the catalogue is open. This also
replaces the reading from two entries ago that the rule was "the bare path":
`/search?q=ring` has a path and is refused, `/market/handmade_gifts` has one
and is not.

**g2 is the opposite shape.** It refuses `/`, `/categories/crm`,
`/products/slack/reviews`, with or without a query, and serves only `/?x=`,
which it also serves to httpx. So g2 blocks this client nearly everywhere and
the one gap is not earned. Why that one URL slips through is not observable
from outside and is not worth guessing at.

**The operational point:** choosing the URL matters as much as the
fingerprint. `etsy.com/` returns 1.7 KB of refusal and `etsy.com/c/jewelry`
returns 985 KB of catalogue, same client, same second, same domain. Testing
only the homepage would have concluded that etsy blocks us while most of the
site was open. That is why `tools/ab_test.py` takes full URLs rather than
hosts.

**A measurement bug worth recording:** the throwaway probe flagged g2's
served homepage as a challenge page. The marker list includes "enable
javascript", which appears somewhere in almost any 493 KB page. Content
heuristics need to be anchored to the small refusal pages they are meant to
catch, not matched anywhere in a document.

---

## 2026-10-06 — A cookie earned here cannot be spent elsewhere

The session experiment, replicated over four interleaved rounds against
`etsy.com/`, reached after `/c/jewelry`. No variance in any arm:

| Arm | |
|---|---|
| pybrws, cold | 0/4 served |
| pybrws, cookies only, fresh connection | 4/4 |
| pybrws, warm, reused connection | 4/4 |
| httpx, cold | 0/4 |
| **httpx, handed the cookies pybrws earned** | **0/4** |

Three things, in order of how much they change.

**Cookies unlock the refused endpoint.** Eight of them arrive from the
category page, and the homepage that refuses a cold request serves a request
carrying them.

**It is the cookies, not the connection.** The arm that drops the pool
between the two requests and opens a fresh one does exactly as well as the
arm that reuses it, so connection reuse contributes nothing here. That arm
exists only because a session changes both at once and a result that mixed
them would have been unreadable.

**The cookies are not transferable.** The same values, sent by a client whose
fingerprint differs, are refused every time. The token is bound to whoever
earned it.

That last one rules out the cheapest architecture in this field: a browser
collects a clearance cookie and anything at all spends it. It does not work
against this protection. What remains does work, but the client spending the
token has to carry the fingerprint too, which is the thing this project
builds.

g2 was in the same run and refuses all three pybrws arms, consistent with
every other measurement of it.

Also fixed while here: `verdict()` lived in the sweep cell, so section 6
could not run without section 3. Helpers now live in the setup cell and every
section stands alone, which matters for a notebook presented live.

---

## 2026-10-06 — Methods, bodies and header merging

What a scraper written against `curl_cffi` needs before this can replace it:
other methods, request bodies, and headers that merge rather than replace.

**Header merging is the one with teeth.** Passing `headers=` used to replace
the profile's whole list, so a caller adding one header silently discarded
the fingerprint. `headers.merge` now keeps the profile order, replaces a
header in place where the name already exists, appends a genuinely new one,
and treats `None` as a removal. Verified against httpbingo: a value added, a
value replaced in situ, one dropped, and the rest of the profile intact.

`tools/verify.py` still passes 18 of 18 after all of it, which was the point
of checking.

**Two bugs, both mine, both found by running it.**

An uppercase header name is a protocol error over HTTP/2: RFC 7540 section
8.1.2 requires lowercase field names, and a caller passing `X-Demo` earned a
GOAWAY. Names are now lowered in the HTTP/2 header block only, since casing
*is* the fingerprint over HTTP/1.1 and simply has no expression here.

Worse, the flow control path span forever on any body over 65535 bytes.
`_await_window` defers frames that are not window updates so the response
reader can have them, and `_next_frame` prefers the deferred queue, so the
first deferral was handed straight back to the code that deferred it. A busy
loop with no error and no timeout, since nothing ever blocked. Split into
`_next_frame`, which prefers deferrals, and `_frame_from_wire`, which never
does. A 200 KB body now posts in half a second and 500 KB works; 1 MB returns
400, and httpx gets the same 400, so that is httpbingo's limit and not ours.

**Unmeasured and marked:** the slot a browser gives `Content-Length`, and the
header set Firefox sends with a POST, which differs from a navigation in
`Content-Type`, `Origin` and the `Sec-Fetch-*` values. Both need a capture
that `tools/catch_request.py` can take.

---

## 2026-10-07 — The POST is only half impersonating

Asked whether a POST impersonates Firefox too. Measured what this client
actually sends:

    Content-Type: application/json
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Priority: u=0, i
    (no Origin)

The TLS handshake and the HTTP/2 connection are unaffected by the method, so
those two layers are still Firefox exactly. The header set is not. It is the
navigation set with `Content-Type` and `Content-Length` appended, and that
combination is one no browser produces: a navigation POST comes from a form
and carries form encoding, never JSON; a JSON POST comes from `fetch` and
sends `Sec-Fetch-Dest: empty`, `Sec-Fetch-Mode: cors`, an `Origin` and a
`Referer`, and never `Sec-Fetch-User`, which means the user activated the
request.

The missing `Origin` is the loudest of them. A browser sends it on every
non-GET request.

So the project reproduced, in its own code, the cross-layer inconsistency it
exists to study: two layers right and the third a combination that cannot
occur. Writing the earlier entry as "unmeasured" understated it; it is wrong,
not absent.

`tools/catch_request.py --post form` and `--post fetch` now answer the first
request with a page that submits a form or calls `fetch`, then capture the
POST that follows. Two captures, because the two are different header sets.
Smoke tested end to end against a scripted client; the browser captures are
still to take.

---

## 2026-10-07 — Two POST header sets, measured

Both captures taken. They differ in more than `Content-Type`, which is why
one set would not have done:

| | form | fetch |
|---|---|---|
| `Accept` | `text/html,...` | `*/*` |
| `Referer` | after `Connection` | before `Content-Type` |
| `Upgrade-Insecure-Requests` | present | absent |
| `Sec-Fetch-Dest` / `Mode` | `document` / `navigate` | `empty` / `cors` |
| `Priority` | `u=0, i` | `u=4` |

`Content-Length` always follows `Content-Type` and precedes `Origin`, which
settles the slot marked unknown an entry ago. Both carry `Origin`, whose
absence was the loudest thing wrong with the old behaviour.

The moving `Referer` is the one worth noting: nothing about the two requests
suggests the header should change position, and no amount of reasoning would
have produced it.

`client.post` now sends the fetch set by default, since that is what an API
client is, with `kind="form"` for the other. Verified against peet.ws that
the wire order matches the captures and that the Akamai fingerprint is
unchanged either way. Both sets reproduce their capture byte for byte and a
test holds it.

**One observation, and an explanation that was asserted rather than tested.**
Neither POST carries `Sec-Fetch-User`, while both navigation captures do.
That much is measured. The claim that the cause is the scripted submit, since
Fetch Metadata sends the header only for a user-activated navigation, is a
hypothesis: Firefox may simply never send it on a form POST, which fits the
same evidence. Asserting the mechanism was the same move that produced the
retracted glassdoor reading, on a smaller scale.

`tools/catch_request.py --post form-click` now serves a page with a button
and waits, so the two can be told apart. Until that capture exists the
profile comment says observed, not explained.

The HTTP/2 variants are derived from the HTTP/1.1 ones by the rule the
navigation captures confirmed: drop Host and Connection, lowercase, append
`te`. Marked inferred, with a test asserting the derivation rather than the
result.

---

## 2026-10-07 — The click settles it

Captured with `--post form-click`:

    Sec-Fetch-Site: same-origin
    Sec-Fetch-User: ?1
    Priority: u=0, i

A form submitted by a click carries `Sec-Fetch-User: ?1`, in the same slot it
occupies in a navigation. One submitted by script does not. Every other byte
is identical, so the hypothesis from the previous entry was right, and is now
measured instead of argued.

That makes a form POST two header sets rather than one, and the right one
depends on what is being imitated. `kind="form"` sends the clicked set, since
a client filling in a login is standing in for a person pressing a button;
`kind="form-script"` is there for a page submitting on their behalf. Three
sets in total with `xhr`, all three verified on the wire against peet.ws with
the Akamai fingerprint unchanged.

Worth noting what the question was worth. The original note asserted a
mechanism from a single absence, and challenging it cost one capture and
turned a guess into a measurement **and** found a second header set that
would otherwise have been missing. The same challenge applied to the
glassdoor reading deleted it instead. Both outcomes are the point.

A wart fixed on the way: the capture tool was answering the favicon request
with the page that triggers the POST, which is harmless here only because
the favicon does not run scripts. Subresources now get a 404.

---

## 2026-10-07 — A header set deleted in silence

Taking inventory of what the profile still lacks turned up that
`H1_IMAGE_HEADERS` was gone. The text slice two entries ago, the one written
to remove an outdated comment, had taken two constants sitting between its
markers: `H1_COOKIE_BEFORE` and the image set.

The cookie constant was caught within minutes, because a test used it. The
image set had **no test**, so it vanished into a commit with a green suite
and nobody noticed until an unrelated inventory listed the profile's
attributes and one was missing.

Restored from history, and given the test it never had, which asserts it
reproduces its capture byte for byte like every other set.

Two things worth keeping from this. Editing source by slicing text between
markers is a bad habit that has now cost twice in one session; both times the
replacement was correct and the collateral was not. And a measured constant
without a test is a measurement that can be deleted without the suite
objecting, which makes it no better than a guess that happens to be right.
