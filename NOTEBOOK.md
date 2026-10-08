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

---

## 2026-10-07 — HTTP/2 measured, and a cookie bug it found

Three captures with the new HTTP/2 server. Two confirmed what was inferred
and one did not.

**Navigation**: the field list matches `H2_NAVIGATION_HEADERS` exactly.

**POST over fetch**: matches the derived set field for field, so the rule
used to produce the HTTP/2 variants from the HTTP/1.1 ones, drop Host and
Connection, lowercase, append `te`, holds.

**Cookies**: it does not.

    referer: https://pybrws.127.0.0.1.nip.io:4443/
    cookie: pybrws_probe=1
    cookie: pybrws_second=2
    upgrade-insecure-requests: 1

**Firefox sends one `cookie` field per cookie over HTTP/2.** This client sent
one joined header, as HTTP/1.1 requires, and has done on every HTTP/2 request
it ever made with more than one cookie. The question had been marked
unmeasured since the cookie work went in, which was honest but did not stop
the wrong behaviour shipping. Marking a gap is not the same as having one.

HPACK is why: each `cookie` field can be indexed on its own, so a repeated
one costs a byte on later requests while a joined header changes whenever any
cookie does.

The anchor was right. Cookies sit before `upgrade-insecure-requests` in both
protocols, which the inference had already got from the HTTP/1.1 order.

Fixed, with the two protocols now deliberately different: joined for
HTTP/1.1, crumbled for HTTP/2, each asserted against its own capture.
Verified on the wire against peet.ws with the Akamai fingerprint unchanged.

One header in the cookie capture belongs to nothing in the profile:
`cache-control: max-age=0`, which Firefox adds on a reload. The capture was a
meta-refresh, so that request is a reload and not a navigation. Not modelled,
and worth knowing before someone reads the fixture as a plain navigation.

Nothing in the profile is inferred any more.

---

## 2026-10-07 — Certificates are verified now

On by default, with `verify=False` and the CLI's `-k` to opt out. Three
pieces: RFC 8879 decompression, which until now was accepted and ignored;
chain validation; and the CertificateVerify signature, which is the part
that proves the peer holds the key rather than merely owning a copy of
someone else's chain.

Path validation goes to `cryptography.x509.verification`. Writing it by hand
would mean reimplementing name constraints and policy handling, which is the
category of code that is wrong in ways nobody notices until it matters.

**Checked in both directions, because "it did not break anything" is not
evidence that a check works.** Six live hosts verify. A well-formed leaf from
a local CA the system does not trust is rejected with "candidates exhausted",
and the same leaf with that CA explicitly trusted is accepted. A hostname
mismatch is rejected. A tampered transcript fails the signature.

`rsa_pkcs1` is refused rather than accepted: TLS 1.3 forbids it for
CertificateVerify, and quietly allowing it would hide a server doing the
wrong thing.

One rough edge worth recording. The first rejection test used the capture
tool's self-signed certificate and failed with "invalid extension" rather
than anything about trust, which would have passed as a success while
proving nothing about untrusted issuers. Re-running against a well-formed
leaf from an untrusted CA produced the right reason. A test that passes for
the wrong reason is worse than one that fails.

Also: the Windows trust store holds at least one certificate `cryptography`
declines to parse. Skipping it is right; failing the whole store over it is
not, so the loader now drops unparseable anchors instead.

This closes the caveat that has been in the README since phase 3, and the
incident that justified it: a free proxy terminated and re-originated the
TLS, replacing the fingerprint, and nothing noticed.

---

## 2026-10-07 — HelloRetryRequest

A server that wants a group the ClientHello advertised but sent no share for
answers with a HelloRetryRequest instead of failing. Cloudflare, Google and
example.com all did exactly that earlier in the project, when the
post-quantum share was removed to see what happened; until now the client
raised.

Two parts of it are easy to get subtly wrong.

**The second ClientHello must be identical to the first except for the
key_share.** Re-emitting it from the profile would change the random, the
session id and the greased ECH, which is three differences too many. So it
is rebuilt from the original bytes: parse, swap one extension, re-serialise.
A test asserts every other field and every other extension payload is
untouched.

**The transcript is rewritten, not appended to.** RFC 8446 section 4.4.1
replaces the first ClientHello with a synthetic `message_hash` message
carrying only its hash:

    0xFE || 00 00 <hash length> || Hash(ClientHello1)

Getting this wrong does not fail at the point of the mistake. It fails much
later, when the server's Finished does not verify, with nothing pointing
back at the cause.

Which is also why the live test is worth more than it looks: provoking a
real retry from Cloudflare, Google, example.com and peet.ws and completing
all four means the rewrite is right, because the Finished check would
otherwise reject it.

**Two guards.** A retry naming a group that was already offered is refused
rather than answered, since answering sends the same thing again and invites
a loop. A second retry in one handshake is refused, which RFC 8446 forbids.

The curve list needed widening on the way: the profile advertises secp384r1
and secp521r1, and `KeyExchange` could not produce either, so a retry asking
for one would have failed on our side. A test now asserts every advertised
group can be produced, since advertising what cannot be delivered is the
same class of fault as the HPACK table size.

**Unmeasured:** where a browser places the cookie extension in the second
ClientHello. Ours goes last, which is legal. No capture covers it.

---

## 2026-10-07 — Session resumption

A server hands out tickets after a handshake so the next one can skip
proving its identity. Three servers of four accept ours:

    tls.peet.ws          2 tickets   RESUMED
    www.cloudflare.com   2 tickets   RESUMED
    www.google.com       2 tickets   RESUMED
    github.com           2 tickets   offered, declined

github declining is its choice rather than a fault here: RFC 8446 requires a
server to abort if a binder does not validate, so a silent decline means the
binder was fine and the policy was not.

**The part worth understanding is the binder.** The ClientHello signs
itself: the binder is an HMAC over the same ClientHello that carries it, up
to the point where the binder begins. So the message has to be built once
with every length already correct and the binder space empty, hashed, and
the result written into the space reserved for it. Build it in the obvious
order and the lengths are wrong by exactly the size of the thing you have
not computed yet.

**And the finding that matters more than the feature.** A resumed
ClientHello is a different fingerprint:

    fresh    t13d1517h2_8daaf6152771_3cbfd9057e0d
    resumed  t13d1518h2_8daaf6152771_5dff20295fdc

Eighteen extensions instead of seventeen, and a different extension hash.
That is correct in itself, since Firefox has two fingerprints for the same
reason. But **there is no capture of Firefox resuming**, so the resumed hello
is now the one part of this client that nothing verifies, and a Session
resumes by default, which means most requests after the first send it.

Shipping resumption without that capture trades a known gap, never looking
like a returning visitor, for an unknown one. The trade is probably right,
and it is still a trade.

It is measurable with the tools already here. `tools/catch_request.py`
completes a handshake, so Python's TLS server issues Firefox a ticket.
Running `tools/catch_hello.py` afterwards on the same host and port captures
the raw bytes of the next hello, which will offer that ticket. Two runs, no
new code.

---

## 2026-10-07 — The TCP check earns its keep

`tools/verify.py` dropped to 17 of 18 straight after the resumption work,
which looked like a regression and was not:

    expected  4:117+?:0:1400:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
    got       4:54+?:0:1400:65535,9:mss,sok,ts,nop,ws:df,id+:0

TTL 54 with `mss,sok,ts,nop,ws` is a Linux stack. This machine is Windows
and has not changed. The exit address had: one address earlier in the
project, another now, with no proxy variables set. So something on
the path is terminating TCP, a VPN or a carrier NAT, and the signature the
server sees belongs to that box.

Every TLS and HTTP check still passed. The one that moved is the one below
the socket, which is the only layer this client does not produce.

Two things to keep. The check is tied to a network as well as to a machine,
which the README said less precisely before. And a failing check that fails
for the right reason is worth more than a passing one: left out, the client
would have looked unchanged while presenting a different operating system to
every server it talked to.

---

## 2026-10-07 — Multiplexing, and walking into a hazard I had just written down

Until now the client sent one request and blocked until its reply, which
makes HTTP/2 a more complicated HTTP/1.1. The reader is now a demultiplexer:
`send_request` opens a stream and returns, `_pump` reads one frame and files
it against whichever stream it belongs to, and `request_many` keeps as many
in flight as the peer's MAX_CONCURRENT_STREAMS allows.

    six one-second requests, one connection
      one at a time   6.6s
      multiplexed     1.1s

**The bug is the part worth keeping.** While writing `_pump` I added this
comment:

> HPACK has one decoder per connection and its state depends on every header
> block in order, so frames cannot be skipped for being someone else's:
> ignoring one corrupts every later header on the connection.

And then accumulated each stream's header block and decoded it when the
stream finished, which is a different order. Six parallel requests later:
`InvalidTableIndex: Invalid table index 72`.

Knowing the hazard was not enough, because the mistake was not skipping a
frame. It was decoding in completion order rather than arrival order, which
is the same hazard wearing different clothes. Blocks are now decoded the
moment END_HEADERS arrives.

The regression test encodes the same fields twice so the second block is
indexed references into the table the first one filled, then delivers them
on two streams whose completion order is the reverse of their arrival order.
Decoding out of order cannot look like it worked.

A GOAWAY now fails only the streams above the peer's last_stream_id, rather
than the whole connection, since the ones below it will still be answered.
A RST_STREAM fails its own stream and leaves the rest alone. Neither was
expressible while one request owned the reader.

---

## 2026-10-07 — Concurrency across connections

`Fetcher` runs requests over a thread pool. The design question was what to
share.

A Session owns connections and a single-threaded frame pump, so it cannot be
shared; each worker gets its own. The cookie jar and the ticket store are
shared deliberately. Giving every worker its own jar would mean a site that
sets a session cookie hands out one per thread, which is both wrong and
conspicuous: four workers with four sessions on one site is not what a
browser looks like. The jar needed a lock for that, which it did not have.

    one at a time, 4 urls    5.0s   0.8/s
    4 workers, 12 urls       3.5s   3.4/s
    8 workers, 12 urls       2.4s   4.9/s

Errors are returned rather than raised. A batch of a thousand should not
stop because one host refused a connection, so `fetch` returns a `Result`
carrying either a response or the exception.

**Retries deliberately exclude 403.** A rate limit or a 5xx is worth
repeating; a block is an answer, and repeating it only burns the address
faster. That distinction came out of the measurement work rather than from
general principle: 429 and 403 mean different things and the harness had to
learn that too.

---

## 2026-10-07 — The browser is being intercepted

A fresh look at tls.peet.ws from Firefox reported a fingerprint matching
neither the stored reference nor this client:

    stored reference  t13d1517h2_8daaf6152771_3cbfd9057e0d
    this client now   t13d1517h2_8daaf6152771_3cbfd9057e0d
    the browser now   t13d2713h2_bd9791dd9fd6_ecd0401ec68b

It is not Firefox's stack. Twenty-seven ciphers rather than fifteen, every
one listed twice, which NSS never does. `encrypt_then_mac` present, which is
an OpenSSL extension. `renegotiation_info` ahead of `server_name`, the
reverse of Firefox's order. And none of the five extensions this project has
used since the first capture to tell NSS from BoringSSL:
`delegated_credentials`, `record_size_limit`, `status_request`,
`signed_certificate_timestamp`, ECH.

The HTTP/2 layer is rebuilt too: stream id 1 rather than 3, no PRIORITY flag
on the HEADERS frame, INITIAL_WINDOW_SIZE 1048576 against Firefox's 131072,
WINDOW_UPDATE 983041 against 12517377.

So something terminates both layers and re-originates them. The cause turned
out to be NordVPN's Threat Protection, which installs a local proxy and a
root certificate to inspect HTTPS and runs **while the VPN is not connected
to anything**. The app being open was enough. The earlier anomaly, where the
TCP signature briefly read Linux from a different exit address, fits the VPN
itself connecting for a moment.

Worth sitting with. This is ordinary consumer software, sold as a security
feature, and its effect is identical to the free proxy caught earlier in the
project: a third party replaces the TLS and HTTP fingerprints of every
request and nothing anywhere reports a problem. Any machine running one of
these is a bad place to capture a reference from, and most people have no
idea theirs does it.

**What matters for the fixtures.** The stored references were captured
before this appeared and carry the five NSS extensions, so they are the real
browser. Re-capturing now would bake the middlebox into the profile and the
client would start imitating the antivirus. Nothing should be re-captured
until the certificate issuer on an ordinary site is a public CA again.

Worth noting what it took to see it. Nothing broke, no error appeared, and
the browser rendered every page normally. The only reason it surfaced is
that something in this project reports back what the server actually
received, which is the same reason the free proxy's interception was caught
rather than shipped.

## 2026-10-07 — Streaming, and a five-kilobyte scare that was nothing

Streaming works: 0.68 MB peak against 2.67 MB buffered for a 1.0 MB
document, 91 chunks, largest 43,216 bytes. Four times less memory, which is
about what a reader that never concatenates should give.

The interesting part is the hour between "it works" and knowing it works.

The first comparison said `same content: False` — 974,701 streamed against
979,740 buffered, a gap of 5,039 bytes. The target was `etsy.com/c/jewelry`,
a dynamic page, so the easy move was to shrug: of course two fetches differ.
That explanation is available for any discrepancy, which is exactly why it
cannot be accepted without a measurement. So:

**Static resources first.** `example.com` and `httpbingo.org/encoding/utf8`
came back byte-identical, streamed against buffered. `httpbingo.org/gzip`
did not, repeatably, five rounds out of five, at identical length. A
repeatable mismatch at identical length is not page variance.

**Then I looked at the wrong thing.** I printed the first 120 bytes and the
last 80 of each body, saw them agree, and nearly concluded the bodies were
identical. The difference lived on line 52 of 55, inside the window I had not
printed. The slice was chosen to be convenient, not to be informative.
Diffing the whole thing took one more line and showed it immediately:

    -      "t=1791390273581527"
    +      "t=1791390273822666"

`X-Request-Start`, a timestamp the httpbingo front end injects into the
request and the endpoint then echoes into the body. Same length every time,
different digits. The endpoint echoes the request, so it cannot be
deterministic, and I had picked it as a determinism control.

**The etsy gap was sampling.** Comparing arms proves nothing without
comparing within an arm first:

| comparison | sizes | delta |
|---|---|---|
| buffered vs buffered | 981,265 / 981,151 | 114 |
| streamed vs streamed | 977,061 / 976,451 | 610 |
| buffered vs streamed | 981,265 / 977,061 | 4,204 |

I read that table as a systematic 4 KB shortfall in the streaming arm and
went looking for a lost tail. The next pair put streamed *above* buffered —
977,928 against 958,737 — and both ended in a complete `</body></html>`.
Across six fetches etsy served between 958,737 and 981,265 bytes. The page
varies by up to 22 KB, so the 114-byte agreement was luck and the 4,204-byte
gap was luck of the opposite sign. With a spread that wide, two samples per
arm can support any conclusion you like. The negative controls were the only
real evidence, and they had already said streaming was correct.

### What the hunt actually found

Chasing a non-bug turned up a real one, in the place I was looking:

    def finish(self):
        if self._impl is None or not hasattr(self._impl, "flush"):
            return b""
        return self._impl.flush()

The whole-body path gets truncation detection free — `zlib.decompress` on a
cut stream raises `Error -5: incomplete or truncated stream`, because it
refuses to return a partial result. Feeding chunk by chunk had no such
guard. A connection dropped mid-body would yield every chunk that arrived,
flush nothing, and hand back a short document with no error.

That is the worst possible failure for a scraper. It does not look like a
failed download; it looks like a page that changed, which is precisely the
explanation I had just caught myself reaching for. The two halves of this
entry are the same mistake seen from both sides.

`finish()` now checks the end-of-stream marker: `eof` for zlib and zstd,
`is_finished()` for brotli, and raises `ContentEncodingError` otherwise.

### Tests

`tests/test_streaming.py`, 16 tests, no network. Every encoding fed at chunk
sizes 1, 2, 7, 64, 1024, whole and oversized, asserted equal to what the
whole-body decoder returns — 1 byte being the pathological case, since
gzip's 10-byte header alone then spans ten calls. Then the same over
scripted HTTP/2 DATA frames at sizes 1, 3, 17, 997 and 16384, because a
frame boundary is a second place a boundary can land.

Two tests exist because an earlier version of a test would have passed
without them: one asserts the body arrives in more than one chunk, since
every equality test above would pass on a decoder that secretly buffered
everything; the other asserts that abandoning the iterator early still
releases the stream, which the `finally` handles but nothing proved.

Disabling the truncation check fails 5 of the 16. Worth running: a guard
whose tests pass with it removed is not a guard.

## 2026-10-07 — The second fingerprint nobody had looked at

`Session` resumes by default. That was recorded as a feature and it is also a
hole: a resumed ClientHello carries `pre_shared_key`, so every request after
the first was sending a fingerprint that no capture and no test covered. The
feature shipped; the measurement did not.

How much does resuming change? Two connections from one Session to
`tls.peet.ws`, the second forced onto a new socket with `_discard` so the
ticket is actually used:

| | fresh | resumed |
|---|---|---|
| ja4 | t13d1517h2_8daaf6152771_3cbfd9057e0d | t13d1518h2_8daaf6152771_5dff20295fdc |
| ja3_hash | 9d42e90b0225e779f03141ddcd699df2 | d592459dbfefa4b91d9cba9f926808cf |
| peetprint_hash | a4bbbc7e3adf3db97d276fd0adb1efc4 | 56519330ce41b30eb57ebdf5188a32da |

Every hash changes. `1517` to `1518` is the extension count going from 17 to
18, and `0029` appears in the sorted list — 0x29 is 41, `pre_shared_key`. So
this is not a variant of the fingerprint, it is a second one. Anything that
has a rule for `t13d1517h2` has a separate rule, or no rule, for
`t13d1518h2`.

### Our side checks out

Three things were worth proving before worrying about the browser.

The hello is well formed: `pre_shared_key` is added, nothing is dropped, the
other seventeen extensions keep their relative order, and the binder sits
last, which RFC 8446 4.2.11 requires rather than suggests.

The binder arithmetic is right, which is the part that could silently be
wrong. Sending a PSK is not the same as a server taking it, and a bad binder
is answered with `decrypt_error`, not with a fallback:

      round 1: resumed=False status=200
      round 2: resumed=True  status=200
      round 3: resumed=True  status=200

A real server behind Cloudflare accepted it twice. The ClientHello signing
itself works.

### Capturing the browser's version

What is left is the comparison, and that needs Firefox's resumed hello.
Neither existing tool can get it, for opposite reasons. `catch_hello.py`
dumps raw bytes and lets the handshake die, so no ticket is ever issued and
the browser has nothing to resume with. `catch_request.py` completes the
handshake through `ssl.wrap_socket`, so a ticket goes out, but by then the
raw ClientHello has been consumed inside OpenSSL.

Both halves are needed at once, so `tools/catch_resumed.py` owns the byte
stream: TLS runs over a pair of `ssl.MemoryBIO`s, every inbound byte is
recorded on its way into OpenSSL, and the first TLS record is sliced off by
its own length prefix. The handshake still completes, the ticket still goes
out, and the hello survives. The reply says `Connection: close` and the page
reloads itself, so the browser opens a fresh socket and resumes on it.

Two bugs on the way, both already in this notebook under other dates.

The first: I wrote the reply immediately after the handshake and closed, so
the server closed a socket that still held the client's unread request.
Windows answers that with an RST, which discards whatever was queued to go
out — the reply and the ticket with it. `catch_request.py` has a comment
about exactly this, which I had read and not applied. Reading the request
before answering fixes it.

The second was `extension.kind`, which does not exist; the field is `type`.
Caught instantly because the tool was driven by pybrws before any browser was
involved, which is the only reason this entry is not a list of guesses about
why Firefox would not come back.

Driving it with our own client is also the test: fresh at 1,887 bytes with 17
extensions, resumed at 2,174 with 18, `added: pre_shared_key (41)`,
`dropped: nothing`, shared order preserved. The same thing peet.ws said,
measured locally.

The browser capture itself is the one step that needs a person to click.

## 2026-10-07 — Firefox swaps, we appended

The browser capture landed, and it says we were wrong in a way worth
understanding.

Resuming, I had assumed, appends `pre_shared_key`. It is what the RFC
describes and what our emitter did. Firefox does something else: it *swaps*.
`session_ticket` comes out, `pre_shared_key` goes in at the end, and the
extension count never moves.

      fresh    17 extensions, 1901 bytes
      resumed  17 extensions, 2472 bytes
      added    pre_shared_key (41)
      dropped  session_ticket (35)

Seventeen both times. Ours was eighteen, and JA4 puts the extension count in
the clear: `t13d1517h2` for the browser against `t13d1518h2` for us. No
hashing required to tell those apart — a server can count. Of all the ways to
be caught, that is the cheap one.

It makes sense in hindsight. `session_ticket` is RFC 5077, the TLS 1.2
resumption mechanism; offering it alongside a TLS 1.3 PSK is offering to
resume twice by two different means. Firefox picks one. The RFC never says to
drop it, so there was nothing to read — only something to measure.

### A retraction

I told Ernesto the capture showed Firefox reordering extensions. It does not.
The check in my own tool was wrong:

      moved = before != [kind for kind in after if kind in before]

`before` is the fresh list, seventeen long. The comprehension filters the
resumed list down to extensions that appear in `before`, which is sixteen,
because one of the seventeen was dropped. Seventeen is not sixteen, so it
reported a reordering. Any dropped extension would have. Comparing only the
extensions present in both shows the order is untouched: `session_ticket`
leaves position six, everything below slides up one, `pre_shared_key` goes
last.

A tool that reports a finding is a measuring instrument and wants the same
suspicion as the thing it measures.

### The ECH payload moves too

One real difference survived the fix. The greased `encrypted_client_hello`
payload went from 240 bytes fresh to 528 resumed. Ours stayed at 240, because
`ECH_PAYLOAD_SIZE` is a constant.

It is not arbitrary: the payload stands in for an encrypted inner
ClientHello, and that inner hello now carries a `pre_shared_key` of its own,
so it grows by roughly one. Roughly:

      ech payload grew by         288
      pre_shared_key on the wire  287
      residual                      1

One byte, unexplained. It could be a constant, or padding rounding up to a
boundary, and one sample cannot tell those apart. I tried to get a second
sample by varying the ticket's length, which would move the PSK size and so
separate the two hypotheses. Two attempts, both dead ends: `--alpn h2`
changes the ALPN stored in the ticket but the tool only speaks HTTP/1.1, so
the browser has nothing to reload; and `SSLContext.set_ciphers` cannot pin a
TLS 1.3 suite at all, because OpenSSL keeps those behind
`SSL_CTX_set_ciphersuites`, which Python does not expose.

So it is fitted to the one observation, on the grounds that a byte wrong
beats 288 wrong, and it is labelled as fitted in `ech_growth_for_psk` and in
a test that names it. That is the honest version of a guess: make it, write
down that it is one, and leave the thing that would settle it in plain view.

What would settle it: a capture where the pre_shared_key extension is a
different size. The cheapest lever left is a longer SNI, which changes the
hello's size without touching the ticket — if the residual stays 1, it is a
constant; if it tracks the hello, it is padding.

### Sixteen bytes that looked like a bug

Writing the fixture test, our rebuilt hello came out sixteen bytes short of
the capture's `pre_shared_key`. Sixteen is a suspicious number and I started
looking for a length prefix I had miscounted.

It was the binder: 48 bytes, not 32. The local server negotiated
`TLS_AES_256_GCM_SHA384` with Firefox, so the binder is a SHA384 hash. That
is a property of the server used for the capture, not of the browser, which
is exactly the sort of thing that gets baked into a fixture and later read as
inherent. The test now derives the suite from the binder's length instead of
naming it, and says out loud that it is the server's doing.

### Where it ended up

Both captures now come back clean through the differ, and the resumed hello
is 2472 bytes against the capture's 2472.

      FRESH    identical as far as the differ is concerned
      RESUMED  identical as far as the differ is concerned

`tests/test_resumed.py`, thirteen tests, no network. Removing the
`session_ticket` drop fails six; removing the ECH growth fails four.

### One self-inflicted wound

Running those mutation checks I reverted the profile with `git checkout
pybrws/profiles/firefox157.py`, forgetting the ECH work in it was not
committed. It went back to the repository's version and the change vanished.
It came back from the patch script still sitting in the scratchpad, so the
cost was a few minutes, but the lesson is cheaper to write down than to
relearn: `git checkout` of a file is a delete, and a mutation test should be
undone by restoring the copy you made, not by asking git for a version that
predates your work.

## 2026-10-07 — QUIC, starting from the reading end

HTTP/3 is the last large item and the one the job posting names. Starting it
by writing a client would have been the wrong end: there is nothing to aim at
until a browser's QUIC ClientHello has been measured, and it cannot be
assumed from the TCP one. Firefox cannot send `session_ticket` over QUIC --
that is the TLS 1.2 mechanism -- nor `record_size_limit`, since QUIC has no
TLS records to limit, and it must send `quic_transport_parameters`. So the
first thing built is a reader.

### QUIC hands the handshake over

The useful fact: QUIC does not run over TLS, it carries TLS 1.3 inside.
The handshake travels in CRYPTO frames inside Initial packets, and those are
protected with keys derived from a salt printed in RFC 9001 section 5.2 and
the connection ID the header carries in the clear. Nothing secret goes into
them. An observer reads a QUIC ClientHello as easily as one off TCP -- which
cuts both ways, and is why all the extension-order work transfers intact.

It also solved a problem I was about to have. Capturing Firefox over HTTP/3
against a local server means persuading Firefox to use HTTP/3 at all, which
needs an Alt-Svc advertisement over TCP first, and then persuading it to
accept a self-signed certificate over QUIC, which it may well refuse outright.
None of that is necessary: capture UDP 443 while the browser visits a real
h3 site and decrypt the Initial. Real server, real certificate, real
transport parameters, no warnings.

### What got built

`pybrws/quic.py` reads a client's first flight: header protection removal,
AEAD decryption, frame walking, and CRYPTO reassembly. It depends on
`cryptography` and nothing else -- deliberately, and there is a check that
imports it with aioquic hidden from `sys.meta_path` to keep that true.

`tools/read_quic.py` gets datagrams out of a pcap or pcapng: both byte
orders, Ethernet, raw IP, loopback and Linux cooked, IPv4 and IPv6.

The piece I would have got wrong by reasoning about it: a capture of port 443
holds several connections whose datagrams interleave. Feeding the lot in as
one stream would mix CRYPTO offsets from different handshakes, and because
offsets from two handshakes can cover a contiguous range, the result would
*parse* -- a ClientHello assembled out of two browsers' worth of bytes.
Grouping by destination connection ID, which is what keys the decryption
anyway, keeps them apart. There is a test that interleaves two flights and
insists on getting both back.

### aioquic as an oracle

The decryptor is checked against aioquic rather than against itself: aioquic
builds a first flight into raw datagrams, and is asked separately what
ClientHello it serialised, so two independent implementations have to agree
on the bytes. Breaking the salt by one byte fails 8 tests, widening the
header-protection mask from `0x0f` to `0x1f` fails 5, and turning the
reassembly gap guard into a no-op fails 1.

One assumption in those tests was wrong and the test caught it. I asserted
the flight spans more than one datagram, because a ClientHello does not fit
in the 1200 bytes QUIC starts with. Firefox's does not -- it is around 1900 --
but aioquic's is 484 bytes and fits easily, so the assertion failed and the
reassembly path was never being exercised. aioquic has
`quantum_readiness_test`, whose whole purpose is to inflate the hello, and
with it the flight takes two datagrams. The multi-datagram cases now live in
their own class, built on that, and the single-datagram class says out loud
that it is not the one covering reassembly.

Which is the second time today a test earned its keep by contradicting the
comment I wrote above it.

### The new fingerprint surface

`quic_transport_parameters` has no equivalent on TCP: an ordered list of
values a client chooses for itself. aioquic sends twelve, in ascending id
order:

      0x1   max_idle_timeout                     0x8   initial_max_streams_bidi
      0x4   initial_max_data                     0x9   initial_max_streams_uni
      0x5   initial_max_stream_data_bidi_local   0xa   ack_delay_exponent
      0x6   initial_max_stream_data_bidi_remote  0xb   max_ack_delay
      0x7   initial_max_stream_data_uni          0xe   active_connection_id_limit
                                                 0xf   initial_source_connection_id
                                                 0x11  version_information

Ascending order is itself a choice, and I would expect a browser not to make
it. That is the measurement to take next.

A detail worth having got right by accident: RFC 9000 section 18.1 reserves
ids of the form 31N+27 to be ignored, the same greasing idea as the cipher
suites. My first `parameter_name` checked that formula before the registered
table, which would rename any registered parameter whose id happens to
satisfy it -- and the formula covers a third of the id space, so that is a
coincidence waiting to happen, not a hypothetical. The table wins now, with a
test that walks the registered ids looking for collisions.

## 2026-10-07 — Firefox shuffles over QUIC, and a capture that was two browsers

The first real capture: 231 UDP datagrams, 12 long-header connections, seven
ClientHellos recovered. The tool worked on real traffic first time, which was
more luck than it sounds -- it had only ever seen datagrams aioquic made.

### The finding

Six of the seven connections carry an identical set of fifteen extensions:

      0 5 10 13 16 23 27 28 34 43 45 51 57 65037 65281

and a **different order every time**. Six connections, six orders, no
repeats. The last two never move: `quic_transport_parameters` then
`encrypted_client_hello`, in that order, in all six.

One of the six is `incoming.telemetry.mozilla.org`, which nothing but Firefox
contacts, and the other five share its exact transport parameter sequence. So
this is one client, and that client shuffles.

Which is the opposite of its behaviour on TCP. `HANDOFF` has said for days
that "Chrome shuffles its extension order, which Firefox does not" -- true,
and true only of the TCP path. Firefox's QUIC is neqo, written in Rust, not
NSS, and it behaves like Chrome here. Two stacks in one browser, two
fingerprinting rules.

It also means the fixture written an hour ago is one sample of a
distribution, not a reference, and no test may assert its order. What can be
asserted is the relationship between samples, which is what
`tests/test_read_quic.py` now holds: same set every time, different order
every time, exactly two pinned at the end.

### The capture was two browsers

The seventh connection, to `www.bing.com`, is not Firefox. Eleven extensions
rather than fifteen, carrying 17613, and missing every NSS marker the others
have -- `renegotiation_info`, `delegated_credentials`, `status_request`,
`extended_master_secret`, `record_size_limit`. Its transport parameters are
`google_connection_options`, `initial_rtt`, `google_version`. That is
something Chromium-shaped, which on this machine means Edge doing whatever
Edge does in the background.

My first reading had all seven as one client, so the report said "7 distinct
orders across 7 connections" and I nearly wrote down that the set varies too.
It does not; the sets split cleanly into two clients. A capture of port 443
holds whatever the machine was doing, which is obvious once stated and was
not obvious while reading the output.

`--all` now groups by extension set before saying anything about order, so a
second client shows up as a second client instead of as noise in the first
one's measurement. It also prints a per-connection line with the ECH
extension length and the parameter count, because the thing that gave the
mixing away was an outlier in a column I had not thought to print.

### Three other differences from TCP

Three cipher suites rather than fifteen: `0x1301 0x1303 0x1302`, the TLS 1.3
ones only, because QUIC forbids TLS 1.2. That is the single cheapest QUIC
tell there is -- a client offering the TLS 1.2 suites over QUIC has not
thought about it.

Three extensions gone: `ec_point_formats`, `session_ticket` and
`signed_certificate_timestamp`. The first two follow from TLS 1.2 being
unavailable. The third does not obviously, and is worth a note rather than an
explanation.

The transport parameters are not in ascending id order -- `reset_stream_at`
(0x1d) and the GREASE id come before `max_datagram_frame_size` (0x20).
aioquic sorts them; Firefox does not. And the GREASE id differs between
connections, with an eight-byte one among them (`0x3ce1db6c726e52b5`), so it
is drawn per connection rather than copied.

### Two things I got wrong on the way

The chooser. `--host cloudflare-quic.com` matched nothing, and the tool fell
back to the largest hello and wrote the fixture anyway -- for
`blog-cloudflare-com-assets.storage.googleapis.com`. A file labelled for one
host holding a measurement of another is worse than no file, because the
label is what a later reader trusts. It refuses now.

The parameter table. I wrote it from memory and it was wrong where it
mattered: 0x1d is `reset_stream_at`, not unknown, and `min_ack_delay` is
0xff04de1b, not the 0xff02de1a the capture shows. The IANA registry settled
it in one fetch. 0xff02de1a satisfies 31N+27 exactly, so it is real GREASE
rather than an old draft codepoint -- but I had assumed the opposite, and the
only reason I checked is that the arithmetic was cheap.

### Still open

`cloudflare-ech.com` has Firefox's exact extension set and Firefox's pinned
tail, but **three** transport parameters where the other five send fourteen:
`max_ack_delay`, `initial_source_connection_id`, `version_information` and
nothing else. That is not a functioning set -- no flow control credit at all.

Our parser is strict about trailing bytes and truncated extension headers, so
a hello that parses cleanly with fifteen extensions almost certainly is not a
reassembly accident. Which points at it being real, and the obvious
suspicion is that `cloudflare-ech.com` publishes a real ECH config, so what
was captured is the *outer* hello -- a decoy -- with the working parameters
encrypted inside. If so it is the first real-ECH hello in this project and
worth its own fixture, and it also means a QUIC profile has two cases, not
one.

Not concluded. It needs the bytes looked at, and the ECH extension length
compared against the 282 of a greased one, which is exactly what the new
per-connection line prints.

## 2026-10-07 — Two corrections, both from the same mistake

The per-connection columns settled the open question and overturned two
things written an hour earlier. Both errors were the same error.

**The GREASE transport parameter is constant.** I wrote that Firefox draws it
per connection "with an eight-byte one observed". It does not: `0xff02de1a`
appears in all six Firefox connections. The eight-byte one,
`0x3ce1db6c726e52b5`, belongs to the other client in the capture. I had
mixed the two again, in exactly the way I had just finished fixing the tool
to prevent, one report earlier.

And a constant is interesting in its own right. A value that never changes is
not greasing anything, and this one carries the varint 1000, which is a
plausible `min_ack_delay`. The registered codepoint for that is 0xff04de1b,
one of a family of `0xff0?de1?` draft codepoints, so 0xff02de1a is most
likely an old draft of it that satisfies the 31N+27 reserved pattern by
coincidence. The tool still prints it as GREASE because the formula says so.
Not identified, and labelled as not identified.

**The real-ECH hypothesis was wrong.** `cloudflare-ech.com` sends three
transport parameters where the others send fourteen, and I guessed that the
host publishes a real ECH config, so what was captured was a decoy outer
hello with the working parameters encrypted inside. Its ECH extension is 282
bytes -- the same greased length as every other connection in the capture.
No real ECH anywhere. The guess was plausible, fitted the evidence I had, and
was simply wrong, which is the argument for printing the column rather than
reasoning about what it would contain.

So the three parameters needed another explanation, and the one that holds is
that there is nothing to explain about the *decoding*: it is real. Three
parameters measure about 26 bytes on the wire against 86 for fourteen, a
difference of 60. `www.cloudflare.com` and `cloudflare-ech.com` have server
names of equal length and hellos of 1900 and 1840 bytes. Sixty, predicted
from the parameter count alone and matching the observed hello sizes, is
independent of the decoder that produced the count.

What Firefox is doing differently with that one host remains unknown. It is
one connection in six and nothing rests on it.

**And the other client is Chrome, not Edge.** I attributed the bing.com
connection to Edge on the grounds that it was a Windows machine. Ernesto had
Chrome open at the time. The attribution did not matter to any measurement,
but it was stated with more confidence than it was held with, which is the
habit worth not having.

## 2026-10-07 — The write side, and two failures that were compliments

Seven hosts out of seven now connect over HTTP/3 with a ClientHello that
matches the Firefox capture byte for byte, six of them selecting
X25519MLKEM768:

      www.google.com                   group 0x11ec  suite 0x1301  alpn h3
      cloudflare-quic.com              group 0x11ec  suite 0x1301  alpn h3
      blog.cloudflare.com              group 0x11ec  suite 0x1301  alpn h3
      www.bing.com                     group 0x11ec  suite 0x1302  alpn h3
      incoming.telemetry.mozilla.org   group 0x001d  suite 0x1301  alpn h3
      www.facebook.com                 group 0x11ec  suite 0x1301  alpn h3
      www.youtube.com                  group 0x11ec  suite 0x1301  alpn h3

Against the capture, with the genuinely per-connection parts compared by
length rather than by value: 1931 bytes against 1931, every static payload
identical, the extension set and pinned tail identical, the cipher suites and
the empty session id identical, and the fourteen transport parameters
identical in order and in value but for the connection's own id.

### Five seams

The plan was one seam. `push_client_hello` writes the message inside
`with push_message(key_schedule, output_buf):`, and that context manager
hashes whatever ends up in the buffer, so replacing the writer keeps the
transcript correct for free. That part held exactly as hoped.

The other four were found by running it.

**Getting hold of the connection.** The writer is handed a buffer and a
hello, not the Context, and per-connection state has to live somewhere, so
`_client_send_hello` is wrapped to create it.

**The key exchange.** Firefox's QUIC key_share is 1327 bytes across three
entries -- X25519MLKEM768 at 1216, X25519 at 32, secp256r1 at 65 -- and
aioquic's `Group` enum has no post-quantum group at all. An unknown group is
silently skipped, so there is no configuration that produces one. We have the
hybrid in `keyexchange.py`, already verified against real servers on TCP, so
all three shares are ours and aioquic's own private keys go unused. The
secret has to come from us too, and aioquic computes it as
`self._x25519_private_key.exchange(peer_public_key)` after
`decode_public_key` turns the server's share into a key object. So
`decode_public_key` keeps the raw share and returns a dummy whose type
satisfies the `isinstance` check, and `_x25519_private_key` becomes an object
whose `exchange` ignores its argument and returns the real secret. A stub in
a hole of exactly the right shape. Ugly, contained, and better than copying
`_client_handle_hello` into our tree where it would go stale in silence.

The remaining two were protocol lessons rather than plumbing, and both only
showed up *because* the impersonation worked.

### A compressed certificate

Cloudflare's answer to our hello was handshake message type 25, and aioquic
replied with `unexpected_message`: CRYPTO_ERROR 266, which is alert 10 inside
a CRYPTO frame.

Type 25 is RFC 8879 CompressedCertificate. We asked for it, because Firefox
sends `compress_certificate` and the profile copies Firefox. The server took
us at our word. aioquic names `COMPRESSED_CERTIFICATE` in its enum and never
dispatches it, which is what made the failure confusing to read: the type is
known and the handling is absent.

We already decompress those in `certs.py` for the TCP client, so the fix was
small, but there is one trap in it. RFC 8879 section 5 puts the *compressed*
message in the handshake transcript. Decompressing and handing the result to
aioquic's own certificate handler would hash the certificate that came out,
not the message that came in, and the only symptom would be a Finished check
failing with nothing in the error pointing at compression. So the
interception hashes the compressed bytes itself and calls only the parsing
half.

A failure caused by being convincing is a good failure. A plain client never
sees message type 25 because it never asks for it.

### Two connection ids, not one

With that fixed, Cloudflare connected and Google did not -- and Google did
not answer at all. No ServerHello, no alert, nothing. Every Initial packet
dropped in silence.

Matching Firefox's three-byte `initial_source_connection_id` means setting
aioquic's `connection_id_length` to 3, and aioquic uses that one setting for
both ids: line 339 of `connection.py` draws the initial *destination* id with
it too. RFC 9000 section 7.2 requires the client's initial destination id to
be at least 8 bytes, because the Initial keys are derived from it and an
attacker who can guess it can forge packets. Three bytes is a violation.
Cloudflare tolerated it; Google dropped it, which is the correct response and
the less helpful one.

So Firefox uses asymmetric lengths -- three bytes for the id it issues, eight
or more for the one it picks for the server -- and aioquic conflates them. The
two are separated now, with a test asserting the destination id in the packet
header is the same bytes the keys were derived from, because a mismatch there
makes every Initial undecryptable by the peer and says nothing about why.

Worth being plain about what is measured and what is not: three bytes is
measured, from the one connection whose parameter values were read out. Eight
is the RFC's floor, not an observation. Firefox's actual choice is not in the
ClientHello and needs the packet headers from a capture.

### On the tests

Twenty-six, offline. Half assert the hello against the fixture. The other
half assert that the seams still exist -- every private name reached for,
plus the shape of the key-exchange hole, plus that aioquic still lacks the
post-quantum group and still does not dispatch type 25. Five monkeypatches
into a dependency's private surface is a liability, and the way to carry it
is to make an upgrade break a test rather than a connection.

Three of my own tests were wrong on the first run and said so: one read the
transcript off the wrong object, one asserted aioquic had never heard of
compressed certificates when it names them, and one inspected
`_client_handle_hello` after this module had already replaced it, so it was
proving that our wrapper calls our own stub.

## 2026-10-07 — Measured against curl_cffi over HTTP/3

curl_cffi is the production tool for this job and it has HTTP/3 fingerprints
since v0.15, so it is the obvious baseline -- the HTTP/3 equivalent of what
httpx has been for TCP, except that httpx is a control and this is a rival.

### No third party

The plan was to point both at a fingerprinting service. `tls.peet.ws`
advertises `h3=":443"` in its Alt-Svc header and does not serve it: both
clients fail the handshake there, identically. curl_cffi's error named
**ngtcp2**, which answered a question its README leaves open -- that is the
QUIC backend curl-impersonate builds against.

So the oracle is our own server, which is better anyway. `catch_quic.py` was
already capturing the ClientHello; it now records the HTTP/3 request headers
too, in arrival order, which a third party would not have shown. That is the
same arrangement `catch_h2.py` gave for HTTP/2.

### What agrees

| | pybrws | curl_cffi firefox147 |
|---|---|---|
| extension set | identical | identical |
| cipher suites | `1301 1303 1302` | `1301 1303 1302` |
| legacy session id | empty | empty |
| key shares | `11ec/1216 1d/32 17/65` | same |
| request header order | 11 headers | **the same 11, same order** |

The header order agreeing is worth dwelling on, because it was a guess. There
is no measured HTTP/3 header profile: `pybrws/h3.py` sends the HTTP/2
navigation set and says in a comment that it is a starting point. It turns out
to match curl_cffi's firefox147 exactly, header for header, in order. Two
independent guesses landing on the same answer is weak evidence, but it is
evidence, and it is more than the comment claimed.

### What differs, and where each of us is wrong

Three extensions differ, and in all three we match the Firefox 157 capture:

| extension | pybrws | curl_cffi | Firefox 157 |
|---|---|---|---|
| `supported_groups` | 12 | 16 | **12** |
| `quic_transport_parameters` | 86 | 79 | **86** |
| `encrypted_client_hello` | 282 | 186 | **282** |

`supported_groups`: five groups against their seven. The transport
parameters: they omit `reset_stream_at` (0x1d), and their GREASE id is eight
random bytes where Firefox's is the constant four-byte `0xff02de1a`. The ECH
payload: 240 bytes against their 144.

Some of that is a version difference rather than a modelling difference, and
saying otherwise would be unfair. Their newest Firefox target is 147 and the
capture is 157; `reset_stream_at` is a recent parameter and may simply not
have been in 147. The group count could go the same way.

Two differences are not version differences, because they are about behaviour
rather than values. Four connections each:

      pybrws     hello sizes [1905, 1905, 1905, 1905]  ech [282, 282, 282, 282]
                 distinct extension orders: 4 of 4
      curl_cffi  hello sizes [1875, 1877, 1807, 1809]  ech [250, 250, 186, 186]
                 distinct extension orders: 1 of 4

**curl_cffi does not shuffle.** One order in four connections, where the real
Firefox gave six distinct orders in six. Their README offers "the ability to
change extension orders", which is a configurable fixed order and not a draw,
and over enough connections the absence of variation is itself the tell: a
client whose extension order never moves is not neqo.

**Its ECH payload length varies** and Firefox's does not. 282 bytes in all six
captured connections and at both server-name lengths tested; theirs moves
between 186 and 250. A length that changes when the browser's does not is a
discriminator in the other direction.

And one difference where **we are probably the wrong ones**. The
pseudo-header order: ours is `:method :path :authority :scheme`, taken from
our own measured HTTP/2 profile on faith; theirs is
`:method :scheme :authority :path`. They presumably measured it. One of us is
wrong about Firefox over HTTP/3 and only a capture settles it. It is written
down in `pybrws/h3.py`, in `tests/test_h3.py` and in HANDOFF rather than left
to be discovered, because this is exactly the kind of inherited assumption
this project is supposed to catch -- and it inherited one.

### What this is and is not

It is not a claim to be better. curl_cffi is a mature tool with Chrome,
Safari, Edge, proxies, a real API and years of use; this has one browser, no
Chrome, and five monkeypatches into a dependency's private surface. The claim
is narrow and checkable: on four specific points of the QUIC handshake,
measured against a real Firefox 157 capture, we match it and the production
tool does not -- and on one point it is the other way round.

What the difference comes from is not cleverness. They configure a fixed
order because a fixed order is what their architecture exposes; we draw one
because six captures said Firefox draws one. The measurement is the whole
advantage.

## 2026-10-07 — A WAF being present is not a WAF being on

Ernesto asked whether anything had been tested against Imperva. Nothing had,
so `tools/detect_waf.py` went looking -- detecting the vendor from the
response rather than guessing which sites use which, since guessing is how a
results table ends up measuring something other than what it says. Imperva
leaves `X-Iinfo`, `X-CDN: Incapsula` or `visid_incap_` cookies; every other
vendor leaves something too.

Twenty-five large retail and listing sites: no Imperva at all. CloudFront,
DataDome, Akamai, Cloudflare, Fastly, PerimeterX. A second and third list
found five: `imperva.com` itself, `endesa.com`, `lineadirecta.com`,
`zurich.es`, `generali.es`.

Then the A/B, three rounds, interleaved:

      endesa.com        3/3 served    httpx 3/3 served    no difference
      generali.es       3/3 served    httpx 3/3 served    no difference
      imperva.com       3/3 served    httpx 3/3 served    no difference
      lineadirecta.com  3/3 served    httpx 3/3 served    no difference
      zurich.es         3/3 served    httpx 3/3 served    no difference

I was about to write that down as five more wins. Ernesto pointed out why it
is not: a vendor sitting in front of a site says nothing about whether bot
protection is switched on, and a page on a random site can be configured
loosely or not at all. The table shows exactly that -- httpx passed all five
too. **The measurement is uninformative, and reporting it as a result would
have been reporting the absence of a gate as the defeat of one.**

The right target for a question like that is a page that demonstrably
challenges, which is the other thing he supplied.

### Where the project ends, measured

`scrapingcourse.com/cloudflare-challenge`, both arms:

      pybrws  403, 5771 bytes, challenge markers, passed=False
      httpx   403, 5601 bytes,                    passed=False

Cloudflare says what it is in its own headers: `cf-mitigated: challenge`,
`/cdn-cgi/challenge-platform`, `managed`, and the tokens `cf_chl_tk`,
`cf_chl_opt`, `cf_chl_f_tk`, `cf_chl_rt_tk`. A Managed Challenge, which
challenges everything that arrives, a real Firefox included.

So this is not a fingerprint failure. A browser gets through by fetching the
challenge script, running it, and posting back what it computes -- the script
reading runtime signals rather than network ones. No ClientHello is good
enough to skip that, and the fingerprint's job is one step earlier: deciding
whether a challenge is served at all. The sites in the results table serve us
and block httpx *without* challenging either, which is the layer this project
works at.

Worth being plain that this is the boundary and always was. It is the gap that
was named at the start of the project -- driving real browsers over CDP, and
deobfuscating the challenge script to see what it collects -- except that it
is now measured instead of assumed.

### Two gaps the sweep found by accident

`ulta.com` fails with `unexpected handshake message 0x0d`. That is
CertificateRequest: the server asks for a client certificate and the
handshake has no case for it. A browser with no matching certificate answers
with an empty Certificate message and carries on, and we do not, so the host
is simply unreachable. Cheap to fix and now in HANDOFF.

`iberia.com`, `swisscom.ch` and `aena.es` fail certificate chain validation.
Could be genuinely odd chains, could be a gap in how intermediates are
handled. Unknown, and not investigated.

### And a check that passed

He also asked whether the baseline is httpx with HTTP/2 rather than
HTTP/1.1 -- a fair thing to distrust, since an HTTP/1.1 baseline would make
every result in the table look better than it is. `ab_test.py` has
`http2=True` and a live check confirms it negotiates `HTTP/2`. Verified
rather than taken from reading the flag.

## 2026-10-07 — TLS 1.2, and the bug that was hiding behind it

Ernesto asked for TLS 1.2. The profile has offered twelve of its suites since
the first day, because Firefox does and removing them would change the
fingerprint, and a server that took one got refused. Two hosts fell out of the
WAF sweep that way and `httpbin.org` had been on the gap list from the start.

Almost nothing carries over from 1.3. Key derivation is a PRF, not HKDF: one
48-byte master secret from HMAC chained over itself, rather than a schedule of
secrets per stage. The server signs its key exchange in ServerKeyExchange
instead of signing the transcript in CertificateVerify, and it may sign with
`rsa_pkcs1`, which 1.3 forbids and 1.2 uses everywhere -- all three test hosts
do. Records keep their content type in the clear, and for GCM they carry an
explicit eight-byte nonce with the sequence number and header as additional
data. ChangeCipherSpec is a real message. Finished is twelve bytes whatever
the hash. And `extended_master_secret` changes the derivation, which is not
optional here because Firefox asks for it.

Implemented: ECDHE with AES-GCM and ChaCha20-Poly1305. The CBC and
static-RSA suites are offered in the hello and refused by name if a server
picks one -- better a failure that says which suite than a silent wrong
answer. Nothing tested picks them.

### OpenSSL as the oracle

The integration tests run against Python's own `ssl` as a TLS 1.2 server. That
is worth more than any unit test here: a PRF tested against a second copy of
itself proves nothing, while a handshake that completes against OpenSSL means
the PRF, the key block, both record constructions and both Finished messages
are all right at once.

Four mutations, each failing all seven of those tests: swapping the two
randoms in the key block, where RFC 5246 reverses them against the master
secret; making verify_data sixteen bytes; using `client finished` for both
directions; and skipping the extended master secret.

### The bug underneath

The first attempt got all the way to ServerHelloDone and then
`handshake_failure`. The trace showed the server's four messages arriving,
the signature verifying, and the failure landing on our flight.

The first cause was mine and embarrassing: I built the ClientKeyExchange,
added it to the transcript, and never sent it. The server got a
ChangeCipherSpec and a Finished and no key.

The second was older and more interesting. `connect` sent the compatibility
ChangeCipherSpec immediately after the ClientHello:

      sock.sendall(client_hello)
      records.write(0x14, b"\x01")

RFC 8446 appendix D.4 puts it immediately before the *second* flight. Every
TLS 1.3 server tolerated the early one, so it never showed. A TLS 1.2 server
cannot: a ChangeCipherSpec arriving before the ClientKeyExchange is a
protocol violation, and the answer is `handshake_failure`.

So the bug was invisible for as long as 1.2 was unreachable, and 1.2 was
unreachable because of the bug. There is a test for the ordering now, which
is simply that a 1.2 handshake completes.

### A client certificate request, twice

The same sweep that found the 1.2 hosts found `ulta.com` dying with
`unexpected handshake message 0x0d`. That is CertificateRequest: the server
asks for a client certificate and the state machine had no case for it.

A browser with none to offer does not fail. It sends a Certificate with an
empty list and no CertificateVerify, and the handshake continues. Which makes
asking a bot check in itself -- the server does not want the certificate, it
wants to see what an unexpected message does to the client. Ours fell over,
which is about as clear an answer as it could have given.

Implemented on both paths, and the 1.3 one taught me something I had wrong.
Adding our Certificate to the transcript before deriving the application
secrets broke them: RFC 8446 section 7.1 derives those from the transcript up
to and including the *server's* Finished, not ours. The symptom was a
handshake that completed and then `InvalidTag` on the first application
record, which says nothing at all about the cause. A snapshot taken at the
server's Finished fixes it.

`ulta.com` now returns 1,657,617 bytes.

### Where it stands

      httpbin.org        TLS 1.2  ECDHE_RSA_WITH_AES_128_GCM_SHA256  h2
      www.gls-group.eu   TLS 1.2  ECDHE_RSA_WITH_AES_128_GCM_SHA256  http/1.1
      www.proximus.be    TLS 1.2  ECDHE_RSA_WITH_AES_128_GCM_SHA256  h2
      www.ulta.com       TLS 1.3  client certificate requested       h2
      example.com        TLS 1.3  TLS_AES_128_GCM_SHA256             h2

Four hosts that were unreachable this morning, and the TLS 1.3 path
unchanged -- which has its own test now, against the same harness, because
the two paths share everything up to the ServerHello and a change to one can
break the other in silence.

## 2026-10-08 — Why yelp refuses Chrome, as far as it can be established

The three-arm sweep in the demo's new section turned up one cell that did not
fit: yelp serves the Firefox profile and refuses the Chrome one. Five
interleaved rounds, alternating which arm went first: 5 of 5 against 0 of 5.
Not transient.

### It is a challenge, not a block

      status 403
      server: DataDome
      x-datadome: protected
      body: "Please enable JS and disable any ad blocker"
             dd={'rt':'i','cid':...,'hsh':...}

A DataDome JavaScript challenge, the same shape as the Cloudflare one tested
earlier. And not a soft one: carried through a Session with its `datadome`
cookie it is still 3 of 3 refused, while the Firefox arm earns the full set a
served visitor gets -- `bse`, `bsi`, `datadome`, `hl`, `location`, `wdi` --
against Chrome's one challenge cookie. The decision is made on the first
request, from the fingerprint.

### A hypothesis, tested and refuted

The Chrome captures were all taken on a reload, so all six
navigation-shaped sets carried `Cache-Control: max-age=0`. Chrome sends that
on a reload and Firefox does not. A client sending it on every request
describes someone who reloads every page they visit, which is anomalous
enough to be a candidate.

Removing it changed nothing: 0 of 4 either way. The header is still a defect
on its own merits and is now separated from what goes on the wire, but it is
not the cause, and presenting it as one would have been a convenient story
rather than a result.

### Isolating the layer, and why that failed

A 2x2 crossing the TLS layer against the HTTP layer gave 403 on both mixed
arms and 200 only on all-Firefox. That looks decisive and is not: a Chrome
ClientHello carrying a Firefox User-Agent is precisely the contradiction
these systems look for, so crossing the layers introduces a third variable.
The experiment is confounded by construction and establishes nothing about
which layer matters.

### What three other Chromium clients say

      pybrws firefox157 (Windows)            3/3 served
      pybrws chrome155  (Windows)            0/3
      curl_cffi edge101 (Windows, Chromium)  0/3
      curl_cffi chrome + Windows UA          0/3

Every Chromium-shaped arm is refused; the only Firefox-shaped one is served.
curl_cffi's targets all claim macOS except edge101, which would be a
contradiction on this Windows machine, so the comparison was made fair two
ways -- edge101, and chrome with the User-Agent overridden -- and both fail.

That rules out the leading suspicion. If our Chrome profile had a defect,
curl_cffi's mature Chromium impersonations would not fail identically.

### And the part that undoes the tidy conclusion

"DataDome challenges Chromium" was the obvious next claim, and it is wrong.
The same two profiles across five targets:

      yelp.com         firefox 200 200   chrome 403 403
      etsy/c/jewelry   firefox 200 200   chrome 200 200
      zillow.com       firefox 200 200   chrome 200 200
      homedepot.com    firefox 200 200   chrome 200 200
      quora.com        firefox 200 200   chrome 200 200

etsy is DataDome too and Chrome passes it. So this is **yelp's configuration
specifically**, not a vendor behaviour and not a general cost of looking like
Chromium. One site, one address, one afternoon.

### What is established and what is not

Established: yelp challenges Chromium-shaped clients and serves
Firefox-shaped ones, from here, today, repeatably, across four independent
Chromium implementations. Not our profile's defect.

Not established: whether a **real** Chrome passes yelp. If it does, every
Chromium impersonation shares a tell none of them has found. If it does not,
yelp simply challenges Chrome users and there is nothing to fix. That is one
browser visit, and it is the only question here worth the next measurement.

The useful thing either way: which browser you choose to impersonate is a
decision with a measurable cost, and the industry default of Chrome is not
free. Nobody tests that because nobody has two profiles measured the same
way.

## 2026-10-08 — Four hypotheses eliminated, and the tell not found

A real Chrome loads yelp.com normally. That is the fact that reframes
everything: it is not that yelp challenges Chrome users, it is that yelp
detects Chrome *impersonations*. Four of them -- ours and three of
curl_cffi's, all made platform-consistent -- get the DataDome challenge while
our Firefox profile is served.

Which constrains the answer sharply. Whatever the tell is, it must be
something our Firefox gets right, our Chrome gets wrong, and curl_cffi's
Chromium also gets wrong. That excludes:

- **Behaviour.** Both our profiles do the same thing: one bare request to a
  homepage, no subresources, no referer chain, no think time. If that were
  the signal, Firefox would fail too.
- **The TCP/IP layer.** Same machine, same stack, and the real Chrome that
  passes shares it.
- **The HTTP/2 frame sequence.** Measured, after `catch_h2.py` was taught to
  log every frame rather than the six types it had branches for. Chrome
  sends `SETTINGS`, `WINDOW_UPDATE`, `HEADERS` -- stream 1, flags 0x25 --
  and so do we, identically. No `PRIORITY_UPDATE`, no ALPS exchange, which
  were the two leading guesses and are both wrong. Advertising
  `application_settings` without speaking the protocol is apparently not
  what gives us away.
- **`Cache-Control: max-age=0`**, the reload artefact baked into the Chrome
  captures. Removing it changed nothing, 0 of 4 either way.

And one experiment that establishes nothing, recorded because it looked
decisive: a 2x2 crossing TLS against headers refuses both mixed arms. That
is not layer isolation, because a Chrome hello carrying a Firefox User-Agent
is itself the contradiction these systems hunt for. Crossing the layers adds
a third variable.

### The shuffle, which cannot be tested with six captures

The best remaining idea was that Chrome's extension order is drawn and
nobody reproduces the draw: we shuffle uniformly, curl_cffi does not shuffle
at all, and Firefox has no order to get wrong because its order is fixed and
copied exactly. It explains the whole pattern.

It is also not supported. Across the six captures, the positions each of the
eighteen shuffled extensions occupied:

      psk_key_exchange_modes   [10, 6, 5, 10, 5, 6]    span 5-10
      server_name              [8, 10, 15, 8, 12, 11]  span 8-15
      signature_algorithms     [17, 0, 17, 11, 13, 17] span 0-17
      ...

Every span is wide and the narrowest covers six positions, which six samples
make unremarkable. The draw looks uniform. That does not prove it is -- six
samples cannot -- but there is no evidence against it, and inventing
structure to fit a theory is the thing this notebook exists to prevent.

### The visit happened, and every fingerprint matches

A real Chrome 155 against the same service, compared field by field rather
than by eye:

      ja4                 identical
      ja4_r               identical
      peetprint_hash      identical
      akamai_fingerprint  identical
      session id length   identical
      HTTP/2 header order identical
      HEADERS priority    identical, weight 256 exclusive depends_on 0

`ja4_r` is the informative one: the raw sorted form, every cipher, extension
and signature algorithm spelled out. It matches. So does the `trust_anchors`
payload, 186 bytes byte for byte, and the greased ECH payload length, 144,
which is one of the three this profile draws from.

Our Chrome hello is indistinguishable from a real Chrome's on everything
peet.ws knows how to compute. And yelp still refuses it.

### Two more eliminations

**The locale.** The one value deliberately changed from the capture: real
Chrome sends `en-MX,en-GB;q=0.9,...` from a Mexican address and this profile
sends `en-US,en;q=0.9`. Sending the captured locale instead: 0 of 3 either
way, and Firefox 3 of 3 either way.

**The shuffle**, which was the best remaining idea and is now gone. `ja4_r`
and `peetprint` both sort the extension list, so the wire order is the one
thing about the hello that none of the matching hashes capture -- which made
the drawn order the obvious suspect. Replaying three *real captured orders*
verbatim instead of drawing one: 0 of 2 each. The order is not it.

### Then the answer was in a sentence I had already been given

Ernesto's report was "me sale la pagina normal en chrome verifica y carga" --
the page comes up in Chrome, it verifies and loads. I read that as *no
challenge* and spent six hypotheses on the difference between a browser that
passes and clients that do not.

**"Verifica."** If a verification screen appears before the page, then real
Chrome is challenged too and gets through by running the JavaScript. Every
observation then fits with nothing left to explain:

      real Chrome         challenged, solves it, loads
      our Chrome          challenged, cannot solve it, 403
      curl_cffi Chromium  challenged, cannot solve it, 403
      our Firefox         not challenged, 200

There is no tell. The profile is correct. yelp challenges Chromium-shaped
clients and serves Firefox-shaped ones, and a JavaScript challenge is the
boundary this project established hours earlier against Cloudflare: no
fingerprint passes one.

Pending his confirmation that a verification screen did appear, because
building on a second misreading would be worse than the first.

### The lesson, which is not a technical one

The most expensive mistake today was misreading a one-line report from the
person holding the browser, and not asking what an ambiguous word meant. Six
hypotheses, each properly tested and properly eliminated, all downstream of
treating "verifica y carga" as "loaded without a challenge".

The eliminations are not wasted -- the profile is now verified against a real
Chrome field by field, which it was not before, and five things that could
have been wrong are known not to be. But the question they were answering was
one I had invented. Measuring carefully in the wrong direction is still the
wrong direction, and the cheap guard against it was one clarifying question.


## 2026-10-08 — yelp, confirmed

Asked directly, and the answer is yes: a verification screen appears before
the page loads in his own Chrome, as an ordinary human visitor.

So the table from the previous entry is the explanation and not a
hypothesis. yelp challenges Chromium-shaped clients, a real Chrome passes by
running the JavaScript, and our Chrome and curl_cffi's Chromium both fail at
the same wall for the same reason. There is no tell in the profile, which is
consistent with every fingerprint matching a real Chrome 155 field by field.

The question is closed, and it was closed by asking one question that could
have been asked before the six hypotheses rather than after them. The six
eliminations stand as verification of the profile, which is worth having,
but they were not the way to the answer and were never going to be.

Nothing to change in the code. `docs/chrome.html` now states this as
established rather than as the reading that fits.


## 2026-10-08 — A host where the transport decides, measured

Ernesto asked the question that undid the HTTP/3 result as it stood: if
httpx got a 200 from the same host, what would our h3 200 have told us?
Nothing. "Seven of seven hosts connect" is a correctness check wearing the
clothes of a result -- it says the QUIC stack works and nothing about
whether speaking h3 changes what a server decides.

So the transport became an arm. `ab_test.py --arms pybrws pybrws-h3 httpx`,
where the pair that can answer anything is pybrws against pybrws-h3, since
it is the only one whose single variable is the transport. pybrws-h3
against httpx moves fingerprint and transport together, which is the same
confound that made the 2x2 layer crossing useless during the yelp work.

### What the probe established first

Of six real targets only one is usable: `www.indeed.com` answers over both.
Three do not speak h3 at all, `www.etsy.com` has no h3 and blocks anyway,
and `www.g2.com` advertises h3 and then does not serve it -- the second
host in this project to do that, after tls.peet.ws. Advertising is not
serving, and the probe decides by connecting.

### The result, four interleaved rounds

      host                 pybrws      pybrws-h3   httpx
      www.indeed.com       0/4         4/4         0/4
      cloudflare-quic.com  4/4         4/4         4/4
      www.crunchbase.com   4/4         0/4         4/4   (control)

No flapping in any cell. The httpx arm is what makes the indeed row mean
something: the host does discriminate, so the other two arms are measuring
a decision rather than an open door.

### Two ways it could still have been nothing, both checked

**The status could have been hiding a soft block.** A challenge page is a
200. `tools/show_transport.py` now prints what each transport actually
received:

      www.indeed.com  h2   403  27,709 B  "Security Check - Indeed.com"   captcha
      www.indeed.com  h3   200 592,001 B  "Bolsa de trabajo ... Indeed Mexico"

A real page, not an interstitial.

**The h3 arm had been redirected.** It ended at `mx.indeed.com`, so the
obvious alternative was that the Mexican host is simply unprotected and the
transport had nothing to do with it -- the TCP arm never saw the redirect
because it was challenged first. Fetching `mx.indeed.com` directly:

      mx.indeed.com   h2   403  27,708 B  "Security Check - Indeed.com"
      mx.indeed.com   h3   200 591,241 B  the page

Same host, same URL, no redirect. The alternative is dead.

### And a defect the control exposed

`crunchbase` reads 0/4 in the h3 column and is not blocking anything: it
does not speak h3, so the connection is refused. The tool was scoring
"could not connect" as "was refused", which means any host without HTTP/3
would have printed `*** served over h2, blocked over h3 ***` -- the mirror
image of the finding being hunted, manufactured by the instrument. Fixed:
an arm that never received an HTTP response is reported as unreachable.

That is twice now that the control has earned its place by failing in a
way that revealed the measurement rather than the target.

### What this does and does not establish

It establishes that on indeed.com, our Firefox-over-QUIC presentation is
served where our Firefox-over-TCP presentation is challenged, deterministic
over four rounds, with a plain client challenged too.

It does not establish that QUIC as such is the discriminator. The QUIC
profile differs from the TCP one in more than transport: three cipher
suites rather than fifteen, a drawn extension order rather than a fixed
one, three extensions absent, and its own header set. "The transport" here
means the whole presentation that goes with it.

Nor does it establish whose fault the TCP refusal is. The decisive test is
a real Firefox with `network.http.http3.enable` set false: if a genuine
browser over TCP also gets the Security Check, indeed is challenging TCP
broadly and our fingerprint is not the reason. If it sails through, the
TCP profile has a tell that the QUIC one does not. Not run yet.

One host, one machine, one address, one day.


---

## 2026-10-08 — An oracle that is not ours

Every instrument in this repo until now was one we wrote. `catch_hello.py`,
`catch_h2.py` and `catch_quic.py` report what arrived at a server we
control, parsed by a parser we control, against a capture we took. That
answers "what did we put on the wire", which no third party will tell you,
and it cannot answer "does the real world see Firefox".

`thumbprint.me/api/v1/probe` reflects the caller's own fingerprints as JSON
and serves HTTP/3, which makes it the first external party that can be asked
the QUIC question at all. `tools/probe_fingerprint.py` asks it over both
transports and puts the answers side by side. Fields are discovered, not
assumed: the response is flattened to dotted paths, so a schema change
prints rather than breaks.

**The TCP JA4 matched character for character.** `t13d1517h2_8daaf6152771_`
`3cbfd9057e0d`, identical to what our own server reported. Someone else's
edge, someone else's parser, across a real network path.

**The QUIC JA4 confirms externally what only our parser had claimed.**
`q13d0315h3_55b375c5d22e_dc5437974b47`, with `ja4_r` listing the suites as
`1301,1302,1303`. Three where the TCP arm sends fifteen. "QUIC forbids TLS
1.2 so the list collapses" had been resting on our own reading of our own
bytes.

**The unexpected part: the service keeps its own captures of real browsers**
with client, version and OS provenance, and reports how many of its recorded
sessions share each of our fingerprints.

| Signal | Matching sessions | Identities |
|---|---|---|
| TLS ClientHello, TCP | 29 | firefox 152.0.5 … 155.0.1 |
| TLS ClientHello, QUIC | 103 | firefox 153.0 … 156.0 |
| HTTP/2 settings | 11 | firefox |
| QUIC transport parameters | 18 | firefox 155.0.1, 156.0 |
| Request headers | 10 | firefox |

This is a different claim from anything we had. Not "we reproduced our own
capture" but "we collide with other people's Firefoxes, on other machines,
across five versions, at four layers independently".

**What it does not establish.** The identities stop at 156; from this
response alone there is no way to tell whether the catalogue holds no 157
capture or whether 157 sends something different. One fingerprint shared by
five versions is evidence that the shape does not move per release, which
favours the first, but it is a reading. `/api/v1/catalog` would settle it and
is 5 MB, so it needs a script rather than a glance. And it is one service's
capture set.

**`tcp_family: Windows`, `tcp_ja4t 65535_2-1-3-1-1-4_1412_8`.** We never
wrote a SYN. This is the kernel's, and it comes out consistent for free
because the profile claims the OS we are running on. The inverse is a real
exposure: the same profile on Linux would present a Linux SYN under a
Windows User-Agent, and no layer we control could fix it from userland. MSS
1412 is this link, not Firefox.

### The ja4h difference, diagnosed offline

`ja4h` differed between the arms beyond the version digit: `ge20nn11enus_`
`3901d4197baf` against `ge30nn11enus_c87d53636918`. Same method, no cookie,
no referer, eleven headers each, `en-US` each.

Diffing the two lists in the profiles needed no network. The difference is
two headers: the HTTP/2 set ends with `te: trailers`, which HTTP/3 does not
carry; the HTTP/3 set has `Alt-Used` after `accept-encoding`, which TCP does
not. Same count, different names and positions, so a different hash. Both
were measured from real captures. Not a bug.

The residual is the one already noted in `firefox157_quic.py`: Firefox sends
`Alt-Used` because it reached h3 via `Alt-Svc` on an earlier TCP connection.
This client dials QUIC directly, so it announces having used an alternative
service that was never offered to it. A server knows whether it ever
advertised h3 to that address. Every header individually correct, the
combination describing something that did not happen. indeed did not care —
it served the QUIC arm 4/4.

This is the shape of what is left. The single-layer work is done; what
remains is consistency *between* layers, which is not a layer further down.

### Correction: a number in a published post was never measured

`docs/firefox.html` claimed "ten of twelve sites that had been refusing
started serving", in the TL;DR, in the results section, and as "two of the
twelve never budged". There is no twelve-site run anywhere in this notebook.
The count was residue from an invented opening anecdote that was removed
from `firefox.html` and survived intact in `docs/index.html` ("a dozen URLs
to fetch once a day, four of them returned 403").

Both are gone. The posts now carry the measured results instead: ten hosts
served here and refused to httpx over three to four interleaved rounds with
`crunchbase.com` as a serving control, the four candidates rejected from the
sweep named individually, and g2 as a site that wins. The irony is not lost:
the post arguing that a self-built oracle proves nothing was itself carrying
a number with no oracle at all.

---

## 2026-10-08 — The catalogue answers both questions, and one answer is a defect

`/api/v1/catalog` holds 849 sessions with client, version and OS, and the
raw per-capture lists behind each hash. `tools/catalog.py` reads it.

**Firefox: confirmed, including 157.** Our `t13d1517h2_8daaf6152771_`
`3cbfd9057e0d` appears in thirty catalogued sessions: firefox 157.0, 156.0.1,
156.0, 155.0.1, 155.0, 154.0.1 and 154.0, on Windows, macOS and Linux. So
the hello does not move across four releases and carries no trace of the
operating system — the SYN underneath carries that, and reported `Windows`
about this machine without being asked. The caveat written into
`docs/firefox.html` earlier today, that the identities stopped at 156, is
answered and removed.

**Chrome: the hypothesis was wrong and the defect is ours.** Their newest
capture is 155.0.8059.39, the exact version this profile models, with 110
Chrome sessions across 40 versions. "Their captures predate us" is dead.

| | extensions in JA4_c order |
|---|---|
| chrome 155, fresh | `…0023,002b,002d,0033,44cd,ca34,fe0d,ff01` |
| chrome 155, resumed | `…0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01` |
| this profile | `…0023,002b,002d,0033,`**`12e0`**`,44cd,ca34,fe0d,ff01` |

We are Chrome 155's fresh hello plus one extension. The `1518` that looked
like a matching count was a coincidence: their eighteenth is `0029`,
`pre_shared_key`, which makes it a resumption hello. Ours is `0x12e0`.

**`0x12e0` appears zero times in 5.2 MB of catalogue**, against 2,346
occurrences of `0x44cd` and 462 of `0xca34`. Not in any Chrome, Chromium,
Edge, Safari or library session.

**What it is not.** Not GREASE: `GREASE_DRAW` holds the sixteen reserved
values and 0x12e0 is not one, and the service strips GREASE correctly
elsewhere in the same response. Not the NordVPN interception either — that
re-originated with OpenSSL's twenty-seven doubled suites, and this capture
carries BoringSSL's fifteen with `acb858a92679`, the same original-order
cipher hash real Chrome 155 produces. The capture is a genuine Chrome.

### An instrument that should have existed from the start

Every JA4 in this project until now came from a server. `tools/ja4.py`
computes it from a profile locally, which makes a counterfactual answerable
without a request. Its `--self-test` reproduces three values measured by
thumbprint, two from real Chrome captures, so the arithmetic is checked
rather than assumed.

    chrome155                    t13d1518h2_8daaf6152771_4980c97edce0
    chrome155 --drop 0x12e0      t13d1517h2_8daaf6152771_cb7bf5808d99

The second is real Chrome 155's fresh hello exactly. `0x12e0` is the only
difference there is. It also recomputes firefox157's JA4 to the value
thumbprint measured over the network, which is a fourth independent check on
that profile.

### What this costs, and the test that decides it

A fingerprint shared with nobody is worse than one that is slightly stale.
"Chrome 155 except for an extension no Chrome sends" is a better
discriminator for a detector than either a real Chrome or a plain Python
client, because it is unique.

But the six captures all contained it, so deleting it on the strength of
somebody else's catalogue would be throwing away a measurement in favour of
a consensus. Their 110 Chrome sessions are all headless, which is one
configuration, and Chrome gates new TLS extensions behind randomised field
trials that a fresh CI container may not join.

The test is one page load: open Chrome on this machine and fetch
`thumbprint.me/api/v1/probe`. If that browser reports `1518` with `12e0`,
this profile is a faithful copy of this Chrome and the question becomes
which Chrome to imitate. If it now reports `1517` without it, the extension
came and went and the profile should follow. Either answer is actionable;
guessing is not. Not run yet.

---

## 2026-10-08 — The Chrome profile was right, and the catalogue is the odd one

Loaded thumbprint.me in a real Chrome window on this machine. Its
cross-transport view reports, over TCP:

    TLS ClientHello (JA4)   t13d1518h2_8daaf6152771_4980c97edce0

That is this project's chrome155 profile exactly, which `tools/ja4.py`
computes offline from the profile and which the probe measured over the
network. Three sources, one value: the browser, the service, and our own
arithmetic.

So the entry above is corrected. `0x12e0` is not a defect and nothing
should be deleted. The profile reproduces a real Chrome.

**What is actually unusual is the catalogue.** Their page labels the QUIC
transport parameters and the HTTP/2 frame fingerprint `Match`, and labels
neither JA4 row. This machine's *real browser* is also absent from their
849 sessions. Their 110 Chrome captures are all headless, 27 of them on
Windows, and none carries `0x12e0`.

Which leaves a question worth more than the one it replaced. Either
headless Chrome omits `0x12e0`, making it a headless tell readable at the
TLS layer with no JavaScript anywhere, or this install joined a randomised
field trial that fresh CI containers do not. The first would be a finding;
the second would mean our profile copies one Chrome population rather than
Chrome.

`tools/headless_tell.py` decides it on this machine, where the binary, the
version, the field trial state and the network are all held constant and
only the window changes. Not run yet.

**Two smaller readings from the same page.**

The locale difference is deliberate and behaved as designed. The browser
sent `ge20nr12enmx_54b4638ab28b`; this client sends `enus`. The profile
holds `CAPTURED_ACCEPT_LANGUAGE` as `en-MX,...` for the fixture tests and
ships `en-US,en;q=0.9`, on the grounds that a header meant to blend in
should not announce one particular machine in Mexico. The header-name hash
`54b4638ab28b` is identical to the catalogue's Chrome 155, and this
client's `0c2c1d640f3e` is the catalogue's no-referer 13-header variant, so
both header sets are real Chrome sets for their respective request kinds.

And their Linux `python-httpx 0.28.1` reports
`t13d1713h1_ab0a1bf427ad_ecd0401ec68b`. The cipher hash is identical to the
httpx value measured here, confirming those seventeen suites from outside;
the extension count differs, 13 against 12, because their OpenSSL sends
`encrypt_then_mac` and the one Python ships on Windows does not. The README
comparison should say that value is a Windows reading.

`ecd0401ec68b` is also the third hash of the NordVPN interception recorded
on 2026-10-07. The middlebox's extension and signature-algorithm set is a
stock OpenSSL client's, which confirms that diagnosis from a dataset that
had nothing to do with it.
