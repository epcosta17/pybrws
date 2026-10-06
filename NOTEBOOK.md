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
