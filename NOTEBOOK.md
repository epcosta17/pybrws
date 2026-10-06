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
