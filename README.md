# pybrws

A from-scratch HTTPS client in Python that emits a ClientHello byte-identical
to a real browser's.

## Clean-room rule

The problem is reconstructed without reading existing solutions.

Off limits: `curl-impersonate`, `uTLS`, `curl_cffi`, `tls-client`, `camoufox`,
and any write-up describing how they patched their TLS stacks. These are opened
only at the end, for the comparison section.

In scope: own packet captures, the RFCs (8446, 8701, 7540), `tls13.xargs.org`,
and the source of NSS, Firefox and OpenSSL.

## Completion criteria

- [x] **Bronze** — JA4 identical to real Firefox
- [x] **Silver** — ClientHello byte-identical, excluding `random` and the
      `key_share` public key, which vary per connection. Verified stronger:
      replaying a capture's own random material reproduces all 1901 bytes
- [ ] **Gold** — byte-identical plus matching HTTP/2 fingerprint and header
      order, verified against `tls.peet.ws/api/all`

## Scope, v1

- Target: Firefox 157 with default settings. Nothing is disabled, so the
  ClientHello carries a post-quantum `key_share`.
- `X25519MLKEM768` is implemented, not deferred. It turned out to be
  mandatory: a server that supports it rejects a malformed hybrid share, and
  rejects a ClientHello that advertises the group without offering a share by
  demanding it in a HelloRetryRequest. Four of six major sites tested select
  it.
- **Certificates are not verified.** This is a laboratory client, not a secure
  one. Do not use it for anything real.
- No renegotiation and no session resumption.

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | ClientHello parser and differ | done |
| 1 | Reference capture of real Firefox | done |
| 2 | ClientHello emitter | done |
| 3 | Full handshake (`cryptography` for primitives) | done |
| 4 | HTTP/2 frames, SETTINGS and header order (`h2`) | next |
| 5 | curl-style CLI | pending |
| 6 | CONNECT proxy sidecar for other languages | pending |

Phases 0 through 2 are standard library only. Phase 3 requires `cryptography`,
phase 4 requires `h2`.

    .venv\Scripts\pip install cryptography

## Usage

All commands assume the project virtualenv is active:

    .venv\Scripts\activate        # Windows
    source .venv/bin/activate     # macOS, Linux

Capture a ClientHello (see `fixtures/README.md` for the hostname requirement):

    python tools/catch_hello.py fixtures/firefox.hex

Run the tests:

    python -m unittest discover -s tests -t . -v
