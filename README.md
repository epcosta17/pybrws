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

- [ ] **Bronze** — JA4 identical to real Firefox
- [ ] **Silver** — ClientHello byte-identical, excluding `random` and the
      `key_share` public key, which vary per connection
- [ ] **Gold** — byte-identical plus matching HTTP/2 fingerprint and header
      order, verified against `tls.peet.ws/api/all`

## Scope, v1

- Target: Firefox with post-quantum key agreement disabled via `about:config`.
  `X25519MLKEM768` support is future work.
- **Certificates are not verified.** This is a laboratory client, not a secure
  one. Do not use it for anything real.
- No renegotiation and no session resumption.

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | ClientHello parser and differ | in progress |
| 1 | Reference capture of real Firefox | pending |
| 2 | ClientHello emitter | pending |
| 3 | Full handshake (`cryptography` for primitives) | pending |
| 4 | HTTP/2 frames, SETTINGS and header order (`h2`) | pending |
| 5 | curl-style CLI | pending |
| 6 | CONNECT proxy sidecar for other languages | pending |

Phases 0 through 2 are standard library only. Phase 3 requires `cryptography`,
phase 4 requires `h2`.

## Usage

Capture a ClientHello (see `fixtures/README.md` for the hostname requirement):

    python tools/catch_hello.py fixtures/firefox.hex

Run the tests:

    python -m unittest discover -s tests -t . -v
