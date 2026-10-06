# pybrws

A from-scratch HTTPS client in Python that emits a ClientHello byte-identical
to a real browser's.

## Does it work

Measured against sites that serve a plain Python client a block page, one GET
each, repeated twice with identical results. `httpx` is a mature HTTP/2 client
over the stdlib TLS stack; `pybrws` differs from it only in protocol
fingerprint.

| Host | Protection | httpx | pybrws |
|---|---|---|---|
| www.zillow.com | CloudFront | 403, 5.7 KB block page | **200, 433 KB real page** |
| www.ticketmaster.com | - | 403, 20 bytes | **200, 562 KB real page** |
| www.indeed.com | Cloudflare | 403, 25 KB block page | 302 redirect |
| www.glassdoor.com | Cloudflare | 403 | 308, then **200, 684 KB** when followed |
| www.g2.com | Cloudflare | 403 | 403 |
| www.etsy.com | DataDome | 403 | 403 |
| www.crunchbase.com | Cloudflare | 200 | 200 |

Four of the six discriminating targets stop blocking. Two do not: a Cloudflare
site at a stricter setting and a DataDome site, both of which want signals this
client cannot produce.

Caveats worth stating. A single client IP, so address reputation is an
uncontrolled variable. No JavaScript challenge is solvable here by
construction, so any site that issues one is out of reach regardless of
fingerprint.

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
- [x] **Gold** — byte-identical plus matching HTTP/2 fingerprint and header
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
| 4 | HTTP/2 frames, SETTINGS and header order | done |
| 4b | HTTP/1.1, for hosts that do not offer h2 | done |
| 5 | curl-style CLI | done |
| 6 | Proxy sidecar for other languages | done |

Phases 0 through 2 are standard library only.

    pip install cryptography hpack brotli

## Usage

All commands assume the project virtualenv is active:

    .venv\Scripts\activate        # Windows
    source .venv/bin/activate     # macOS, Linux

Capture a ClientHello (see `fixtures/README.md` for the hostname requirement):

    python tools/catch_hello.py fixtures/firefox.hex

Run the tests:

    python -m unittest discover -s tests -t . -v

Fetch a URL:

    python -m pybrws https://example.com/
    python -m pybrws -IL https://www.glassdoor.com/
    python -m pybrws -H 'Accept-Language: es-MX,es;q=0.9' -o page.html https://www.zillow.com/

Lend the fingerprint to another language, with no change to its code:

    python -m pybrws.proxy
    HTTPS_PROXY=http://127.0.0.1:8080 node --use-env-proxy -e "fetch('https://tls.peet.ws/api/all')..."
    curl -k -x http://127.0.0.1:8080 https://tls.peet.ws/api/all

The proxy terminates TLS rather than tunnelling it, so the caller must trust
the CA it prints on startup, or skip verification. A plain CONNECT tunnel
would leave the caller performing its own handshake, which is the fingerprint
this project replaces.

Compare the live fingerprint against the reference capture:

    python tools/verify.py
