# pybrws

A from-scratch HTTPS client in Python that emits a ClientHello byte-identical
to a real browser's.

## Does it work

`tools/ab_test.py`, four interleaved rounds per target, both clients
following redirects, with crunchbase.com as a negative control. `httpx` is a
mature HTTP/2 client over the stdlib TLS stack; `pybrws` differs from it only
in protocol fingerprint.

| Target | Protection | httpx | pybrws |
|---|---|---|---|
| www.zillow.com | CloudFront | 0/3 served | **3/3 served** |
| www.etsy.com/c/jewelry | DataDome | 0/3 | **3/3** |
| www.yelp.com | DataDome | 0/3 | **3/3** |
| www.homedepot.com | Akamai | 0/3 | **3/3** |
| www.macys.com | Akamai | 0/3 | **3/3** |
| www.sephora.com | Akamai | 0/3 | **3/3** |
| www.stubhub.com | CloudFront | 0/3 | **3/3** |
| www.quora.com | Cloudflare | 0/3 | **3/3** |
| www.ticketmaster.com | - | 0/4 | **4/4** |
| www.indeed.com | Cloudflare | 0/4 | **4/4** |
| www.etsy.com/ | DataDome | 0/4 | 0/4 |
| www.g2.com | Cloudflare | 0/4 | 0/4 |
| example.com | - | served | served (control) |

Ten of twelve discriminating targets stop blocking, across four protection
vendors, with no flapping in any cell. What still blocks is specific rather
than general: on etsy the homepage and the search parameter `?q=` are refused
while an ordinary category page is served, so the strictest rules sit on the
endpoints worth scraping.

g2 is worth its own line. It serves a request carrying any query string, and
so does httpx, so the query opens it for everybody and this client adds
nothing there. etsy refuses httpx with the same parameter. The same
observation means opposite things on the two sites, and only the baseline arm
tells them apart.

### The fingerprint is necessary and not sufficient

Those numbers come from a residential connection. Crossing the fingerprint
against the address, three rounds each, shows the two factors are not
independent:

| Target | pybrws direct | pybrws proxied | httpx direct | httpx proxied |
|---|---|---|---|---|
| www.zillow.com | **3/3** | 0/3 | 0/3 | 0/3 |
| www.crunchbase.com | 3/3 | 3/3 | 2/3 | 3/3 (control) |
| www.glassdoor.com | 0/3 | 0/3 | 0/3 | 0/3 |
| www.g2.com | 0/3 | 0/3 | 0/3 | 0/3 |
| www.etsy.com | 0/3 | 0/3 | 0/3 | 0/3 |

One cell passes. The browser fingerprint on a home connection; every other
combination is refused, including the same fingerprint through a commercial
static ISP exit. A proxy address sold as clean is itself a signal, and here
it was worse than an ordinary domestic line.

So this project buys one of two things a request needs, and `tools/isolate.py`
exists to keep that honest.

## Running it elsewhere

Python 3.14, or add the `zstd` extra: the profile advertises zstd because
Firefox does, so servers send it, and the decoder only reached the standard
library in 3.14.

    python -m venv .venv
    .venv/bin/pip install -e ".[client,dev]"     # .venv\Scripts\pip on Windows
    .venv/bin/python -m unittest discover -s tests -t . -v

Two things are tied to the machine the references were captured on, which was
Windows:

- **`tools/verify.py` checks `tcpip.p0f`** against a Windows Firefox capture.
  On any other operating system that one check fails while the other
  seventeen pass. The TCP stack is below the socket, so it is not something
  this client controls.
- **The profile says Windows.** Running it on a Mac leaves the TCP/IP layer
  saying macOS while every layer above says Windows, which is the
  cross-layer inconsistency this project is about. Either know it is there,
  or capture a macOS reference: `tools/catch_hello.py` and
  `tools/catch_request.py` both run anywhere, and the fixtures and profile
  are the only things that change.

The captured requests are stored with the CRLF that HTTP requires, pinned by
`.gitattributes`, so the byte-identity tests hold on every platform.

## Demo

`demo.ipynb` fetches one URL twice, with a plain client and with this one,
renders both results, and shows what the server saw. Outputs are stripped;
run it to fill them in.

    .venv/bin/jupyter lab demo.ipynb

Picking this up after a break, or on another machine: read `HANDOFF.md`.

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
  one. Do not use it for anything real. One of two working free proxies tested
  turned out to be intercepting, which this would have caught.
- **TLS 1.2 is advertised but not implemented.** The profile offers it because
  Firefox does, and removing it would change the fingerprint, so a server that
  declines TLS 1.3 is refused rather than downgraded to. httpbin.org is one.
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
| 7 | Outbound proxies, HTTP CONNECT and SOCKS5 | done |
| 8 | Sessions: cookie jar and connection reuse | done |
| 9 | Methods, request bodies, header merging | done |

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

Send a request, with a body and headers of your own merged into the profile's:

    from pybrws.client import get, post
    post("https://api.example.com/v1/items", json={"name": "x"})   # fetch headers
    post("https://example.com/login", data={"u": "x"}, kind="form")  # form headers
    get("https://example.com/", headers={"Accept-Language": "es-MX", "Priority": None})

Keep cookies and connections across requests:

    from pybrws.session import Session
    with Session() as s:
        s.get("https://httpbingo.org/cookies/set?demo=1")
        print(s.get("https://httpbingo.org/cookies").text())
        # {"cookies": {"demo": "1"}} - sent back over the same connection

Fetch a URL:

    python -m pybrws https://example.com/
    python -m pybrws -x socks5://user:pass@exit.example:1080 https://example.com/
    python -m pybrws -H 'Accept-Language: es-MX,es;q=0.9' -o page.html https://www.zillow.com/

Lend the fingerprint to another language, with no change to its code:

    python -m pybrws.proxy
    python -m pybrws.proxy --upstream socks5://user:pass@exit.example:1080
    HTTPS_PROXY=http://127.0.0.1:8080 node --use-env-proxy -e "fetch('https://tls.peet.ws/api/all')..."
    curl -k -x http://127.0.0.1:8080 https://tls.peet.ws/api/all

The proxy terminates TLS rather than tunnelling it, so the caller must trust
the CA it prints on startup, or skip verification. A plain CONNECT tunnel
would leave the caller performing its own handshake, which is the fingerprint
this project replaces.

Compare the live fingerprint against the reference capture:

    python tools/verify.py

Track how targets respond over time, against a plain client:

    python tools/ab_test.py
    python tools/ab_test.py --history

Separate the fingerprint from the address it comes from:

    python tools/isolate.py
