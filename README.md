# pybrws

A from-scratch HTTPS client in Python that emits a ClientHello byte-identical
to a real browser's.

## Does it work

`tools/ab_test.py`, four interleaved rounds per target, both clients
following redirects, with crunchbase.com as a negative control. `httpx` is a
mature HTTP/2 client over the stdlib TLS stack, running with `http2=True` and
verified to negotiate it; `pybrws` differs from it only in protocol
fingerprint.

The protection column is **detected, not assumed** -- `tools/detect_waf.py`
reads each vendor's own markers out of the response, which corrected two
rows here. It says which vendor is *present*, which is not the same as which
one is enforcing: a vendor can sit in front of a site with bot protection off
or in monitor mode, so presence explains nothing on its own. What the two
result columns do is measure enforcement directly.

| Target | Protection (detected) | httpx | pybrws |
|---|---|---|---|
| www.zillow.com | CloudFront | 0/3 served | **3/3 served** |
| www.etsy.com/c/jewelry | DataDome, Fastly | 0/3 | **3/3** |
| www.yelp.com | DataDome, Fastly | 0/3 | **3/3** |
| www.homedepot.com | Akamai | 0/3 | **3/3** |
| www.macys.com | Akamai | 0/3 | **3/3** |
| www.sephora.com | Akamai | 0/3 | **3/3** |
| www.stubhub.com | CloudFront | 0/3 | **3/3** |
| www.quora.com | Cloudflare | 0/3 | **3/3** |
| www.ticketmaster.com | Fastly | 0/4 | **4/4** |
| www.indeed.com | Cloudflare | 0/4 | **4/4** |
| www.etsy.com/ | DataDome, Fastly | 0/4 | 0/4 |
| www.g2.com | Cloudflare **and DataDome** | 0/4 | 0/4 |
| example.com | - | served | served (control) |

Ten of twelve discriminating targets stop blocking, across four protection
vendors, with no flapping in any cell. What still blocks is specific rather
than general: on etsy the homepage and the search parameter `?q=` are refused
while an ordinary category page is served, so the strictest rules sit on the
endpoints worth scraping.

Both corrections came from measuring instead of remembering. ticketmaster was
listed as unprotected and is behind Fastly. g2 was listed as Cloudflare and
carries DataDome as well -- which matters, because g2 is one of the two
targets that still blocks us, and two vendors in series is a better account
of that than one.

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
    # or, the same thing: pip install -r requirements.txt
    .venv/bin/python -m unittest discover -s tests -t . -v

Two things are tied to the machine the references were captured on, which was
Windows:

- **`tools/verify.py` checks `tcpip.p0f`** against a capture taken from
  Windows on one network. That one check fails on another operating system,
  and also on the same machine behind a VPN or a carrier NAT, since what it
  measures is whichever TCP stack last touched the packet. Observed during
  development: the egress address changed and the signature went from
  Windows to Linux while the other seventeen checks kept passing. It is
  below the socket, so it is not something this client controls.
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
- **Certificates are verified**, chain and CertificateVerify signature, with
  `verify=False` or the CLI's `-k` to opt out. It was off for most of this
  project's life, and one of two working free proxies tested during that time
  turned out to be intercepting and replacing the fingerprint undetected.
- **TLS 1.2 is implemented**, ECDHE with AES-GCM and ChaCha20-Poly1305, which
  is every suite a current server picks. The profile offers twelve because
  Firefox does; the CBC and static-RSA ones are refused by name if a server
  chooses one, which no server tested does. `extended_master_secret` is
  implemented because Firefox asks for it, and a server that echoes it
  derives that way.
- **A client certificate request is answered**, with an empty Certificate and
  no CertificateVerify, which is what a browser holding none does. Asking is
  itself a bot check: the server does not need the certificate, it wants to
  see what an unexpected message does to the client.
- Session resumption is implemented and is a `Session`'s default, which
  is also a gap: a resumed ClientHello carries `pre_shared_key` and so a
  second JA4, and no capture covers it yet.
- No renegotiation.

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
| 10 | Session resumption, PSK binders | done |
| 11 | Streaming responses, incremental decoding | done |
| 12 | Reading a ClientHello out of QUIC Initial packets | done |
| 13 | Firefox's ClientHello over QUIC, via aioquic | done |
| 14 | HTTP/3 requests, measured against a real capture | done |
| 15 | TLS 1.2, for the hosts that decline 1.3 | done |
| 16 | A second browser profile, to test the abstraction | done |

Phase 16 is the one that mattered to the design. `profiles/` had two
implementations and both were Firefox, so it was an abstraction shaped by one
browser. Chrome broke it, which is what it was for: Chrome draws its
extension order per connection, so a profile cannot be an ordered list, and it
greases six separate lists, so a cipher list cannot be a constant. Both are
now things a profile may be rather than things it must be -- and Firefox keeps
its stored order, because a stored order is a stronger claim than a drawn one
and flattening them would discard what was measured.

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
    post("https://example.com/login", data={"u": "x"}, kind="form")  # a clicked form
    get("https://example.com/", headers={"Accept-Language": "es-MX", "Priority": None})

Fetch many URLs across several connections:

    from pybrws.pool import Fetcher
    with Fetcher(concurrency=8) as fetcher:
        for result in fetcher.fetch_all(urls):
            print(result.status, result.url)
    # errors come back as results rather than stopping the batch;
    # the cookie jar and the ticket store are shared across workers

Put several requests on one connection at once:

    from pybrws.handshake import connect
    from pybrws.http2 import Http2Connection
    with connect("httpbingo.org") as tls:
        http = Http2Connection(tls)
        for response in http.request_many(
            [("GET", "/delay/1", "httpbingo.org")] * 6
        ):
            print(response.status)
    # six one-second requests in 1.1s rather than 6.6s

Keep cookies and connections across requests:

    from pybrws.session import Session
    with Session() as s:
        s.get("https://httpbingo.org/cookies/set?demo=1")
        print(s.get("https://httpbingo.org/cookies").text())
        # {"cookies": {"demo": "1"}} - sent back over the same connection

Read a large response without holding it in memory:

    from pybrws.client import stream
    with stream("https://www.etsy.com/c/jewelry") as (response, chunks):
        for chunk in chunks:
            out.write(chunk)
    # a 1.0 MB document: 0.68 MB peak against 2.67 MB buffered, 4.0x less

Chunks are decompressed as they arrive, which is the part worth testing:
gzip, brotli and zstd all carry state across a chunk boundary, so a chunk
is not a valid stream on its own. A body that stops early raises rather
than returning the prefix, because a silently short document reads exactly
like a page that changed.

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

Speak HTTP/3 with Firefox's ClientHello:

    import asyncio
    from aioquic.asyncio import connect
    from pybrws import quic_impersonate

    quic_impersonate.install()

    async def main():
        host = "cloudflare-quic.com"
        config = quic_impersonate.configuration(host)
        async with connect(host, 443, configuration=config) as connection:
            await connection.wait_connected()

    asyncio.run(main())

The hello matches the capture at 1931 bytes, and seven hosts out of seven
connect, six of them selecting X25519MLKEM768. aioquic provides the transport
and knows nothing about impersonation; five of its private functions are
patched to carry the profile, each named in `pybrws/quic_impersonate.py` and
each asserted by a test, so an upgrade breaks a test rather than a
connection. The handshake is done and the request path is not: there is no
`client.get` over QUIC yet, and no measurement of what Firefox puts in an
HTTP/3 request, which is QPACK rather than HPACK and a separate fingerprint.

Two of those patches exist only because the impersonation works. Asking for
`compress_certificate` because Firefox does means servers reply with an RFC
8879 compressed certificate, which aioquic names and does not handle; and
Firefox's connection ids are asymmetric, three bytes out and at least eight
in, where aioquic has one setting for both.

Recover a browser's ClientHello from a QUIC capture:

    # capture UDP 443 while the browser visits a site that speaks HTTP/3
    python tools/read_quic.py capture.pcapng --host www.google.com
    python tools/read_quic.py capture.pcapng --all

`--all` groups the connections by extension set before saying anything about
order, because a capture of port 443 holds whatever the machine was doing.
That matters here: over QUIC Firefox **shuffles its extension order per
connection**, which is the opposite of its behaviour on TCP -- its QUIC stack
is neqo, in Rust, not NSS. Six captured connections gave six distinct orders
over identical sets, with only `quic_transport_parameters` and
`encrypted_client_hello` pinned at the end. Reading a second browser's
connections as the same client is what made that look like noise at first.

QUIC carries TLS 1.3 inside rather than running over it, and an Initial
packet is protected with keys derived from a salt published in RFC 9001 and
the connection ID its own header carries in the clear. So the ClientHello is
as readable there as it is on TCP, by anyone, with no server and no
certificate for a browser to object to -- and every extension-order question
this project answers for TCP applies unchanged.

Find out what a host is actually behind, from its own answer:

    python tools/detect_waf.py
    python tools/detect_waf.py --urls targets.txt --vendor imperva

Guessing which site uses which vendor is how a results table ends up
measuring something other than what it says, and it already corrected two
rows of the one above. It also found two bugs by accident: a host that asks
for a client certificate kills the handshake, and three hosts fail chain
validation.

Compare the live fingerprint against the reference capture:

    python tools/verify.py

Track how targets respond over time, against a plain client:

    python tools/ab_test.py
    python tools/ab_test.py --history

Separate the fingerprint from the address it comes from:

    python tools/isolate.py
