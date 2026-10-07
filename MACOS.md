# Running this on a Mac

Written on the Windows machine where everything was measured, for whoever
picks it up on the Mac — most likely because a demo is minutes away and
something does not work. Diagnostic order, cheapest first. Each step says
what the answer means, not just what to type.

The short version: **the code is portable, the measurements are not.** Every
fixture came from Firefox 157 on Windows 11. Two of them cannot be right on
a Mac and one of those is not fixable.

## 0. Setup

    python3 -m venv .venv
    .venv/bin/python -m pip install -e ".[client,dev]"

`requires-python` is 3.11, but `compression.zstd` only arrived in the standard
library in 3.14. On anything older, add the `zstd` extra or brotli/zstd
responses raise `ContentEncodingError` — which looks like a network problem
and is not:

    .venv/bin/python -m pip install -e ".[client,dev,zstd]"

Then:

    .venv/bin/python -m unittest discover -s tests -t .

568 tests, no network needed for any of them. **If these fail, stop here** —
nothing further will make sense, and the most likely cause is the next
section.

## 1. If the byte-identity tests fail, it is line endings

The captured request fixtures contain the CRLF that HTTP requires. Git's
`autocrlf` will happily rewrite them, and then tests that compare bytes fail
on a Mac while passing on Windows. `.gitattributes` pins them:

    fixtures/reference-*.txt -text
    fixtures/reference-*.hex -text

This was verified once with a clean clone at `core.autocrlf=input`, so it
should hold. If it does not:

    .venv/bin/python -c "print(open('fixtures/reference-firefox-157-h1.txt','rb').read()[:80])"

Look for `\r\n`. If you see bare `\n`, the checkout is wrong rather than the
code:

    git rm --cached -r . && git reset --hard

## 2. The TCP/IP check will fail, and it is right to

`tools/verify.py` runs 18 checks against tls.peet.ws. On a Mac, 17 pass and
`tcpip.p0f` fails. That is correct and not fixable here.

The reference is `4:117+?:0:1400:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0`.
The `117` is a TTL that started at 128, which is Windows; macOS starts at 64.
The window scale and the TCP option order differ too. **None of this is
produced by this client** — it comes from the host's TCP stack, and there is
nothing in user space to imitate it with. The fixture says so in a `_note`.

So on a Mac: expect 17 of 18, and treat an 18th failure as the real signal.

## 3. The User-Agent claims Windows

    Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0

Running from a Mac, that declares Windows while the TCP stack says macOS.
A server comparing the two sees a contradiction, which is exactly the class
of signal that matters most — declaring one thing and demonstrating another.

In practice almost every scraper in the world runs on Linux declaring
Windows and gets away with it, so this is unlikely to break a demo. But if
targets that worked on Windows start refusing on the Mac, this is the first
thing to suspect, and the honest fix is a macOS-measured profile rather than
editing the string.

## 4. Is the ClientHello even the same on macOS?

**This is assumed, not measured.** NSS is the same code on both platforms so
the hello should be byte-identical given the same hostname, but nobody has
checked. Two minutes:

    .venv/bin/python tools/catch_hello.py /tmp/firefox-macos.hex

Open `https://pybrws.127.0.0.1.nip.io:4443/` in Firefox, accept the warning,
then:

    .venv/bin/python -c "
    from pybrws.differ import diff
    from pybrws.hexio import load_hex
    from pybrws.parser import parse_client_hello
    a = parse_client_hello(load_hex('fixtures/reference-firefox-157-windows-fresh.hex'))
    b = parse_client_hello(load_hex('/tmp/firefox-macos.hex'))
    print(diff(a, b) or 'identical as far as the differ is concerned')
    "

If it prints differences, the profile needs measuring on macOS and that is a
real finding worth writing down rather than working around. If it prints
identical, the assumption held and the only platform gaps are sections 2
and 3.

## 5. If a specific host refuses

Order of suspicion:

1. **Something is intercepting TLS.** This cost hours on Windows: NordVPN's
   Threat Protection was rewriting the browser's handshake *while the VPN was
   disconnected*. The tell is a hello with duplicated ciphers, an
   `encrypt_then_mac` extension, and no NSS markers. Check with
   `tools/verify.py` — if the live fingerprint does not match the fixture,
   something local is in the way before any target is to blame.

2. **It is a challenge, not a block.** Look for `cf-mitigated: challenge` in
   the response headers. A managed challenge challenges everything including
   a real browser, and no fingerprint passes it; that is the boundary of this
   project, not a bug in it.

3. **It wants TLS 1.2, or a client certificate.** Both are implemented. If
   either path errors, the message says which.

4. **Run the A/B before concluding anything.** `tools/ab_test.py` with four
   interleaved rounds. A single refusal means nothing: several findings in
   `NOTEBOOK.md` were retracted after more rounds dissolved them.

## 6. Demo notes

`demo.ipynb` needs `jupyterlab` from the `dev` extra. Section ordering
matters: the setup cell defines helpers the later sections use, so running a
section standalone without it fails for a reason that has nothing to do with
the client.

For HTTP/3, `aioquic` is in the `dev` extra and `pybrws/quic.py` deliberately
does not need it — there is a test asserting the library imports with aioquic
hidden. If HTTP/3 is part of the demo, install `dev`.

## 7. What is not portable, in one list

- `tcpip.p0f` in `verify.py` — host stack, unfixable here.
- The User-Agent string — measured on Windows.
- Nothing else is known to be platform-dependent. There is not a single
  `sys.platform` branch in `pybrws/`, and the trust store comes from
  Python's `ssl`, which works the same on macOS.

Read `HANDOFF.md` for the gap list and `NOTEBOOK.md` for why things are the
way they are, including the findings that were retracted. The retractions are
the useful part.
