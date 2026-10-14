# Adding a profile

This is descriptive, not aspirational: it is what was done for Firefox 157
and then for Chrome 155, including the two places where doing it the obvious
way produced a wrong answer. A profile is the set of constants that make up
one client's fingerprint, and the work is almost entirely measurement. The
module at the end is short.

## 0. A profile belongs to a transport

A browser does not send the same hello over TCP and over QUIC. `firefox157`
and `firefox157_quic` are separate modules for that reason, with different
cipher lists, a different `SESSION_ID_SIZE`, and transport parameters in one
and not the other. Sending the QUIC profile over TCP produces a hello no
browser has ever sent, so `cli.resolve_profile` refuses the cross and says
which table the name is in.

Decide which transport you are modelling before capturing, because it decides
which tool captures it.

## 1. Capture, and capture more than once

A browser pointed at `https://127.0.0.1:4443` sends **no** `server_name`
extension, because SNI carries hostnames and not addresses. JA4 encodes SNI
presence in its first field, so a capture taken that way is not a capture of a
real connection. Use a name that resolves to the loopback without touching
`/etc/hosts`:

    python tools/catch_hello.py fixtures/<browser>.hex --count 6

then open `https://pybrws.127.0.0.1.nip.io:4443/` in the browser and accept
the certificate warning. The handshake fails and the browser reports an
error; the ClientHello has already arrived. With `--count 6` the captures are
written as `<browser>-1.hex` through `<browser>-6.hex`.

**Six, not one.** One capture cannot tell a stored extension order from a
drawn one, and that single fact decides which kind of module you write.
Firefox gave one order in five captures; Chrome gave six in six.
Both are checkable from the committed fixtures, which is the point of
committing them:

    fixtures/firefox-*.hex   5 captures, 1 distinct order, 1 distinct set
    fixtures/chrome-*.hex    6 captures, 6 distinct orders, 1 distinct set

The other capture servers, for the parts a ClientHello does not contain:

| Tool | What it records |
|---|---|
| `catch_hello.py` | the ClientHello, over TCP |
| `catch_quic.py` | the ClientHello inside a QUIC Initial, and the HTTP/3 request headers |
| `catch_h2.py` | the HTTP/2 SETTINGS, WINDOW_UPDATE, priority and header order |
| `catch_request.py` | the HTTP/1.1 request, verbatim |
| `catch_resumed.py` | a fresh hello and a resumed one from the same browser |

## 2. Read the captures before writing anything

    from pybrws.hexio import load_hex
    from pybrws.parser import parse_client_hello
    print(parse_client_hello(load_hex("fixtures/x-1.hex")).summary())

Then diff two of them:

    from pybrws.differ import diff
    diff(parse_client_hello(load_hex("fixtures/x-1.hex")),
         parse_client_hello(load_hex("fixtures/x-2.hex")))

What differs between captures is per-connection. What does not is a constant.
**That partition is the profile.** Expect `random`, `session_id`, `key_share`
and the greased `encrypted_client_hello` payload to differ. If anything else
differs, that is a finding and it belongs in `NOTEBOOK.md` before it belongs
in a module.

## 3. Pick the kind of module

The branch is in `emitter.build_extensions`:

**Stored.** The module holds `EXTENSIONS`, a list of `(type, payload)` pairs
in wire order, where a payload is either bytes or a callable taking `ctx`.
This is Firefox over TCP, which sends the same order every time.

**Drawing.** The module holds `extension_order(ctx)` returning one
connection's order, and `payload_for(kind, ctx)` answering for one extension
at a time. This is Chrome on every protocol, and Firefox over QUIC.

Both kinds exist on purpose. A stored order is a stronger claim than a drawn
one, and collapsing both into a draw would throw away the distinction that
was measured.

## 4. The names the emitter requires

From `emitter.build_client_hello`:

| Name | Notes |
|---|---|
| `LEGACY_VERSION` | `0x0303` for everything current |
| `RECORD_VERSION` | the outer record's version, `0x0301` in both profiles |
| `SESSION_ID_SIZE` | 32 over TCP, **0** over QUIC |
| `COMPRESSION_METHODS` | `[0x00]` |
| `CIPHER_SUITES` | a list, or a callable taking `ctx` if the list carries a per-connection greased value |
| `EXTENSIONS` *or* `extension_order` + `payload_for` | section 3 |

Optional: `ech_growth_for_psk(psk_extension_size)`, which `emitter.with_psk`
calls to grow the greased ECH payload on resumption. By convention also
`NAME` and `USER_AGENT`.

A profile is **not only a ClientHello.** `firefox157` also carries
`H2_SETTINGS`, `H2_HEADERS_PRIORITY`, and header sets per request kind —
`H2_NAVIGATION_HEADERS`, `H1_HEADERS`, `H1_IMAGE_HEADERS`,
`H1_POST_FORM_HEADERS`, `H1_POST_XHR_HEADERS` and their HTTP/2 forms. A
profile that models only the TLS layer sends somebody else's headers, and
header order is as readable as a cipher list.

## 5. Per-connection values come from `ctx`, never from the module

- `ctx.random(n)` — bytes. Use this and not `os.urandom`: the rng is
  injectable, and that is what makes the byte-identity replay test possible.
- `ctx.choice(options)` — one of a measured set, e.g. an ECH `aead_id`.
- `ctx.once(key, factory)` — compute once per connection and reuse, for a
  value the order and the payload lookup must agree about.
- `ctx.grease(slot)` — a GREASE value, drawn once per slot per connection.

`grease` is memoised **by slot** because the draws are not all independent.
Chrome draws five independent values — first cipher suite, first signature
algorithm, first supported version, and both ends of the extension list — but
`supported_groups` and `key_share` share one, identical in all six captures,
which the protocol requires: the key_share entry has to name a group that was
offered.

If you draw a uniform index, reject rather than take a modulus.
`chrome155._below` exists because a modulus over a byte skews the low indices,
and over eighteen items that skew is measurable across enough connections — a
skew is itself a fingerprint.

## 6. Assert against the captures, not against what you typed

Copy the shape of `tests/test_chrome_profile.py`. Its docstring records that
writing it found two defects in the profile: a missing extension, and two
greased extension types that could collide. The tests worth having:

- there are N captures, and they are one extension set
- N distinct orders for a drawing profile; one order for a stored one
- every static payload equals the captured one
- the volatile extensions match the capture **in length**
- the extension count matches, because JA4's first field counts it
- every hello the profile produces has a length the browser produces

That last one is the test that caught the GREASE collision: two greased types
colliding made both take the first one's payload, giving a hello one byte
shorter than any capture. A length no browser produces is the cheapest
possible tell.

## 7. Check the fingerprint, offline first

    python tools/ja4.py --profile <name>
    python tools/ja4.py --profile <name> --drop 0x12e0

No network either way. `--drop` answers what the fingerprint would be without
one extension, which is how you test a hypothesis about a difference without
editing the profile. `ja4.py` hardcodes the `t` transport letter, because QUIC
profiles do not route through `build_client_hello`.

Then ask somebody else:

    python tools/probe_fingerprint.py --profile <name>

## 8. Register it

In `pybrws/profiles/__init__.py`, in `TCP` or `QUIC`. Putting it in the wrong
one is the mistake section 0 describes.

## The traps, all of them measured

**Your capture is one field-trial arm, not "the browser".** Chrome gates
features behind randomised trials whose state lives in the profile directory,
and extension `0x12e0` is one of them. A fresh `--user-data-dir` has not
joined the trial; the install you use by hand may have. So "Chrome 155's JA4"
is a distribution over arms, and the seed rotates on Google's schedule rather
than Chrome's release schedule. `tools/headless_tell.py` is the
seed-transplant experiment that settled it, and `docs/chrome.html` has the two
wrong conclusions it corrected.

**The greased ECH payload length may or may not follow the hostname.** It
stands in for an encrypted inner ClientHello which carries the real name, so
it easily could. Measured for Firefox 157: it does not. A 66-character name
grew the hello by exactly the 43 bytes the name added and the payload stayed
at 240. Measure it rather than assuming either way —
`ECH_PAYLOAD_SIZE` was fitted at one 23-character name, and every host
actually fetched has a different one.

**On resumption Firefox swaps `session_ticket` for `pre_shared_key`** instead
of appending it, so a resumed hello carries the same number of extensions as a
fresh one. Appending without dropping leaves you at eighteen against its
seventeen — `t13d1518h2` against `t13d1517h2`, a tell a server reads by
counting, without hashing anything.

**The PSK path also grows the ECH payload**, by about the size of one
`pre_shared_key`. `ECH_PSK_GROWTH_RESIDUAL = 1` is fitted to two observations
and the residual is still unexplained; what remains untested is a different
ticket length.

**Capture the headers over TLS, not cleartext.** Over cleartext Firefox
omits the `Sec-Fetch-*` headers and drops `br` and `zstd` from
`Accept-Encoding`, so a plaintext capture is not a valid reference for an
HTTPS client. `catch_request.py` serves a self-signed certificate for exactly
this reason.

**Post-quantum changes the sizes.** A `X25519MLKEM768` (`0x11EC`) key share is
1216 bytes: ML-KEM-768's 1184 plus X25519's 32.

**Something on your own path may be rewriting the handshake** before any
target sees it. `MACOS.md` §5.1 records NordVPN's Threat Protection rewriting
the browser's ClientHello *while the VPN was disconnected* — duplicated
ciphers, an `encrypt_then_mac` extension, no NSS markers. Run
`tools/verify.py` before blaming a profile or a target.

## What this does not cover

A new browser family may need emitter work rather than only a profile: Safari
and Edge are untried here, and the two profile kinds were sufficient for
exactly two browsers. If a third needs a third kind, that is a finding about
the abstraction and `build_extensions` is where it goes.
