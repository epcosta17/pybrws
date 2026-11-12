# Profiles

A profile is a Python module of constants and small functions: what pybrws needs to send what one browser sends. Choose one with `profile=` in Python, or `--profile` on the command line.

## Built-in profiles

| Name | Transport | Used by | Captured from |
|---|---|---|---|
| `firefox157` | TCP: TLS, HTTP/1.1 and HTTP/2 | the default of `pybrws.client`, `Session`, `Fetcher` and `pybrws` | Firefox 157.0 on Windows with default settings: its ClientHello, and its requests for a navigation, form and `fetch()` POSTs, cookies and an image |
| `chrome155` | TCP: TLS, HTTP/1.1 and HTTP/2 | `profile=chrome155`, `--profile chrome155` | Chrome 155 on Windows: six ClientHellos from one run, and its HTTP/1.1 and HTTP/2 requests |
| `firefox157_quic` | QUIC: HTTP/3 | `pybrws.h3`, `pybrws --http3` | Firefox 157 on Windows over QUIC: six connections from one capture, and one HTTP/3 request |

The captures are the files under `fixtures/` in the [repository](https://github.com/epcosta17/pybrws), and the test suite compares each profile with them.

```python
from pybrws.client import get
from pybrws.profiles import chrome155

response = get("https://example.com/", profile=chrome155)
```

A profile belongs to one transport. Naming one for the other transport is refused with a message that names the transport needed: `profiles.load("firefox157_quic")` raises `ProfileError`, and `pybrws --http3 --profile chrome155` stops before sending anything.

What each one draws afresh for every connection, besides the random values every TLS client draws:

| | `firefox157` | `chrome155` | `firefox157_quic` |
|---|---|---|---|
| extension order | the same 17 every time | 18 shuffled between two greased extensions | 13 shuffled, then `quic_transport_parameters` and `encrypted_client_hello` |
| GREASE | none | at the head of five lists, and at both ends of the extension list | none |
| greased ECH payload | 240 bytes | 144, 208 or 240 bytes | 240 bytes |

## What a profile refuses

A request whose header set the profile lacks raises `Unmeasured`, naming the capture that would supply it. HTTP/3 refuses every method but GET and HEAD.

| Request | `firefox157` | `chrome155` | `firefox157_quic` |
|---|---|---|---|
| GET or HEAD | sent | sent | sent |
| POST, `kind` `"xhr"`, `"form"` or `"form-script"` | sent | sent | `Unmeasured`: no HTTP/3 POST captured |
| `kind="image"` over HTTP/2 | sent | sent | not offered |
| `kind="image"` over HTTP/1.1 | sent | `Unmeasured`: chrome155 has no `H1_IMAGE_HEADERS` | not offered |

```text
Unmeasured: pybrws.profiles.chrome155 has no H1_IMAGE_HEADERS: that request kind was never captured for this browser. pybrws capture request and pybrws capture h2 take it.
Unmeasured: no Firefox HTTP/3 POST has been captured, so there is no measured header set to send. pybrws capture quic takes one; until then send it over TCP.
```

Resumption: over TCP a `Session` resumes TLS 1.3 with the session tickets servers issue. Firefox 157's resumed hello was captured; Chrome 155's was not, as the next list says. Over QUIC no session ticket is offered, because no resumed Firefox QUIC hello has been captured.

### Sent without a capture

These go on the wire although no capture backs their exact shape:

- **chrome155's resumed ClientHello.** A `Session` offers a session ticket with any TCP profile, and the resumed hello is built the way Firefox 157's was captured: `pre_shared_key` takes the place of `session_ticket`. No resumed Chrome hello is among the captures chrome155 was built from.
- **The second ClientHello after a HelloRetryRequest**, with either profile. No capture shows a browser answering one. When the server sends a cookie, the `cookie` extension goes after every other extension but `pre_shared_key`, which RFC 8446 requires to be last.
- **firefox157's HTTP/2 form POSTs and image requests.** Those sets are derived from the HTTP/1.1 captures by one rule: drop Host and Connection, lower-case the names, add `te: trailers`. The rule reproduces the captured HTTP/2 `fetch()` POST field for field.
- **Cookies on a form POST**, with either profile, **and on an HTTP/1.1 fetch POST.** No capture carries a cookie there. They go before the profile's anchor when the set has it, else last: see [Where cookies go](#where-cookies-go).
- **HEAD.** It sends the GET navigation set, and no capture is of a HEAD request.
- **An image request with any method but GET.** `kind="image"` picks the image set whatever the method, and every captured image request is a GET.
- **Methods other than GET, HEAD and POST**, such as PUT or DELETE. They send the set `kind` names.

## Writing your own

A profile of your own is a `.py` file. Load it by path:

```python
from pybrws import profiles
from pybrws.client import get

mine = profiles.load("my_firefox.py")
response = get("https://example.com/", profile=mine)
```

Every `--profile` on the command line takes a path as well as a name:

```console
pybrws --profile my_firefox.py https://example.com/
pybrws verify --local --profile my_firefox.py --capture my_firefox.hex
```

`profiles.load(spec, transport="tcp")` takes a built-in name, a module, or a path: an `os.PathLike`, or a string that ends in `.py` or holds a `/` or `\`. `transport` is `"tcp"`, `"quic"` or `"any"`. A file is checked against the contract below, and a missing name raises `ProfileError` listing every name missing. Built-in profiles are returned as they are.

The file is loaded on its own, outside any package, so its imports must be absolute: `from pybrws.profiles import firefox157`, not `from .. import hosts`. A relative import raises `ProfileError` saying so.

### The example file

[my_firefox.py](examples/my_firefox.py) is a complete profile: firefox157's values under a name of its own, with every name of the contract spelled out and a comment on each group. Download it, change what your browser sends differently, and check it against a capture of your browser with `pybrws verify`. It begins:

```python
from pybrws.profiles import firefox157

# The profile's own name. `pybrws -v` prints it, and `pybrws ab` logs it.
NAME = "my_firefox"

# The ClientHello's fixed fields: record and legacy versions, the cipher
# suites in order, the session id size and the compression methods.
RECORD_VERSION = firefox157.RECORD_VERSION
LEGACY_VERSION = firefox157.LEGACY_VERSION
CIPHER_SUITES = firefox157.CIPHER_SUITES
```

Checked against the Firefox 157 capture that ships in the package, saved as `my_firefox.hex`. The report repeats the command on its first line:

```text
$ pybrws verify --local --profile my_firefox.py --capture my_firefox.hex

capture  my_firefox.hex
sni      pybrws.127.0.0.1.nip.io   (taken from the capture)
ours     1901 bytes
real     1901 bytes

version ....... match
cipher suites . match   15, same order
extensions .... match   17, same order
payloads ...... 15 of 17   byte for byte

random ........ differs   must (32 fresh random bytes)
session_id .... differs   must (32 fresh random bytes)
key_share ..... differs   must (a real keypair)
encrypted_client_hello  differs   must (greased payload)

ja4  t13d1517h2_8daaf6152771_3cbfd9057e0d
     same string as the capture
```

The fields marked `must` are drawn afresh for every connection, so a hello that copied them would be broken, not closer.

## The contract over TCP

A TCP profile defines every name in `profiles.REQUIRED_TCP`, and its extensions in one of two forms.

| Name | What it is | In `firefox157` |
|---|---|---|
| `NAME` | the profile's name | `"firefox157"` |
| `RECORD_VERSION` | the record layer version of the hello | `0x0301` |
| `LEGACY_VERSION` | the hello's legacy version | `0x0303` |
| `CIPHER_SUITES` | the cipher suites in order, or a function of `ctx` that returns them | 15 suites |
| `SESSION_ID_SIZE` | how many random bytes of legacy session id | `32` |
| `COMPRESSION_METHODS` | the compression methods | `[0]` |
| `KEY_SHARE_GROUPS` | the key shares as `(group, public key size)`, in order | `(0x11EC, 1216)`, `(0x001D, 32)`, `(0x0017, 65)` |
| `H2_SETTINGS` | the SETTINGS frame as `(identifier, value)`, in order | 4 settings |
| `H2_CONNECTION_WINDOW_UPDATE` | the connection's WINDOW_UPDATE increment; 0 sends none | `12517377` |
| `H2_FIRST_STREAM_ID` | the first request's stream id | `3` |
| `H2_PSEUDO_ORDER` | the order of `:method`, `:path`, `:authority` and `:scheme` | `:method :path :authority :scheme` |
| `H2_NAVIGATION_HEADERS` | a navigation's HTTP/2 headers as `(name, value)`, in order | 11 headers |
| `H2_COOKIE_BEFORE` | the HTTP/2 header that `cookie` fields go before, in a set with no `{cookie}` slot; see [Where cookies go](#where-cookies-go) | `"upgrade-insecure-requests"` |
| `H1_HEADERS` | a navigation's HTTP/1.1 headers, in order and in their case | 12 headers |
| `H1_COOKIE_BEFORE` | the HTTP/1.1 header that `Cookie` goes before, in a set with no `{cookie}` slot; `None` puts it last | `"Upgrade-Insecure-Requests"` |

The extensions:

| Form | Names | For a browser that |
|---|---|---|
| a list | `EXTENSIONS`: `(type, payload)` in wire order; a payload is bytes, or a function of `ctx` called for each hello | sends one order every time, as `firefox157` does |
| a draw | `extension_order(ctx)` returns the types in order, and `payload_for(type, ctx)` returns each payload | draws its order per connection, as `chrome155` does |

A payload of `None` leaves the extension out: `server_name` for an IP address, for example.

`ctx` is the connection whose hello is being built:

| Member | What it gives |
|---|---|
| `ctx.hostname` | the server name |
| `ctx.random(n)` | `n` random bytes |
| `ctx.choice(values)` | one of `values` |
| `ctx.grease(slot)` | a GREASE value, drawn once per connection for each slot name |
| `ctx.once(key, factory)` | `factory()`, computed once per connection |
| `ctx.key_exchange` | the key exchange behind `key_share`; a profile creates one when it is `None` |

Header values may hold placeholders that are filled for each request: `{authority}`, `{content_length}`, `{content_type}`, `{origin}`, `{referer}` and `{cookie}`. A placeholder filled with an empty value removes its header. `{cookie}` marks where a set was captured carrying a cookie: see [Where cookies go](#where-cookies-go).

Optional names, which the client reads when they are there:

| Name | What it is | Without it |
|---|---|---|
| `H2_HEADERS_PRIORITY` | the priority in the HTTP/2 HEADERS frame: `{"exclusive": ..., "depends_on": ..., "weight": ...}` | the frame carries no priority |
| `H2_COOKIE_BEFORE_FALLBACK` | the HTTP/2 header that `cookie` fields go before in a set that lacks `H2_COOKIE_BEFORE` | they go last |
| `ech_growth_for_psk(size)` | how many bytes the greased ECH payload grows when a session ticket is offered | a resumed hello keeps the ECH payload's size |
| `H1_POST_XHR_HEADERS`, `H2_POST_XHR_HEADERS`, `H1_POST_FORM_HEADERS`, `H2_POST_FORM_HEADERS`, `H1_POST_FORM_SCRIPT_HEADERS`, `H2_POST_FORM_SCRIPT_HEADERS`, `H1_IMAGE_HEADERS`, `H2_IMAGE_HEADERS` | the header sets of the other kinds of request | that kind of request raises `Unmeasured` |
| `DRAWN` | the fields `pybrws verify` should expect to differ from a capture, and why | the profile is compared strictly |

### Where cookies go

A `Session` sends its cookies joined in one `Cookie` header over HTTP/1.1, and as one `cookie` field each over HTTP/2. It puts them:

1. in the set's `{cookie}` slot, if it has one; with no cookie, the slot's header is left out;
2. otherwise before `H1_COOKIE_BEFORE` or `H2_COOKIE_BEFORE`, if the set has that header;
3. otherwise, over HTTP/2, before `H2_COOKIE_BEFORE_FALLBACK`, if the profile names one and the set has it;
4. otherwise last.

In the built-in profiles, where each set puts them, and whether a capture backs that place:

| Set | `firefox157` | `chrome155` |
|---|---|---|
| navigation, HTTP/1.1 | before Upgrade-Insecure-Requests: captured | last: captured |
| navigation, HTTP/2 | before upgrade-insecure-requests: captured | before priority: captured |
| image, HTTP/1.1 | the `{cookie}` slot, after Referer: captured | no set |
| image, HTTP/2 | the `{cookie}` slot, after referer: derived from the HTTP/1.1 set | before priority: captured |
| fetch POST, HTTP/2 | before sec-fetch-dest, the fallback: captured | before priority: captured |
| fetch POST, HTTP/1.1 | last: not captured | last: not captured |
| form POSTs, HTTP/1.1 | before Upgrade-Insecure-Requests: not captured | last: not captured |
| form POSTs, HTTP/2 | before upgrade-insecure-requests: not captured | before priority: not captured |

### DRAWN

`DRAWN` maps field names from the report of `pybrws verify --local` to the reason each one is drawn per connection. `chrome155` declares it:

```python
DRAWN = {
    "extensions": "order drawn per connection",
    "supported_groups": "greased value at the head",
    "supported_versions": "greased value at the head",
    "signature_algorithms": "greased value at the head",
    "cipher suites": "greased value at the head",
    "length": "ECH payload length drawn from 144, 208, 240",
}
```

verify reports a field in `DRAWN` as `drawn (reason)` instead of `UNEXPECTED -- investigate`, and does not fail on it. The keys are the report's row names (`version`, `cipher suites`, `extensions`) and extension names (`supported_groups`, `signature_algorithms`, ...). A `length` entry gives the reason on the report's `ours` line when the hello's length differs from the capture's.

`verify` reads `DRAWN` from the profile it loaded, so a copy made with `from pybrws.profiles.chrome155 import *` inherits it. `firefox157` declares none, and neither does the example file: a profile without `DRAWN` is compared strictly.

## The contract over QUIC

A QUIC profile defines every name in `profiles.REQUIRED_QUIC`. `pybrws.h3` writes its hello into aioquic's handshake.

| Name | What it is |
|---|---|
| `NAME` | the profile's name |
| `ALPN_PROTOCOLS` | the ALPN list, `("h3",)` |
| `CIPHER_SUITES` | the cipher suites, in order |
| `SESSION_ID_SIZE` | the legacy session id size, `0` over QUIC |
| `LEGACY_COMPRESSION_METHODS` | the compression methods |
| `KEY_SHARE_GROUPS` | the key shares as `(group, public key size)`, in order |
| `CONNECTION_ID_SIZE` | the length of the client's connection id |
| `IDLE_TIMEOUT_SECONDS`, `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_DATAGRAM_FRAME_SIZE` | the limits the transport parameters announce, which aioquic is set to enforce |
| `STATIC_PAYLOADS` | `{type: payload}` for the extensions that never change |
| `EXT_SERVER_NAME`, `EXT_KEY_SHARE`, `EXT_QUIC_TRANSPORT_PARAMETERS`, `EXT_ENCRYPTED_CLIENT_HELLO` | the types of the extensions built per connection |
| `extension_order(rng)` | one connection's extension order; `rng(n)` returns `n` random bytes |
| `server_name(hostname)` | the `server_name` payload, or `None` for an IP address |
| `transport_parameters(connection_id)` | the `quic_transport_parameters` payload, carrying the connection's own id |
| `greased_ech(rng)` | the `encrypted_client_hello` payload |
| `navigation_headers(authority)` | the HTTP/3 request headers, in order |

`INITIAL_DESTINATION_ID_SIZE` is optional: the length of the client's first destination connection id, which is otherwise `CONNECTION_ID_SIZE`.
