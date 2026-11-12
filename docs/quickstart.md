# Quick Start

Every function here takes an `https://` URL: for any other, the TCP client raises `UnsupportedUrl` and `pybrws.h3` raises `Http3Error`. The default profile is `firefox157`, and [Profiles](profiles.md) lists the others.

## get and post

```python
from pybrws.client import get, post, request

response = get("https://example.com/")
response = post("https://example.com/api", json={"q": "pybrws"})
response = post("https://example.com/login", data={"user": "me"}, kind="form")
response = request("https://example.com/", method="HEAD")
```

| Argument | Default | What it does |
|---|---|---|
| `profile` | `firefox157` | the browser to imitate, a profile module |
| `headers` | none | a dict or a list of pairs merged into the profile's headers: a header the profile sends keeps its place with your value, a new one goes last, and `None` removes one |
| `data` | none | the body: bytes, a string, or a mapping to form-encode |
| `json` | none | an object to send as JSON |
| `kind` | `"xhr"` | which captured header set a POST sends: `"xhr"` for a `fetch()` call, `"form"` for a person submitting a form, `"form-script"` for a page submitting one; `"image"` sends an image request |
| `referer` | the URL's origin, as `https://example.com/` | the Referer of the sets that carry one, the POST and image sets; an empty string leaves it out. A navigation carries none: add one with `headers=` |
| `follow_redirects` | `0` | how many redirects to follow; 0 returns the redirect itself, as curl does without `-L` |
| `timeout` | `20.0` | the socket timeout, in seconds |
| `proxy` | from the environment | see [Proxies and NO_PROXY](#proxies-and-no_proxy) |
| `verify` | `True` | check the server's certificate; see [Trust stores](#trust-stores) |
| `trust_store` | Mozilla's and the platform's roots | see [Trust stores](#trust-stores) |
| `max_body_size` | 128 MiB | see [max_body_size](#max_body_size) |

A GET or HEAD sends the profile's navigation headers, unless `kind="image"`. Any other method sends the set `kind` names. Only GET and POST requests were captured; [Sent without a capture](profiles.md#sent-without-a-capture) lists the rest.

The response:

| Attribute | What it holds |
|---|---|
| `status` | the status code |
| `ok` | `True` for a status from 200 to 399 |
| `headers` | the headers, as `(name, value)` pairs in the order received |
| `header(name)` | the first value of a header, in any case, or `None` |
| `body` | the body, decoded from gzip, deflate, br or zstd |
| `text()` | the body as text, in the charset Content-Type names (UTF-8 if none) |
| `json()` | the body, parsed as JSON |
| `http_version` | `"HTTP/1.1"`, `"h2"` or `"h3"` |
| `url` | the URL this response answers |
| `history` | the redirect responses followed on the way |
| `trailers` | HTTP/2 trailers, if any |

The server chooses HTTP/2 or HTTP/1.1 through ALPN; both are sent as the profile says.

## Session and Fetcher

A `Session` keeps cookies and connections across requests:

```python
from pybrws.session import Session

with Session() as session:
    session.get("https://example.com/")
    response = session.post("https://example.com/api", json={"page": 2})
```

| A Session keeps | |
|---|---|
| cookies | from Set-Cookie, sent back where the profile puts them; `session.cookies` |
| connections | one per host and port, reused for the next request |
| session tickets | a new TLS 1.3 connection to the host resumes with one |
| defaults | `profile`, `proxy`, `timeout` (20 s), `follow_redirects` (5), `verify`, `trust_store`, `max_body_size` |

`session.request()`, `get()` and `post()` take `headers`, `data`, `json`, `kind`, `referer`, `timeout` and `follow_redirects` per request. A request that fails on a reused connection may go again once, under the [retry rules](advanced.md#retries).

A `Fetcher` runs many requests at once, each worker thread with its own Session. The cookie jar and the session tickets are shared between them:

```python
from pybrws.pool import Fetcher, Retry

urls = ["https://example.com/", "https://example.com/a", "https://example.com/b"]
with Fetcher(concurrency=4, retry=Retry(attempts=3)) as fetcher:
    for result in fetcher.fetch_all(urls):
        print(result.url, result.status, result.error)
```

| Method | Returns |
|---|---|
| `fetch(url, **kwargs)` | one `Result` |
| `fetch_all(urls, **kwargs)` | a list of `Result`, in the order given |
| `map(urls, **kwargs)` | `Result`s as they finish |

A `Result` holds `url`, `response`, `error`, `attempts`, `status` and `ok`. Errors are returned in it, not raised. The keyword arguments go to `Session.request`. A Fetcher takes `concurrency` (8), `profile`, `proxy`, `timeout`, `verify`, `follow_redirects` (5), `retry` and `max_body_size`; it has no `trust_store`.

## Streaming

```python
from pybrws.client import stream

with stream("https://example.com/") as (response, chunks):
    with open("page.html", "wb") as out:
        for chunk in chunks:
            out.write(chunk)
```

- `response` carries the status and headers; its body stays empty.
- `chunks` yields the body decoded, in pieces of at most 1 MiB, with no total cap.
- Read the chunks inside the `with` block: the connection closes when it ends.
- Streaming needs HTTP/2. A server that chooses HTTP/1.1 raises `UnsupportedUrl`.
- `stream` follows no redirects.

## HTTP/3

```console
pip install "pybrws[http3]"
```

```python
from pybrws import h3

response = h3.get("https://example.com/")
print(response.status, response.http_version)
```

- The profile is `firefox157_quic`, the only QUIC profile.
- GET and HEAD only. Any other method raises `pybrws.client.Unmeasured`: no Firefox HTTP/3 POST has been captured.
- No proxy: QUIC runs over UDP.
- No resumption: every connection is a full handshake.
- `h3.get` follows no redirects; `pybrws --http3` does.
- It takes `headers`, `timeout` (30 s), `verify`, `cadata` and `max_body_size`.

Inside an event loop, `await h3.fetch(url)` does the same.

## max_body_size

```python
from pybrws.client import get
from pybrws.message import BodyTooLarge

try:
    response = get("https://example.com/", max_body_size=10 * 2**20)
except BodyTooLarge:
    print("more than 10 MiB")

response = get("https://example.com/", max_body_size=None)  # no cap
```

The cap applies to the body as received and as decoded, and is 128 MiB unless you set it. `Session`, `Fetcher` and `pybrws.h3` take the same argument; on the command line it is `--max-filesize BYTES`, where 0 lifts it. See [Decoding caps](advanced.md#decoding-caps).

## Proxies and NO_PROXY

```python
from pybrws.client import get

get("https://example.com/", proxy="http://user:pass@proxy.example.com:8080")
get("https://example.com/", proxy="socks5h://proxy.example.com:1080")
get("https://example.com/", proxy=False)  # direct, whatever the environment says
```

| Scheme | Default port | |
|---|---|---|
| `http://` | 8080 | a CONNECT tunnel |
| `https://` | 8080 | TLS to the proxy first, checked against the platform's roots, then CONNECT |
| `socks5://`, `socks5h://` | 1080 | both resolve the target's name at the proxy |

A proxy URL without a scheme is read as `http://`. The handshake inside the tunnel is the profile's, and the server sees the proxy's address and TCP/IP signature instead of yours.

With `proxy` left as `None`, the proxy comes from the first of these that is set: `PYBRWS_PROXY`, `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`, `all_proxy`.

`NO_PROXY` (or `no_proxy`) lists the hosts that are reached directly, separated by commas: `*` for every host, or a name that matches exactly or as a domain suffix, with or without a leading dot. `example.com` covers `api.example.com`, not `badexample.com`. It applies only to a proxy taken from the environment; one passed as `proxy=` is always used.

`Session` and `Fetcher` take `proxy` the same way. HTTP/3 has no proxy support.

## Trust stores

By default a server's chain must lead to one of Mozilla's roots, from the certifi bundle, or to one of the platform's. Mozilla's root program is the one Firefox uses.

```python
from cryptography import x509
from cryptography.x509.verification import Store
from pybrws import certs
from pybrws.client import get

get("https://example.com/", trust_store=certs.system_store())  # the platform's roots alone

with open("my-ca.pem", "rb") as f:
    mine = Store(x509.load_pem_x509_certificates(f.read()))
get("https://example.com/", trust_store=mine)                  # your roots alone

get("https://example.com/", verify=False)                      # no verification
```

| To trust | Pass |
|---|---|
| Mozilla's roots and the platform's | nothing: `certs.default_store()` is the default |
| the platform's roots alone | `trust_store=certs.system_store()` |
| your own roots alone | `trust_store=Store([...])` |
| nothing: no verification | `verify=False`, or `-k` on the command line |

`get`, `post`, `request`, `stream` and `Session` take `trust_store`. HTTP/3 verifies through aioquic: against certifi's roots, or the PEM bytes you pass as `cadata`. [Verification and trust](advanced.md#verification-and-trust) has the details.
