# Advanced topics

## Verification and trust

With `verify=True`, the default, a TCP connection is checked this way:

| Check | |
|---|---|
| the chain | leads to a trusted root and names the URL's host, or its IP address; path validation is `cryptography`'s |
| TLS 1.3 | the server's CertificateVerify signs the handshake with the certificate's key; a full handshake without one is refused |
| TLS 1.2 | the server's ServerKeyExchange is signed with the certificate's key |
| revocation | not checked |

The trusted roots, by default, are Mozilla's and the platform's:

| Store | Holds |
|---|---|
| `pybrws.certs.default_store()`, the default | Mozilla's roots, from the certifi bundle (Mozilla's root program is the one Firefox uses), plus the platform's; a root in both counts once |
| `pybrws.certs.system_store()` | the platform's roots alone, as Python's `ssl` module reads them |
| a `cryptography.x509.verification.Store` of your own | the roots you put in it |

Each of the first two raises `CertificateError` when it ends up with no root at all. Pass a store as `trust_store=` to `get`, `post`, `request`, `stream` or `Session`. A `Fetcher` takes no store: its sessions use the default.

Mozilla's half needs nothing from the platform, so a Python whose platform store is empty or out of date still verifies a public site. The platform's half is read through Python's `ssl` module, which honours `SSL_CERT_FILE`: to trust a CA of your own in every request, put it in a PEM bundle and point `SSL_CERT_FILE` at that file. On Linux and macOS the file takes the place of the platform's bundle, so it should hold every root you still want from there; on Windows it is read besides the system store. Mozilla's half stays either way.

`verify=False`, or `-k` on the command line, skips the chain check and, on TLS 1.3, the CertificateVerify check. Anyone on the path can then read and change the traffic without any sign of it.

Over HTTP/3, verification is aioquic's: against certifi's roots, or against the PEM certificates passed as `cadata`, which then replace them. The platform's roots are not read.

An `https://` proxy's own certificate is checked by Python's `ssl` module, against the platform's roots.

## Retries

Only a `Session` and a `Fetcher` send a request again. The functions of `pybrws.client` and `pybrws.h3` never do.

`pybrws.session.may_retry(method, error, response_started)` decides whether a request may go again:

| The failure | May go again |
|---|---|
| one after which the server provably never processed the request (`NEVER_PROCESSED`): a stream it refused, or one above its GOAWAY's last stream id (`StreamRefused`); a refused connection; a name that did not resolve | any method, POST included |
| any other: a timeout, a reset, a protocol error | GET, HEAD and OPTIONS (`IDEMPOTENT`), and only if no part of the answer had arrived |

A `Session` sends a request again once at most, on a new connection, when sending it fails with a transport error (`RETRYABLE`: `EOFError`, `TlsAlert`, `Http1Error`, `Http2Error`, `ConnectionError` or `OSError`), `may_retry` allows it, and either:

- it failed on a reused connection, which is how a connection the server had already closed shows itself, or
- the server provably never processed it.

A failure to open the connection is raised as it is.

A `Fetcher` retries on top of its sessions, by its `Retry`:

| Field | Default | |
|---|---|---|
| `attempts` | `1` | tries per URL in all; 1 means no retry |
| `statuses` | 429, 500, 502, 503, 504 | answers that are asked again, for GET, HEAD and OPTIONS only |
| `backoff` | `1.0` | seconds before the second try, doubling before each one after |

When a request raises, a `Fetcher` applies the same `may_retry` rule, as if no part of an answer had arrived. A connection that could not be opened is among the failures it can send again.

## Decoding caps

| | |
|---|---|
| `max_body_size` | 128 MiB unless set (`pybrws.message.DEFAULT_MAX_BODY`), on the body both as received and as decoded; `None` lifts it |
| past the cap | `BodyTooLarge`, a `ContentEncodingError`, raised as soon as the cap is passed, before the body is held whole |
| a Content-Length past the cap, over HTTP/1.1 | refused before any of the body is read |
| encodings | gzip, with several members; deflate, as zlib or raw; br; zstd, from the standard library on Python 3.14 and from `zstandard` before it. Any other raises `ContentEncodingError` |
| a compressed body cut short | `ContentEncodingError`: "stream ended early: the body is truncated" |
| a TLS stream that ends without close_notify | `TruncatedStream`, rather than a short body |
| `stream()` | decoded pieces of at most 1 MiB, with no total cap |
| a response head | at most 256 KiB, over HTTP/1.1 and HTTP/2 |

`max_body_size` is an argument of `get`, `post`, `request`, `Session`, `Fetcher`, `h3.request` and `h3.fetch`. On the command line it is `--max-filesize BYTES`, where 0 lifts the cap. A connection whose response was refused for its size is closed, not reused: the rest of that body is still on the wire.

## Protocol errors

Over TCP, when a server breaks the protocol (a TLS message out of order, a bad HTTP/2 frame or setting, a header that carries CR, LF or NUL), the client raises an exception and closes the connection. It sends nothing to the peer: no TLS alert, no GOAWAY, no RST_STREAM, no close_notify.

The message names the error the RFC calls for:

```text
HandshakeError: a handshake message spans the key change (RFC 8446 5.1: unexpected_message)
Http2Error: PROTOCOL_ERROR: SETTINGS_ENABLE_PUSH 2 (RFC 9113 6.5.2)
```

No browser capture covers what a client sends as it aborts, so pybrws sends nothing then. A `Session` never reuses a connection that saw a protocol error, over HTTP/1.1 or HTTP/2.

Over HTTP/3 the connection is aioquic's, and aioquic closes it with a QUIC CONNECTION_CLOSE frame.

## No JavaScript engine

pybrws runs no JavaScript and renders nothing. A page that builds its content with script, or a JavaScript challenge, comes back as the HTML the server sent, and nothing in it runs. Cookies come only from Set-Cookie headers. `pybrws ab` counts a small body that carries a challenge page's marker as not served.
