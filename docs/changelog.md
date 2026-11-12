# Changelog

## 0.1.0

The first release on PyPI.

### Client

- A TLS 1.3 client written in Python, with TLS 1.2 (ECDHE, with AES-GCM or ChaCha20-Poly1305) for servers that decline 1.3.
- HTTP/1.1 and HTTP/2, as the server chooses through ALPN.
- HTTP/3 through aioquic, with Firefox 157's QUIC hello: `pybrws.h3`, in the `pybrws[http3]` extra.
- Three profiles: `firefox157` and `chrome155` over TCP, and `firefox157_quic` over QUIC.
- Profiles of your own, loaded from a `.py` file with `pybrws.profiles.load` or `--profile`, and checked against the contract.
- `get`, `post`, `request` and `stream` in `pybrws.client`.
- `Session`: cookies, connection reuse and TLS 1.3 resumption with session tickets.
- `Fetcher`: many requests on threads, sharing one cookie jar, with a `Retry` policy.
- Proxies: `http://`, `https://`, `socks5://` and `socks5h://`, given or taken from the environment, with `NO_PROXY`.
- Certificates verified against Mozilla's roots and the platform's, or a store you pass.
- `python -m pybrws.proxy`: a local HTTPS proxy that re-issues requests with firefox157's fingerprint, for clients in other languages.

### Limits and refusals

- A request whose header set the profile lacks raises `Unmeasured`: Chrome's image request over HTTP/1.1. HTTP/3 refuses every method but GET and HEAD, and offers no session ticket. What is still sent without a capture behind it is listed under [Profiles](profiles.md#sent-without-a-capture).
- A request goes again only when that is safe: any method if the server provably never processed it, otherwise GET, HEAD and OPTIONS before any answer arrived. A `Fetcher` whose `Retry` allows more than one attempt also asks again, for GET, HEAD and OPTIONS, after a 429, 500, 502, 503 or 504.
- Bodies are decoded from gzip, deflate, br and zstd, and capped at 128 MiB as received and as decoded unless `max_body_size` says otherwise.
- A compressed body cut short, or a TLS stream that ends without close_notify, raises instead of returning a short body.
- On a protocol error over TCP the client raises and closes the connection, and sends nothing to the peer. A `Session` does not reuse it, over HTTP/1.1 or HTTP/2.
- A header set captured carrying a cookie marks the place with a `{cookie}` slot: a `Session`'s cookies go there, and with none the header is left out.

### Command line

- `pybrws URL`: a fetch shaped like curl's, following redirects as a browser does.
- The method's tools as subcommands: `capture hello`, `capture request`, `capture h2`, `capture quic`, `capture resumed`, `read-quic`, `ja4`, `verify`, `probe`, `ab`, `isolate` and `waf`.
- `pybrws verify --local` compares a profile with a browser capture, offline. The captures for `firefox157` and `chrome155` ship in the package, and `--capture` takes one of your own.
- A command that needs a missing extra stops before sending anything, naming `pybrws[http3]` or `pybrws[measure]`.
