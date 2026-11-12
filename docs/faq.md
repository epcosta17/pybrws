# FAQ

## Should I use pybrws or curl_cffi?

For production use, use [curl_cffi](https://pypi.org/project/curl-cffi/). pybrws is a learning and measurement tool: a client written in Python that you can read end to end, with the tools to capture a browser, write its profile, check it and measure it.

## Will a site accept my requests?

pybrws makes no promise that any site accepts its requests. It sends what a browser sends in the TLS hello, the HTTP/2 start and the headers. A server can look at much more: the address, the timing, cookies, and whatever JavaScript would have run. [The method](method/index.md) shows how to measure what matters on a given site, with controls.

## Which browsers can it imitate?

Firefox 157 and Chrome 155 over TCP, and Firefox 157 over HTTP/3: see [Profiles](profiles.md). For another browser or version, capture it and write a profile; the [command line](cli.md#capture) has the capture tools, and [the method](method/index.md) walks through it.

## Does it run JavaScript?

No. A page that needs script to show its content comes back as the HTML the server sent. See [No JavaScript engine](advanced.md#no-javascript-engine).

## Why does `get` not follow redirects?

`pybrws.client.get` returns the redirect itself, as curl does without `-L`; pass `follow_redirects=5` to follow up to five. A `Session` and a `Fetcher` follow five by default, and so does the `pybrws` command, as a browser does; `--no-location` turns that off.

## Why does a POST over HTTP/3 raise `Unmeasured`?

No Firefox HTTP/3 POST has been captured, so there is no measured header set to send. Send the POST over TCP. The same error comes from any request kind a profile has no capture for: see [What a profile refuses](profiles.md#what-a-profile-refuses).

## Why does `pybrws verify --local` print "differs" lines and still pass?

The random, the session id, the key share and the greased ECH payload are drawn afresh for every connection, so they must differ from any capture; a profile can name further drawn fields in [`DRAWN`](profiles.md#drawn). verify passes when the JA4 matches the capture's and nothing else differs. See [verify](cli.md#verify).

## I get `CertificateError: certificate chain rejected`. What now?

The chain does not lead to one of Mozilla's roots or the platform's. If the server uses a CA of your own, pass it with `trust_store=`, or add it to a bundle named by `SSL_CERT_FILE`; see [Verification and trust](advanced.md#verification-and-trust). `verify=False` (`-k`) turns checking off, and with it any protection against interception.

## Does it work through a proxy?

Over TCP, yes: `http://`, `https://`, `socks5://` and `socks5h://`, given as `proxy=` or taken from the environment, with `NO_PROXY` for the hosts reached directly. See [Proxies and NO_PROXY](quickstart.md#proxies-and-no_proxy). HTTP/3 has no proxy support.

## Is it async? Is it thread-safe?

The TCP client is synchronous. For many requests at once, a `Fetcher` runs them on threads, each with its own `Session`; a single `Session` is not safe to share between threads. HTTP/3 runs on asyncio: inside an event loop, `await pybrws.h3.fetch(url)`.

## Does it speak plain HTTP?

No: every URL must be `https://`. For any other, the TCP client raises `UnsupportedUrl` and `pybrws.h3` raises `Http3Error`.

## My profile file will not load. Why?

`ProfileError` says which of these it is:

- a relative import, such as `from .. import hosts`: a profile file is loaded on its own, so its imports must be absolute;
- a name of the contract that is missing: the message lists each one;
- no file at that path;
- an error raised while the file runs, which the message names.

See [Writing your own](profiles.md#writing-your-own) and the [example file](examples/my_firefox.py).
