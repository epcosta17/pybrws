# pybrws

Python + browser: an HTTPS client that sends what a real browser sends

pybrws is written from scratch in Python. It sends what Firefox 157 and Chrome 155 send on the wire: the TLS ClientHello, the HTTP/2 start and the headers. It also sends Firefox's QUIC hello over HTTP/3. It is a learning and measurement tool that you can install, and it began as a way to see how browsers look on the wire.

It is not a replacement for [curl_cffi](https://pypi.org/project/curl-cffi/). For production use, use curl_cffi. pybrws makes no promise that any site will accept its requests.

## Install

```
pip install pybrws
```

Python 3.11 or newer. Two optional extras:

- `pip install "pybrws[http3]"` adds aioquic, for HTTP/3.
- `pip install "pybrws[measure]"` adds httpx, for the A/B controls of `pybrws ab`.

## Use it from Python

```python
from pybrws.client import get
from pybrws.profiles import chrome155

response = get("https://example.com/", profile=chrome155)
print(response.status, response.header("content-type"))
print(response.text()[:200])
```

The default profile is `firefox157`. `post` and `request` work the same way. HTTP/3 is `pybrws.h3.get(url)`, Firefox only.

## Use it from the command line

```
pybrws https://example.com/
pybrws verify --local
```

The first fetches a page like curl. The second compares the default profile's ClientHello with the browser capture shipped in the package, offline, and prints "same string as the capture". Other subcommands: `capture`, `read-quic`, `ja4`, `verify`, `probe`, `ab`, `isolate`, `waf`.

## More

- Documentation: https://pybrws.readthedocs.io/
- Source: https://github.com/epcosta17/pybrws
- Licence: [MIT](https://github.com/epcosta17/pybrws/blob/master/LICENSE)
