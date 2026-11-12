# pybrws

Python + browser: an HTTPS client that sends what a real browser sends.

pybrws is an HTTPS client written from scratch in Python. It sends what Firefox 157 and Chrome 155 send on the wire: the TLS ClientHello, the start of HTTP/2 and the request headers, in the browser's order. Over HTTP/3 it sends Firefox 157's QUIC hello.

| pybrws is | pybrws is not |
|---|---|
| A client you can read: TLS, HTTP/1.1, HTTP/2 and the profiles are plain Python. | A replacement for [curl_cffi](https://pypi.org/project/curl-cffi/). For production use, use curl_cffi. |
| A learning tool: each profile is a module of constants read from browser captures. | A browser: it runs no JavaScript and renders nothing. |
| A measurement tool: its subcommands capture your browser, then compare, verify and measure. | A promise that any site accepts its requests. |

## Install

```console
pip install pybrws
```

Python 3.11 or newer. Two optional extras:

| Extra | Adds | For |
|---|---|---|
| `pybrws[http3]` | aioquic | `pybrws.h3`, `pybrws --http3`, `pybrws capture quic`, and the QUIC arms of `pybrws probe` and `pybrws ab` |
| `pybrws[measure]` | httpx | the httpx arms of `pybrws ab` and `pybrws isolate` |

A command that needs a missing extra stops before it sends anything, with one line naming the extra:

```text
pybrws ab needs httpx: pip install 'pybrws[measure]'
```

## Example

```python
from pybrws.client import get
from pybrws.profiles import chrome155

response = get("https://example.com/")                     # as Firefox 157
print(response.status, response.http_version)
print(response.header("content-type"))

response = get("https://example.com/", profile=chrome155)  # as Chrome 155
print(response.status, response.text()[:15])
```

```text
200 h2
text/html; charset=utf-8
200 <!doctype html>
```

From the command line:

```console
pybrws https://example.com/
pybrws verify --local
```

The first fetches the page, as curl would. The second compares the default profile's ClientHello with the browser capture that ships in the package, offline.

## Where next

| To | Read |
|---|---|
| send requests from Python | [Quick Start](quickstart.md) |
| choose a profile, or write your own | [Profiles](profiles.md) |
| use the `pybrws` command and its subcommands | [Command line](cli.md) |
| know the trust, retry and size rules | [Advanced topics](advanced.md) |
| imitate your own browser, step by step | [The method](method/index.md) |
| look up a function | [API reference](api/client.md) |
