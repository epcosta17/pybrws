# fixtures

Raw ClientHello captures in hex. Not tracked in git: they are specific to the
machine that produced them.

## Hostname requirement

A browser pointed at `https://127.0.0.1:4443` sends no `server_name`
extension, because SNI carries hostnames and not IP addresses. A capture taken
that way does not represent a real connection, and JA4 encodes SNI presence in
its first field.

Map the loopback address to a name instead:

    127.0.0.1   pybrws.test

- macOS and Linux: `/etc/hosts`
- Windows: `C:\Windows\System32\drivers\etc\hosts`, as administrator

Then capture against `https://pybrws.test:4443`.

## Capturing

Terminal 1:

    python tools/catch_hello.py fixtures/firefox.hex --peek

Terminal 2, or the browser: open `https://pybrws.test:4443`. The handshake
fails and the client reports an error; the ClientHello has already been sent.

## Captures to collect

| File | Source |
|---|---|
| `firefox.hex` | Firefox, post-quantum disabled in `about:config`. The v1 target. |
| `firefox-pq.hex` | Firefox with post-quantum enabled, for size comparison. |
| `chrome.hex` | Chrome, to identify browser-specific extensions. |
| `python-ssl.hex` | `python -c "import ssl,socket; ssl.create_default_context().wrap_socket(socket.create_connection(('pybrws.test',4443)), server_hostname='pybrws.test')"` |
| `curl.hex` | `curl https://pybrws.test:4443` |

Capture Firefox five times as `firefox-1.hex` through `firefox-5.hex` and diff
them against each other to establish whether the target is stable. The answer
determines what "byte-identical" means for the emitter.
