# fixtures

Raw ClientHello captures in hex, and the reference HTTP requests the
byte-identity tests compare against. These are tracked: a reader checking the
GREASE analysis or the variance table needs the data behind it. They are still specific to
the machine that produced them, and the write-ups say so where it matters:
one machine's GPU, OS, font set, browser build and field-trial state are a
sample and not a population.

## Hostname requirement

A browser pointed at `https://127.0.0.1:4443` sends no `server_name`
extension, because SNI carries hostnames and not IP addresses. A capture taken
that way does not represent a real connection, and JA4 encodes SNI presence in
its first field.

So the browser needs a *name* that resolves to the loopback. The references
here were taken against `pybrws.127.0.0.1.nip.io`, which resolves to
127.0.0.1 without an `/etc/hosts` entry and is what `REFERENCE_HOSTNAME` in
`tests/test_emitter.py` holds. An `/etc/hosts` line works equally well if you
would rather not depend on a public resolver:

    127.0.0.1   pybrws.test

- macOS and Linux: `/etc/hosts`
- Windows: `C:\Windows\System32\drivers\etc\hosts`, as administrator

Either way, capture against the name and not the address.

## Capturing

Terminal 1:

    python tools/catch_hello.py fixtures/firefox.hex --peek

Terminal 2, or the browser: open `https://pybrws.127.0.0.1.nip.io:4443/`. The handshake
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
