# Command line

`pybrws URL` fetches a page, as curl does. `pybrws SUBCOMMAND` runs one of the tools of [the method](method/index.md). A first argument that is not a subcommand's name is a URL.

## Fetch

```console
pybrws https://example.com/
pybrws -i https://example.com/
pybrws -o page.html --profile chrome155 https://example.com/
pybrws -d 'q=pybrws' https://example.com/search
pybrws -H 'Accept-Language: de-DE,de;q=0.9' https://example.com/
pybrws --http3 https://example.com/
```

With `-v` and `-I`, trimmed after the second header:

```text
$ pybrws -v -I https://example.com/
> https://example.com/
> transport: tcp
> profile: firefox157
* 200 h2 577 bytes
h2 200
date: Thu, 12 Nov 2026 15:13:45 GMT
content-type: text/html; charset=utf-8
...
```

The lines that start with `>` and `*` go to stderr. The body goes to stdout, or to the file `-o` names.

| Option | What it does |
|---|---|
| `-X`, `--request METHOD` | the method: GET, or POST with `-d` |
| `-d`, `--data BODY` | the request body; implies POST, and `Content-Type: application/x-www-form-urlencoded` unless `-H` sets one |
| `-H`, `--header 'Name: value'` | replace or add a header, repeatable; a header the profile sends keeps its place |
| `-o`, `--output FILE` | write the body to `FILE` |
| `-i`, `--include` | print the response head before the body |
| `-I`, `--head-only` | print the response head and not the body; the method does not change |
| `-L`, `--location` | follow redirects, the default, as a browser does |
| `--no-location` | return the redirect itself |
| `--max-redirs N` | follow at most `N` redirects (5) |
| `-v`, `--verbose` | describe the request on stderr: URL, transport, profile, proxy and the headers given with `-H` |
| `-s`, `--silent` | leave out the status lines on stderr |
| `-x`, `--proxy URL` | `http://`, `https://`, `socks5://` or `socks5h://`, with an optional `user:pass@`; without it, the proxy comes from the environment, as in [Proxies and NO_PROXY](quickstart.md#proxies-and-no_proxy) |
| `-k`, `--insecure` | do not verify the server's certificate |
| `--profile NAME` | `firefox157` (the default) or `chrome155`; `firefox157_quic` with `--http3`; or a `.py` file |
| `--http3` | fetch over HTTP/3 with its own profile and code path; needs `pybrws[http3]`, and takes no `--proxy` |
| `--timeout SECONDS` | the socket timeout (20) |
| `--max-filesize BYTES` | the most a body may be, received or decoded (128 MiB); 0 lifts the cap |

The exit status is 0 for a final status below 400 and 1 otherwise. An error such as `CertificateError: ...` prints one line that names it, and exits with status 1.

## Subcommands

| Subcommand | Step | What it does |
|---|---|---|
| `pybrws capture hello` | [1. Capture](method/01-capture.md) | your browser's ClientHello over TCP |
| `pybrws capture request` | 1 | your browser's HTTP/1.1 request, decrypted |
| `pybrws capture h2` | 1 | your browser's HTTP/2 request, decoded |
| `pybrws capture quic` | 1 | your browser's ClientHello over QUIC |
| `pybrws capture resumed` | 1 | your browser's resumed ClientHello, the one with `pre_shared_key` |
| `pybrws read-quic` | 1 | a QUIC ClientHello from a packet capture |
| `pybrws ja4` | [2. Compare](method/02-compare.md), [4. Verify](method/04-verify.md) | a profile's JA4, computed locally |
| `pybrws verify` | 4 | a profile's ClientHello against a capture, field by field |
| `pybrws probe` | 4 | what an outside service sees over TCP and QUIC |
| `pybrws ab` | [5. Measure](method/05-measure.md) | pybrws against plain clients, in interleaved rounds |
| `pybrws isolate` | 5 | fingerprint crossed with address: each client direct and through a proxy |
| `pybrws waf` | 5 | which protection's marks each URL's response carries |

`pybrws SUBCOMMAND --help` prints its options. Every `--profile` takes a built-in name or a `.py` file. A subcommand that needs a missing extra stops before it sends anything, naming the extra:

```text
pybrws ab needs httpx: pip install 'pybrws[measure]'
pybrws --http3 needs aioquic: pip install 'pybrws[http3]'
```

## capture

`pybrws capture KIND [options]` runs a local server, by default on `127.0.0.1:4443`, and records what your browser sends to it. Files go to the path given, in the current directory unless the path says otherwise.

### capture hello

```console
pybrws capture hello firefox.hex
```

Takes one TCP connection and writes the first bytes the client sends, its ClientHello, as hex. The browser's handshake then fails, which does not matter: the hello has been sent. Open the listener under a name that resolves to 127.0.0.1, such as `https://pybrws.127.0.0.1.nip.io:4443/`; under an IP address the browser sends no `server_name`.

| Option | |
|---|---|
| `OUT` | the file to write the hex to |
| `--host`, `--port` | where to listen (127.0.0.1, 4443) |
| `--wait SECONDS` | how long to wait for a connection (120) |
| `--quiet-after SECONDS` | the silence that ends the read (0.8) |
| `--peek` | print a hexdump |
| `--count N` | capture `N` hellos, written as `firefox-1.hex` and so on, and compare them: what a browser that shuffles its extension order needs |

### capture request

```console
pybrws capture request firefox-h1.txt
```

Serves a self-signed certificate, so the request arrives decrypted. Open `https://pybrws.127.0.0.1.nip.io:4443` and accept the certificate warning; the request is written to the file.

| Option | |
|---|---|
| `OUT` | the file to write the request to |
| `--host`, `--port` | where to listen (127.0.0.1, 4443) |
| `--hostname NAME` | the name in the certificate, which the URL must use (`pybrws.127.0.0.1.nip.io`) |
| `--alpn {http/1.1,h2}` | the protocol to offer (`http/1.1`); `h2` captures the HTTP/2 preamble |
| `--post {form,form-click,fetch}` | answer with a page that posts, then capture that POST: `form` submits by script, `form-click` waits for a click, `fetch` sends a `fetch()` |
| `--any-request` | capture subresources too, not only a document request |
| `--set-cookie` | answer the first request with a Set-Cookie, and capture the reload that carries it |
| `--wait SECONDS`, `--quiet-after SECONDS` | as for `capture hello` (120, 1.0) |

### capture h2

```console
pybrws capture h2 firefox-h2.txt
```

Speaks enough HTTP/2 to decode the browser's HEADERS frame with HPACK. Open `https://pybrws.127.0.0.1.nip.io:4443` and accept the certificate. The headers go to the file in wire order, and the frames the browser sent to `firefox-h2.frames.json` beside it.

| Option | |
|---|---|
| `OUT` | the file to write the headers to |
| `--host`, `--port`, `--hostname` | as for `capture request` |
| `--wait SECONDS` | how long to wait (120) |
| `--set-cookie` | answer with a Set-Cookie, and capture the reload |
| `--any-request` | capture a subresource instead of the document: how an image request is taken |
| `--post {form,form-click,fetch}` | answer with a page that posts |

### capture quic

```console
pybrws capture quic --out firefox-quic.hex
```

Runs aioquic's QUIC server and records the ClientHello the browser sends in its Initial packets, then the HTTP/3 request if one arrives. Needs `pybrws[http3]`. To make a browser speak HTTP/3 to the listener at all, it needs an Alt-Svc advertisement over TCP first.

| Option | |
|---|---|
| `--out FILE` | the file to write the hello to |
| `--host`, `--port`, `--hostname` | where to listen, and the name in the certificate |
| `--wait SECONDS` | how long to wait (180) |
| `--dump` | print a hexdump |

### capture resumed

```console
pybrws capture resumed --fresh fresh.hex --resumed resumed.hex
```

Completes the handshake, so the server can issue a session ticket, then captures the next hello, which offers it in `pre_shared_key`. Open the URL it prints and accept the certificate warning; the page reloads itself on a new connection.

| Option | |
|---|---|
| `--fresh FILE` | where to write the first hello, without a ticket |
| `--resumed FILE` | where to write the first hello that offers one |
| `--host`, `--port`, `--hostname`, `--alpn` | as for `capture request` |
| `--wait SECONDS` | how long to wait (180) |
| `--dump` | hexdump the resumed hello |

## read-quic

```console
pybrws read-quic capture.pcapng --host example.com --out quic.hex
```

Recovers QUIC ClientHellos from a `.pcap` or `.pcapng` file of UDP traffic, such as one Wireshark or dumpcap saved while a browser opened a site over HTTP/3. Initial packets are protected with keys anyone can derive (RFC 9001), so no key log is needed. No extra is needed either.

| Option | |
|---|---|
| `CAPTURE` | the packet capture |
| `--port PORT` | the UDP destination port (443), or 0 for every port |
| `--host NAME` | keep the connection whose `server_name` is this |
| `--out FILE` | where to write that hello |
| `--all` | compare every recovered hello: whether the extension order is stable, and which parameters vary |
| `--dump` | print a hexdump |

## ja4

```console
pybrws ja4 --profile chrome155
pybrws ja4 --profile chrome155 --drop 0x12e0
pybrws ja4 --profile my_firefox.py
pybrws ja4 --self-test
```

Computes a profile's JA4 locally, with no request, from a hello built the way the client builds it. Trimmed after `ja4_r`'s cipher list:

```text
$ pybrws ja4 --profile chrome155
chrome155
  ja4      t13d1518h2_8daaf6152771_4980c97edce0
  ja4_o    t13d1518h2_acb858a92679_0e65c2360604
  ja4_r    t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_...
```

| Option | |
|---|---|
| `--profile NAME` | a built-in name or a `.py` file (`firefox157`) |
| `--hostname NAME` | the name in `server_name`; it does not change the JA4 |
| `--drop TYPE` | leave out this extension type, such as `0x12e0`, to see the fingerprint without it; repeatable |
| `--self-test` | reproduce three JA4 values measured independently, to check the arithmetic |

A profile that shuffles its extensions gives a different `ja4_o` on every run and the same `ja4`.

## verify

```console
pybrws verify --local
pybrws verify --local --profile chrome155
pybrws verify --local --profile my_firefox.py --capture my_firefox.hex
pybrws verify
```

`--local` builds the profile's ClientHello and compares it with a browser capture, field by field, offline. For `firefox157` and `chrome155` the capture ships in the package. A profile file has none, so it needs `--capture`, a hex ClientHello such as `pybrws capture hello` writes. The host name in the built hello is taken from the capture's `server_name`, so the two can be compared byte for byte. The report's first line repeats the command:

```text
$ pybrws verify --local --profile firefox157

capture  reference-firefox-157-windows-fresh.hex
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

A field marked `must` is drawn afresh for every connection: its bytes differ, but its length must be the capture's. One marked `drawn` is excused by the profile's [`DRAWN`](profiles.md#drawn), which can hold only the extension order and the lengths a field drawn per connection is drawn from. Content is compared first: a field whose content differs fails whatever `DRAWN` says. A GREASE value compares equal to any other GREASE value; everything else in the lists that carry one must be the capture's. A capture without its 5-byte record header, as Wireshark's handshake layer gives it, is compared without the record version and without our header, and the report says so. A pass is the same JA4 as the capture and no difference outside those two kinds: the JA4 line reads "same string as the capture", and verify exits 0. Otherwise it ends with "Something differs that should not. Not a pass." and exits 1.

Without `--local`, verify fetches `https://tls.peet.ws/api/all` with firefox157 and compares that service's reading with the reading of Firefox 157 that ships in the package. For an outside reading over TCP and QUIC, `pybrws probe` is the other choice.

| Option | |
|---|---|
| `--local` | compare with a capture, offline |
| `--profile NAME` | with `--local`, the profile to build: a built-in name or a `.py` file (`firefox157`) |
| `--capture FILE` | with `--local`, a hex ClientHello from your browser, with or without its record header; needed for a `.py` profile |
| `--hostname NAME` | the name to put in `server_name`, instead of the capture's; the report's `sni` line and first line then say so |
| `--json` | without `--local`, print the service's full report |

## probe

```console
pybrws probe
pybrws probe --profile chrome155 --only tcp
pybrws probe --json
```

Asks an outside service that reflects the caller's fingerprints, over TCP with the profile and over QUIC with `firefox157_quic`, and prints its answers side by side with the differing rows marked. The default service is `https://thumbprint.me/api/v1/probe`. The QUIC arm needs `pybrws[http3]`.

| Option | |
|---|---|
| `--url URL` | the service to ask |
| `--profile NAME` | the TCP arm's profile (`firefox157`); the QUIC arm always sends `firefox157_quic` |
| `--timeout SECONDS` | (20) |
| `--json` | print both raw answers instead of a table |
| `--full` | one block per field, nothing cut short |
| `--only {tcp,quic}` | ask over one transport only |

## ab

```console
pybrws ab --targets https://example.com/
pybrws ab --targets https://example.com/page --control https://example.com/ --rounds 10
pybrws ab --arms pybrws pybrws-h3 httpx --targets https://example.com/
pybrws ab --history
```

Sends each target the same request from several clients, the arms, in interleaved rounds, and prints for each target and arm how many answers were served. A 403, 429 or 503, a redirect left at the end, or a small body that carries a challenge page's marker counts as not served. Every sample is appended to a JSONL log, so a later run can be read against an earlier one.

| Arm | |
|---|---|
| `pybrws` | this client, with `--profile` |
| `httpx` | httpx, with its own TLS and headers |
| `httpx+ff` | httpx carrying the profile's headers: what separates the headers' effect from the TLS fingerprint's |
| `pybrws-h3` | this client over HTTP/3; runs only with `--profile firefox157` and no proxy, so that it differs from `pybrws` in the transport alone |

| Option | |
|---|---|
| `--targets TARGET ...` | the hosts or URLs to measure; required, unless `--history` |
| `--control URL` | a target that serves every client, run in every round; without one there is no control row |
| `--profile NAME` | the profile the `pybrws` arm sends and whose headers `httpx+ff` carries (`firefox157`) |
| `--rounds N` | (4) |
| `--arms ARM ...` | the arms to run (`pybrws httpx httpx+ff`) |
| `--timeout SECONDS`, `--pause SECONDS` | per request (25), and between requests (1) |
| `--proxy URL`, `--use-env` | send the `pybrws` arm through a proxy, given or taken from the environment; this changes address and fingerprint at once, which `pybrws isolate` separates |
| `--log PATH` | the log to append to and read (`ab-test-log.jsonl`, in the current directory) |
| `--no-log` | append nothing |
| `--history` | summarise the log's past runs, and exit |

The httpx arms need `pybrws[measure]`, and `pybrws-h3` needs `pybrws[http3]`.

## isolate

```console
pybrws isolate --targets https://example.com/ --proxy http://user:pass@proxy.example.com:8080
```

Sends each target the same request from four arms: pybrws and httpx, each direct and each through the proxy. Only the full square says whether a difference comes from the fingerprint, from the address, or from both. It prints a table of served counts, then every status. Needs `pybrws[measure]`.

| Option | |
|---|---|
| `--proxy URL` | the proxy of the proxied arms; required, from `PYBRWS_PROXY` when not given |
| `--targets TARGET ...` | the hosts or URLs to measure; required |
| `--rounds N` | (3) |
| `--profile NAME` | the pybrws arms' profile (`firefox157`) |

## waf

```console
pybrws waf --urls urls.txt
pybrws waf --urls urls.txt --vendor NAME
```

Fetches each URL with firefox157 and prints the status and which protection vendors' marks the response carries: a header or a header value, a cookie name, or a phrase on a block page. `urls.txt` holds one URL per line, such as `https://example.com/`; lines that start with `#` are skipped.

| Option | |
|---|---|
| `--urls FILE` | the file of URLs; required |
| `--vendor NAME` | print only the URLs where this vendor's marks were found; the names are the keys of `pybrws.tools.detect_waf.SIGNATURES` |
| `--timeout SECONDS` | (20) |
