# 1. Catching your browser's ClientHello

!!! abstract "TL;DR"
    `pybrws capture hello firefox.hex` opens a plain TCP listener on `127.0.0.1:4443` and writes the first bytes a browser sends to it, its ClientHello, as hex. The listener never answers, so the page fails to load, but by then the hello has been sent. Firefox 157's is 1901 bytes: 15 cipher suites and 17 extensions, with a key_share extension of 1327 bytes. `capture request` and `capture h2` take the request headers. `capture quic` and `read-quic` take the hello Firefox sends over HTTP/3.

## Why start with the hello

The first message a browser sends on a new HTTPS connection is a ClientHello, and it travels in the clear. It lists the cipher suites, groups and extensions the browser supports, in an order the browser chose, and any server can read all of it. TLS fingerprints such as JA4 are computed from it. The request headers come later, inside the encrypted connection. So I started by catching the hello exactly as the browser sends it, byte for byte, before any TLS library could parse it and throw the bytes away.

## A listener that never answers

The way to do that is not to be a TLS server at all. `pybrws capture hello` is a plain TCP socket. It accepts one connection, reads until the browser goes quiet, writes what it read to a file, and closes. The browser's handshake then fails, which does not matter: the hello was the first thing it sent.

```console
pybrws capture hello firefox.hex
```

With the listener waiting, I opened `https://pybrws.127.0.0.1.nip.io:4443/` in Firefox. The page failed to load, and the terminal showed the hello arrive:

!!! note "Screenshot pending: capture-hello-terminal"
    The terminal after Firefox 157 connected to `pybrws capture hello firefox.hex`: the listening line, the connection, and `captured 1901 bytes -> firefox.hex`.

Three things needed care.

- **The name.** Opened as `https://127.0.0.1:4443/`, the browser sends no `server_name` extension: a hello for an IP address is one extension short of the hello it sends to any real site. A name that resolves to `127.0.0.1`, such as `pybrws.127.0.0.1.nip.io`, keeps the extension.
- **The size.** At 1901 bytes, the hello can arrive in more than one TCP segment. So the listener does not stop after the first read. It reads until the browser has been quiet for 0.8 seconds, which `--quiet-after` changes.
- **Only fresh hellos.** The listener never completes a handshake, so the browser never gets a session ticket from it and never offers one. Every hello it catches is a fresh one. A browser that resumes a session sends a different hello, which [step 2](02-compare.md#a-resumed-hello-is-another-hello) catches with `capture resumed`.

Wireshark sees the same bytes on the loopback interface, filtered with `tcp.port == 4443`:

!!! note "Screenshot pending: capture-hello-wireshark"
    Wireshark on the loopback interface, filter `tcp.port == 4443`, with Firefox 157's ClientHello selected. The packet details show the TLS Client Hello, with the cipher suites and the extension list expanded.

## What it wrote

The file is hex, 32 bytes to a line. Mine is in the repository as `fixtures/reference-firefox-157-windows-fresh.hex`. It also ships in the package: it is the capture `pybrws verify --local` compares `firefox157` with. Its first four lines:

```text
1603010768010007640303385239933d597d7b4af6834465b2ebc3b234e4b51b
6c0fef4962f1312f523a552092e41db0ed46c33e887e0145aa5c470abcf0d489
a4101f0e57b9aadb0a5c96eb001e130113031302c02bc02fcca9cca8c02cc030
c013c014009c009d002f0035010006fd0000001c001a0000177079627277732e
```

Read by hand, the start of it is:

```text
16 0301 0768               a TLS record: handshake, version 0x0301, 1896 bytes follow
01 000764                  a handshake message: ClientHello, 1892 bytes follow
0303                       legacy_version
3852...3a55                random, 32 bytes
20 92e4...96eb             session_id: 32 bytes
001e 1301 1303 1302 ...    cipher_suites: 30 bytes, so 15 suites
01 00                      compression_methods: one, null
06fd ...                   extensions: 1789 bytes, the rest of the file
```

Reading 1789 bytes of extensions by hand is not worth doing twice. The parser the tools use does it:

```python
from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello

hello = parse_client_hello(load_hex("firefox.hex"))
print(hello.summary())
```

```text
legacy_version   0x0303
random           385239933d597d7b4af6834465b2ebc3b234e4b51b6c0fef4962f1312f523a55
session_id       (32B) 92e41db0ed46c33e887e0145aa5c470abcf0d489a4101f0e57b9aadb0a5c96eb
cipher_suites    (15)
    0x1301
    0x1303
    0x1302
    0xc02b
    0xc02f
    0xcca9
    0xcca8
    0xc02c
    0xc030
    0xc013
    0xc014
    0x009c
    0x009d
    0x002f
    0x0035
compression      [0]
extensions       (17)
        0  server_name                    28B
       23  extended_master_secret          0B
    65281  renegotiation_info              1B
       10  supported_groups               12B
       11  ec_point_formats                2B
       35  session_ticket                  0B
       16  alpn                           14B
        5  status_request                  5B
       34  delegated_credentials          10B
       18  signed_certificate_timestamp    0B
       51  key_share                    1327B
       43  supported_versions              5B
       13  signature_algorithms           24B
       45  psk_key_exchange_modes          2B
       28  record_size_limit               2B
       27  compress_certificate            7B
    65037  encrypted_client_hello        282B
total raw        1901 bytes
```

## Reading what it caught

Most of the list is a few bytes of fixed values. Four fields stand out, and they come back in every later step.

- **random and session_id**, 32 bytes each, are drawn afresh for every connection. No profile copies them.
- **key_share** is 1327 bytes, most of the hello. Firefox sends three key shares: X25519MLKEM768, a post-quantum hybrid, with a 1216-byte public key; x25519 with 32 bytes; and secp256r1 with 65. Each share carries 4 bytes of header and the list 2 more: 2 + 1220 + 36 + 69 = 1327. The keys are new on every connection, but the groups and their sizes are the fingerprint.
- **encrypted_client_hello** is 282 bytes. The server published no ECH configuration, so Firefox sends a greased one: random bytes in the shape of a real ECH extension, with a 32-byte key and a 240-byte payload. The contents change on every connection. Their sizes are the fingerprint.
- **server_name** is 28 bytes: the 23 characters of `pybrws.127.0.0.1.nip.io` and 5 bytes of header.

The cipher suites are TLS 1.3's three first, in Firefox's order: `0x1301`, `0x1303`, `0x1302`. Then come twelve for TLS 1.2.

## The request headers

The hello is what a server reads before the request. The request itself arrives inside the encrypted connection, so catching it needs a server that completes the handshake. `capture request` (HTTP/1.1) and `capture h2` (HTTP/2) serve a self-signed certificate. I opened the same URL, accepted the browser's warning, and the request arrived decrypted:

```console
pybrws capture request firefox-h1.txt
pybrws capture h2 firefox-h2.txt
```

`capture h2` writes the header list to the file, in wire order. It writes what the browser's first frames said to `firefox-h2.frames.json` beside it: the settings, the window update, the first stream id and the priority. Step 3 reads them. Firefox 157's navigation, as `fixtures/reference-firefox-157-h2.txt` holds it:

```text
:method: GET
:path: /
:authority: pybrws.127.0.0.1.nip.io:4443
:scheme: https
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
accept-language: en-US,en;q=0.9
accept-encoding: gzip, deflate, br, zstd
upgrade-insecure-requests: 1
sec-fetch-dest: document
sec-fetch-mode: navigate
sec-fetch-site: none
sec-fetch-user: ?1
priority: u=0, i
te: trailers
```

The order is part of the fingerprint, down to the four pseudo-headers. Firefox sends `:method`, `:path`, `:authority`, `:scheme`.

!!! note "Screenshot pending: capture-h2-terminal"
    The terminal after Firefox 157 loaded the page from `pybrws capture h2 firefox-h2.txt`: the listening lines, the captured request, the frames the browser sent, and the decoded header list.

A navigation is one request among several. The same tools take the others a profile needs: `--set-cookie` shows where the Cookie header goes, `--post` captures form and `fetch()` POSTs, and `--any-request` captures an image request. The [command line](../cli.md#capture) lists them.

## Over HTTP/3

Over HTTP/3, Firefox sends another hello. It travels inside QUIC Initial packets, which are encrypted, but with keys anyone can derive from the packet itself (RFC 9001). So the hello can be read from an ordinary packet capture, with no key log. I recorded UDP port 443 in Wireshark while Firefox opened a site over HTTP/3, saved the capture, and read it:

```console
pybrws read-quic capture.pcapng --host example.com --out firefox-quic.hex
```

`--host` picks the connection whose `server_name` is that name, and `--out` writes its hello. `pybrws capture quic --out firefox-quic.hex` is the other way: a local QUIC listener on the same port, over UDP. The hard part there is getting the browser to try HTTP/3 against a local listener at all. It has to learn that the host speaks HTTP/3 from an `Alt-Svc` header over TCP first. `capture quic` needs the `http3` extra. `read-quic` needs no extra.

`read-quic` prints the hello it recovered. For the hello in `fixtures/reference-firefox-157-quic.hex`, from its extension list on:

```text
  extensions, in wire order:
    0      server_name                           54
    13     signature_algorithms                  24
    45     psk_key_exchange_modes                 2
    28     record_size_limit                      2
    65281  renegotiation_info                     1
    43     supported_versions                     3
    51     key_share                           1327
    5      status_request                         5
    27     compress_certificate                   7
    10     supported_groups                      12
    23     extended_master_secret                 0
    34     delegated_credentials                 10
    16     alpn                                   5
    57     quic_transport_parameters             86
    65037  encrypted_client_hello               282

  quic_transport_parameters, in wire order:
    0x1      max_idle_timeout                   80007530
    0x4      initial_max_data                   81800000
    0x5      initial_max_stream_data_bidi_local 80c00000
    0x6      initial_max_stream_data_bidi_remote 80100000
    0x7      initial_max_stream_data_uni        80100000
    0x8      initial_max_streams_bidi           4064
    0x9      initial_max_streams_uni            4064
    0xb      max_ack_delay                      14
    0xe      active_connection_id_limit         08
    0xf      initial_source_connection_id       b90271
    0x11     version_information                000000011aea6a5a6b3343cf00000001
    0x1d     reset_stream_at                    (empty)
    0xff02de1a GREASE                             43e8
    0x20     max_datagram_frame_size            8000ffff
```

It is a different hello from the one over TCP:

- 15 extensions instead of 17. `session_ticket`, `ec_point_formats` and `signed_certificate_timestamp` are gone. `quic_transport_parameters` is new: 14 values in an order of Firefox's own.
- Three cipher suites, the TLS 1.3 ones, and `supported_versions` offers TLS 1.3 alone.
- The same three key shares, 1327 bytes, and the same greased ECH, 282 bytes.

That is why pybrws has a separate profile for it, `firefox157_quic`. [Profiles](../profiles.md) lists what each of the three draws for every connection, and [step 2](02-compare.md) shows how to find that out.
