# 2. What changes between connections

!!! abstract "TL;DR"
    One capture is one sample, and in one sample every field looks like a constant. Take several. Five Firefox 157 hellos have their 17 extensions in the same order; between them only the random, the session id, the key shares and the greased ECH change. Six Chrome 155 hellos have six different orders: 18 extensions shuffled between two GREASE extensions, a GREASE value at the head of five lists, and a greased ECH payload of 144, 208 or 240 bytes. A resumed connection sends a third kind of hello. JA4 sorts what Chrome shuffles, so the six Chrome hellos share one `ja4`, and each has its own `ja4_o`.

## Six at once

A browser opens several connections while it loads a page, so one visit can give several hellos. `--count` keeps the listener open for that many, writes each one, and compares them:

```console
pybrws capture hello --count 6 chrome.hex
```

It writes `chrome-1.hex` to `chrome-6.hex`, then prints the comparison:

!!! note "Screenshot pending: capture-count-terminal"
    The terminal after Chrome 155 loaded the page from `pybrws capture hello --count 6 chrome.hex`: six lines of bytes received, the six `wrote` lines, and the comparison that ends with the pinned GREASE at both ends.

The comparison is computed from the files, so it can be run again on them at any time. On my six Chrome 155 captures, `fixtures/chrome-1.hex` to `chrome-6.hex`:

```python
from pybrws.hexio import load_hex
from pybrws.tools.catch_hello import compare

compare([load_hex(f"chrome-{n}.hex") for n in range(1, 7)])
```

```text
6 hello(s), 6 distinct order(s), 1 distinct set(s), GREASE collapsed to 'GREASE'
  GREASE 35 16 23 10 51 65037 5 51764 0 11 45 17613 27 65281 43 18 4832 13 GREASE
  GREASE 13 27 43 18 10 5 45 4832 51 16 0 65281 11 51764 17613 23 35 65037 GREASE
  GREASE 51764 18 10 11 65037 45 23 51 65281 27 43 35 4832 5 16 0 17613 13 GREASE
  GREASE 17613 35 18 10 65037 43 11 65281 0 27 45 13 23 51764 16 5 51 4832 GREASE
  GREASE 23 18 17613 10 51764 45 4832 65281 51 11 5 27 0 13 43 65037 35 16 GREASE
  GREASE 5 11 27 16 35 65037 45 4832 18 23 17613 0 10 51 43 65281 51764 13 GREASE
  -> a different order each time: it is drawn per connection, so the profile has to draw one too.
     pinned at the front: GREASE
     pinned at the end:   GREASE
```

Six connections, six orders, one set. Laid side by side, the orders agree on no position but the two ends. The same comparison on five Firefox 157 hellos, `fixtures/firefox-1.hex` to `firefox-5.hex`:

```text
5 hello(s), 1 distinct order(s), 1 distinct set(s), GREASE collapsed to 'GREASE'
  0 23 65281 10 11 35 16 5 34 18 51 43 13 45 28 27 65037
  -> the same order 5 times: it is stored, and the profile can hold it as a list.
```

So Firefox's order over TCP is a constant, and its profile holds it as a list. Chrome's is drawn, so its profile has to draw one for every connection.

## GREASE

Before it compares anything, the comparison collapses every GREASE value to one name. GREASE (RFC 8701) is a set of 16 reserved values, `0x0a0a`, `0x1a1a` and so on up to `0xfafa`, which a client sends so that servers keep tolerating values they do not know. Chrome draws a fresh one for each place it uses them, on every connection. Compared raw, six captures of one browser look like six different clients.

These are the values in my six Chrome captures:

| Where | chrome-1 | chrome-2 | chrome-3 | chrome-4 | chrome-5 | chrome-6 |
|---|---|---|---|---|---|---|
| first extension | `caca` | `caca` | `caca` | `1a1a` | `baba` | `eaea` |
| cipher suites, at the head | `baba` | `aaaa` | `0a0a` | `aaaa` | `6a6a` | `5a5a` |
| supported_groups and key_share, at the head | `6a6a` | `6a6a` | `7a7a` | `fafa` | `2a2a` | `caca` |
| supported_versions, at the head | `3a3a` | `8a8a` | `2a2a` | `9a9a` | `baba` | `eaea` |
| signature_algorithms, at the head | `2a2a` | `9a9a` | `dada` | `dada` | `9a9a` | `baba` |
| last extension | `eaea` | `5a5a` | `4a4a` | `6a6a` | `4a4a` | `1a1a` |

Three regularities hold in all six, and the profile has to keep each one:

- `supported_groups` and `key_share` carry the same value. A key share has to name a group the client offered, and Chrome's greased key share is one byte, `00`.
- The first greased extension is empty, and the last carries one zero byte.
- The first and last extensions never share a value. A hello may not carry the same extension type twice (RFC 8446, section 4.2), and two independent draws from 16 values would collide one time in 16. So chrome155 draws the last one from the 15 values the first did not take.

!!! note "Screenshot pending: chrome-grease-wireshark"
    Wireshark with one of Chrome 155's ClientHellos to the listener selected. The packet details show the cipher suites and the extension list expanded, with a GREASE entry at the head of the cipher suites and GREASE extensions first and last.

## Field by field

With the order settled, the payloads. Compared byte for byte across the captures of each browser:

| | Firefox 157, five hellos | Chrome 155, six hellos |
|---|---|---|
| length | 1901 bytes every time | 1937, 2001, 1937, 2001, 2001 and 2033 bytes |
| random, session_id | new every time, 32 bytes each | new every time, 32 bytes each |
| cipher suites | the same 15 in the same order | the same 15 in the same order, behind a GREASE value |
| extension payloads the same byte for byte | 15 of 17 | 13 of 18 |
| supported_groups, supported_versions, signature_algorithms | among those 15 | the same once the GREASE value at the head is removed |
| key_share | new keys every time: X25519MLKEM768, x25519, secp256r1 | new keys every time, behind the greased entry: X25519MLKEM768, x25519 |
| encrypted_client_hello | random bytes; AEAD id `0x0001` or `0x0003`; payload 240 bytes | random bytes; AEAD id `0x0001`; payload 144, 208 or 240 bytes |

Chrome's length is the ECH payload moving. The hellos with a 144-byte payload are 1937 bytes, those with 208 are 2001, and the one with 240 is 2033. Everything else in the hello keeps its size. Six samples gave 144 twice, 208 three times and 240 once. That cannot establish which sizes exist, or how often each is drawn. chrome155 draws the three it saw with equal chance, and more captures would settle it.

Firefox has its own small draw: the ECH extension names AEAD `0x0001` in some hellos and `0x0003` in others. Missing that would give every connection the same AEAD id, a detail no single capture shows.

## A resumed hello is another hello

`capture hello` never completes a handshake, so the browser never has a session ticket to offer it. `capture resumed` completes one, so that the server can issue a ticket, lets the page reload on a new connection, and keeps both hellos:

```console
pybrws capture resumed --fresh fresh.hex --resumed resumed.hex
```

Firefox 157's pair is in the repository as `reference-firefox-157-windows-fresh.hex` and `reference-firefox-157-windows-resumed.hex`. Saved as `fresh.hex` and `resumed.hex`:

```python
from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello

for name in ("fresh.hex", "resumed.hex"):
    hello = parse_client_hello(load_hex(name))
    print(f"{name}: {len(hello.raw)} bytes, {len(hello.extensions)} extensions, the last three:")
    for extension in hello.extensions[-3:]:
        print(f"    {extension.name:<24} {len(extension.data):>4} bytes")
```

```text
fresh.hex: 1901 bytes, 17 extensions, the last three:
    record_size_limit           2 bytes
    compress_certificate        7 bytes
    encrypted_client_hello    282 bytes
resumed.hex: 2472 bytes, 17 extensions, the last three:
    compress_certificate        7 bytes
    encrypted_client_hello    570 bytes
    pre_shared_key            283 bytes
```

`session_ticket` is gone, and `pre_shared_key` is last, where RFC 8446 requires it. The ECH extension grew by 288 bytes, from 282 to 570. That is about the size of the pre_shared_key extension, which is 287 bytes with its type and length fields. I cannot explain the one byte left over; firefox157 records it as measured, in `ech_growth_for_psk`. No resumed Chrome hello was captured, so chrome155 resumes in Firefox's shape: [Sent without a capture](../profiles.md#sent-without-a-capture) says so.

## JA4: what a fingerprint keeps

JA4 is the fingerprint most services report for a hello. It has three parts:

- the first part counts: `t13d1518h2` is TCP, TLS 1.3, a domain name in `server_name`, 15 cipher suites, 18 extensions with GREASE left out, and `h2` as the first ALPN value;
- the second is a hash of the cipher suites, sorted;
- the third is a hash of the extensions, sorted, without `server_name` and ALPN, then the signature algorithms in the order sent.

The sorting is the point. `ja4_o` hashes the cipher suites in the order sent, and every extension type in the order sent, `server_name` and ALPN included, GREASE left out. On the six Chrome captures:

```python
from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello
from pybrws.tools.ja4 import compute

for n in range(1, 7):
    hello = parse_client_hello(load_hex(f"chrome-{n}.hex"))
    fingerprint = compute(hello, drop=set())
    print(f"chrome-{n}.hex  {len(hello.raw)} bytes  {fingerprint['ja4']}  {fingerprint['ja4_o']}")
```

```text
chrome-1.hex  1937 bytes  t13d1518h2_8daaf6152771_4980c97edce0  t13d1518h2_acb858a92679_e1690d71140d
chrome-2.hex  2001 bytes  t13d1518h2_8daaf6152771_4980c97edce0  t13d1518h2_acb858a92679_5a51eb11b663
chrome-3.hex  1937 bytes  t13d1518h2_8daaf6152771_4980c97edce0  t13d1518h2_acb858a92679_23b5ec3ffafd
chrome-4.hex  2001 bytes  t13d1518h2_8daaf6152771_4980c97edce0  t13d1518h2_acb858a92679_74beba7150f0
chrome-5.hex  2001 bytes  t13d1518h2_8daaf6152771_4980c97edce0  t13d1518h2_acb858a92679_0ff126c1fccc
chrome-6.hex  2033 bytes  t13d1518h2_8daaf6152771_4980c97edce0  t13d1518h2_acb858a92679_df9f5b1675ca
```

One `ja4` and six `ja4_o`. `pybrws ja4` computes the same from a profile, with no request: it builds the hello the way the client does. chrome155 draws a new order every time, so two runs give the same `ja4` and two different `ja4_o`. Each run is trimmed here after `ja4_r`'s cipher list:

```console
pybrws ja4 --profile chrome155
```

```text
chrome155
  ja4      t13d1518h2_8daaf6152771_4980c97edce0
  ja4_o    t13d1518h2_acb858a92679_223b519e5d14
  ja4_r    t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_...
```

```text
chrome155
  ja4      t13d1518h2_8daaf6152771_4980c97edce0
  ja4_o    t13d1518h2_acb858a92679_ec65f627e401
  ja4_r    t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_...
```

Firefox's middle part is the same as Chrome's, `8daaf6152771`: both offer the same 15 cipher suites, in different orders. Its JA4 is `t13d1517h2_8daaf6152771_3cbfd9057e0d` in all five captures. The resumed hello has a JA4 of its own, `t13d1517h2_8daaf6152771_e6dcd7ae0a9e`, because `pre_shared_key` replaces `session_ticket`.

What JA4 cannot see matters as much. It reads three payloads: the signature algorithms, the first ALPN value and the highest TLS version. Every other extension reaches it as a type alone, so neither the lengths nor the bytes of the key shares or the ECH extension count. A hello with a 208-byte ECH payload where Firefox sends 240 has Firefox's JA4. That is why [step 4](04-verify.md) compares bytes and sizes, not only fingerprints.

## What goes into the profile

The comparison sorts every field into one of two kinds, and [step 3](03-profile.md) writes each kind differently.

- **The same in every capture:** a value, copied from the capture. Firefox's extension order, the cipher suites, every payload but `key_share` and `encrypted_client_hello`, the key share groups and their sizes, the ECH payload size. `server_name` was the same in every capture too, but it carries the host the client connects to, so the profile builds it from that host.
- **Drawn per connection:** a function of the connection. The random and session id, the keys, the greased ECH bytes, Firefox's ECH AEAD id, and for Chrome the order, every GREASE value and the ECH payload size.

Over QUIC, Firefox draws its order too. `firefox157_quic` draws 13 extensions in a new order every time, then sends `quic_transport_parameters` and `encrypted_client_hello` last. `pybrws read-quic capture.pcapng --all` compares every hello in a packet capture in the same way.
