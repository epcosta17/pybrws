# 3. Writing the profile

!!! abstract "TL;DR"
    A profile is a Python file of constants and a few functions. What step 2 found to be the same in every capture goes in as a value, copied from the capture. What it found drawn per connection goes in as a function of the connection. The quickest start is the example, [my_firefox.py](../examples/my_firefox.py): firefox157's values under a name of its own, with every name of the contract spelled out. Change what your browser sends differently, then check the result in step 4. For a browser that shuffles its extensions, start from chrome155 instead.

## Start from the example

I wrote firefox157 by hand from the captures. You do not have to start from nothing. [my_firefox.py](../examples/my_firefox.py) is a complete profile: firefox157's values under the name `my_firefox`, with a comment on each group of names. Download it and keep it beside your capture. Every `--profile` takes a path as well as a name:

```console
pybrws verify --local --profile my_firefox.py --capture firefox.hex
pybrws https://example.com/ --profile my_firefox.py
```

[Writing your own](../profiles.md#writing-your-own) has the loading rules, and [the contract](../profiles.md#the-contract-over-tcp) lists every name a profile defines.

## From bytes to constants

Every value in the file was read from a capture. The hello's are the easiest to see. Here is each extension's payload in my Firefox capture, the first 14 bytes of each:

```python
from pybrws.hexio import load_hex
from pybrws.parser import parse_client_hello

hello = parse_client_hello(load_hex("firefox.hex"))
print(" ".join(f"{suite:04x}" for suite in hello.cipher_suites))
for extension in hello.extensions:
    print(f"{extension.type:>5}  {extension.name:<28} {extension.data[:14].hex()}")
```

```text
1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c013 c014 009c 009d 002f 0035
    0  server_name                  001a0000177079627277732e3132
   23  extended_master_secret       
65281  renegotiation_info           00
   10  supported_groups             000a11ec001d001700180019
   11  ec_point_formats             0100
   35  session_ticket               
   16  alpn                         000c02683208687474702f312e31
    5  status_request               0100000000
   34  delegated_credentials        00080403050306030203
   18  signed_certificate_timestamp 
   51  key_share                    052d11ec04c06808a27e58b02d1a
   43  supported_versions           0403040303
   13  signature_algorithms         0016040305030603080408050806
   45  psk_key_exchange_modes       0101
   28  record_size_limit            4001
   27  compress_certificate         06000100020003
65037  encrypted_client_hello       0000010001b00020f531d41e7554
```

Fourteen of those payloads were the same in every capture, so firefox157 holds them as bytes, copied from the capture. It builds the other three for each connection: `server_name` from the host it connects to, `key_share` from new keys, and the ECH extension from random bytes. This is its list, from `pybrws/profiles/firefox157.py`, in wire order:

```python
EXTENSIONS: list[tuple[int, bytes | object]] = [
    (0, server_name),
    (23, b""),                                              # extended_master_secret
    (65281, bytes.fromhex("00")),                           # renegotiation_info
    (10, bytes.fromhex("000a11ec001d001700180019")),        # supported_groups
    (11, bytes.fromhex("0100")),                            # ec_point_formats
    (35, b""),                                              # session_ticket
    (16, bytes.fromhex("000c02683208687474702f312e31")),    # alpn: h2, http/1.1
    (5, bytes.fromhex("0100000000")),                       # status_request
    (34, bytes.fromhex("00080403050306030203")),            # delegated_credentials
    (18, b""),                                              # signed_certificate_timestamp
    (51, key_share),
    (43, bytes.fromhex("0403040303")),                      # supported_versions
    (13, bytes.fromhex("001604030503060308040805080604010501060102030201")),
    (45, bytes.fromhex("0101")),                            # psk_key_exchange_modes
    (28, bytes.fromhex("4001")),                            # record_size_limit
    (27, bytes.fromhex("06000100020003")),                  # compress_certificate
    (65037, greased_ech),
]
```

The cipher suites go in `CIPHER_SUITES` the same way, in the order sent. my_firefox.py takes the whole list with `EXTENSIONS = firefox157.EXTENSIONS`. To change one payload, write the list out in your file and change that line.

## The three functions

**`server_name(ctx)`** returns the payload for `ctx.hostname`, or `None` for an IP address, which leaves the extension out as the browser does.

**`key_share(ctx)`** cannot copy anything: each share is the public half of a real key pair, new for every connection, and the client needs the private half to read the server's answer. What the capture fixes is which groups, in which order, and how big each public key is. So the profile holds `KEY_SHARE_GROUPS`, `(0x11EC, 1216), (0x001D, 32), (0x0017, 65)` for Firefox 157. A connection makes one key pair for each group in that list, and `pybrws verify` builds them the same way. The function lays them out, checking each one's size. The 1216 bytes of the X25519MLKEM768 share are an ML-KEM-768 encapsulation key of 1184 bytes followed by an x25519 public key of 32.

One thing to know before you change the groups: firefox157's `key_share` checks the shares against firefox157's own `KEY_SHARE_GROUPS`, not yours. A list that keeps Firefox's first groups in Firefox's order works as it is. Two shares, as Chrome 155 sends, take one line in my_firefox.py:

```python
KEY_SHARE_GROUPS = [(0x11EC, 1216), (0x001D, 32)]
```

The extension is then 1258 bytes, 2 + 1220 + 36, in `pybrws verify --local` and on a connection alike. A group after the third is left out, and any other list stops the hello from being built. With x25519 first, `[(0x001D, 32), (0x11EC, 1216)]`:

```console
pybrws verify --local --profile my_firefox.py --capture firefox.hex
```

```text
cannot build a hello from profile 'my_firefox': ValueError: key_share for 0x11ec: expected 1216 bytes from 0x001d, got 32
```

A connection stops at the same place, before any socket is opened, and says the same in one line:

```console
pybrws https://example.com/ --profile my_firefox.py
```

```text
ProfileError: cannot build a hello from profile 'my_firefox': ValueError: key_share for 0x11ec: expected 1216 bytes from 0x001d, got 32
```

For a list like that, write `key_share` in your file and put it in `EXTENSIONS`. In my_firefox.py, these lines take the place of the `KEY_SHARE_GROUPS` and `EXTENSIONS` lines:

```python
from pybrws.profiles import firefox157
from pybrws.wire import u16, vector

KEY_SHARE_GROUPS = [(0x001D, 32), (0x11EC, 1216)]


def key_share(ctx):
    entries = b""
    for (group, size), (offered, share) in zip(KEY_SHARE_GROUPS,
                                               ctx.key_exchange.client_shares()):
        if offered != group or len(share) != size:
            raise ValueError("key_share for 0x%04x: wrong size" % group)
        entries += u16(group) + vector(share, 2)
    return vector(entries, 2)


EXTENSIONS = [(kind, key_share if kind == 51 else payload)
              for kind, payload in firefox157.EXTENSIONS]
```

`ctx.key_exchange` holds the key pairs made for your list. The extension is 1258 bytes again, with x25519 first.

**`greased_ech(ctx)`** fills the shape step 2 measured with random bytes. From firefox157, without its comments:

```python
ECH_OUTER = 0x00
ECH_KDF_ID = 0x0001
ECH_AEAD_IDS = (0x0001, 0x0003)
ECH_ENC_SIZE = 32
ECH_PAYLOAD_SIZE = 240


def greased_ech(ctx) -> bytes:
    return (
        u8(ECH_OUTER)
        + u16(ECH_KDF_ID)
        + u16(ctx.choice(ECH_AEAD_IDS))
        + u8(ctx.random(1)[0])
        + vector(ctx.random(ECH_ENC_SIZE), 2)
        + vector(ctx.random(ECH_PAYLOAD_SIZE), 2)
    )
```

It is the same story as the key share: the bytes are random, and the sizes are the fingerprint. The function reads firefox157's constants as well, so a browser with another payload size needs its own `greased_ech` in `EXTENSIONS`.

The resumed hello from step 2 adds one optional name: `ech_growth_for_psk(size)` says how much the ECH payload grows when a session ticket is offered. In firefox157 it is the pre_shared_key extension's size plus the one unexplained byte.

`ctx` is the connection whose hello is being built. Besides `ctx.hostname` and `ctx.random(n)`, it gives `ctx.choice(values)`, `ctx.grease(slot)` and `ctx.once(key, factory)`. [The contract](../profiles.md#the-contract-over-tcp) describes each one.

## A browser that shuffles

chrome155 cannot hold its order in a list. In place of `EXTENSIONS` it defines two functions. `extension_order(ctx)` returns one connection's order, and `payload_for(type, ctx)` returns each payload. The order, from `pybrws/profiles/chrome155.py` without its docstring:

```python
def extension_order(ctx) -> list[int]:
    drawn = list(SHUFFLED)
    for index in range(len(drawn) - 1, 0, -1):
        pick = _below(ctx, index + 1)
        drawn[index], drawn[pick] = drawn[pick], drawn[index]
    first, last = pinned_pair(ctx)
    return [first] + drawn + [last]
```

`SHUFFLED` is the 18 extension types, and `pinned_pair` draws the two GREASE extensions, different from each other. The details were the hard part:

- **The shuffle has to be fair.** `_below` draws an index by rejection: a byte at or above the largest multiple of the limit is thrown away and drawn again. Taking a random byte modulo 18 instead would favour indices 0 to 3 slightly, since 256 is 14 × 18 + 4. Over enough connections, a skew like that is itself a fingerprint.
- **GREASE values belong to the connection.** `ctx.grease(slot)` draws a value once per connection for each slot name. `supported_groups` and `key_share` ask for the same slot, `"groups"`, which is how they carry the same value.
- **The ECH payload size is drawn too:** 144, 208 or 240 bytes, with equal chance. chrome155 fills the ECH extension's 32-byte key field with a real x25519 public key, from a key pair drawn per connection. firefox157 fills it with random bytes.

GREASE values need no declaration: `pybrws verify` compares any GREASE value as equal to any other, in every list that carries one. What else a browser draws per connection, the profile names in [`DRAWN`](../profiles.md#drawn), so that step 4 reports it as drawn, not as a failure. `DRAWN` can excuse an order of extensions or a size, nothing else. chrome155 names its extension order, its ECH payload's size, and with it the whole hello's length. For a Chrome of your own, start from chrome155. `from pybrws.profiles.chrome155 import *` copies every name, `DRAWN` included, and step 4 shows such a copy pass.

## HTTP/2

The start of an HTTP/2 connection is a fingerprint of its own. `capture h2` writes it to its `.frames.json` file. Chrome 155's, as `fixtures/reference-chrome-155-h2.frames.json` holds it:

```text
{
  "connection_window_update": 15663105,
  "first_stream_id": 1,
  "headers_flags": 37,
  "headers_priority": {
    "dependency": 0,
    "exclusive": true,
    "weight": 256
  },
  "settings": [
    [
      1,
      65536
    ],
    [
      2,
      0
    ],
    [
      4,
      6291456
    ],
    [
      6,
      262144
    ]
  ]
}
```

Four of its fields are names in the profile. The fifth, `headers_flags`, is 37: the HEADERS frame carried a priority (0x20), ended the headers (0x4) and ended the stream (0x1). For Firefox, the values are in the outside reading of Firefox 157 that ships in the package. Its HTTP/2 string, `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`, gives the settings, the window update, no PRIORITY frames and the pseudo-header order. Its record of the HEADERS frame gives stream 3 and weight 42.

| Name | firefox157 | chrome155 |
|---|---|---|
| `H2_SETTINGS` | 1: 65536, 2: 0, 4: 131072, 5: 16384 | 1: 65536, 2: 0, 4: 6291456, 6: 262144 |
| `H2_CONNECTION_WINDOW_UPDATE` | 12517377 | 15663105 |
| `H2_FIRST_STREAM_ID` | 3 | 1 |
| `H2_HEADERS_PRIORITY` | weight 42, depends on 0, not exclusive | weight 256, depends on 0, exclusive |
| `H2_PSEUDO_ORDER` | `:method :path :authority :scheme` | `:method :authority :scheme :path` |

The two browsers agree on settings 1 and 2, and both make the request depend on stream 0. Every other value differs. Firefox sends setting 5, the largest frame it accepts. Chrome sends setting 6 instead, the largest header list it accepts.

## The headers

`H2_NAVIGATION_HEADERS` is the header file from step 1 without the pseudo-headers, in wire order. `H1_HEADERS` comes from `capture request` with each name in the case it was sent. Values that change per request are placeholders, such as `{authority}` or `{cookie}`: [Profiles](../profiles.md#the-contract-over-tcp) lists them, and [Where cookies go](../profiles.md#where-cookies-go) explains the cookie anchors.

Three things in Chrome's header captures could not be copied as they were:

- **The case is mixed over HTTP/1.1.** The client hints are lower case and everything else is capitalised, so a client that normalises the case either way gets it wrong. Three consecutive lines of Chrome's HTTP/1.1 capture:

    ```text
    sec-ch-ua-mobile: ?0
    sec-ch-ua-platform: "Windows"
    Upgrade-Insecure-Requests: 1
    ```

- **The navigations carry a reload's header.** Each of Chrome's navigation captures, form POSTs included, carries `cache-control: max-age=0`, the header Chrome adds when a page is reloaded. Sent on every request, it would describe a browser that reloads every page it visits. So chrome155 sends its sets without it, and keeps the captured sets under `CAPTURED_` names, which the tests compare with the captures.
- **Accept-Language is the capturing machine's locale.** It describes a person, not the browser. chrome155 keeps the captured value for the tests and sends `en-US,en;q=0.9`, as firefox157 does.

## Let the loader check it

pybrws checks a profile file against the contract when it loads it. A missing name stops it before anything is built. This is my_firefox.py with the `H2_SETTINGS` line deleted and the name changed to `incomplete`:

```console
pybrws verify --local --profile incomplete.py --capture firefox.hex
```

```text
profile 'incomplete' is missing: H2_SETTINGS
```

The message lists every name missing. When the file loads, [step 4](04-verify.md) compares what it builds with your capture.
