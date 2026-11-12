# 4. Proving it

!!! abstract "TL;DR"
    `pybrws verify --local --profile my_firefox.py --capture firefox.hex` builds the profile's hello for the capture's host and compares the two field by field, with no network. A pass ends with "same string as the capture" and exits 0. The fields drawn afresh for every connection are listed, each with the reason it must differ, and their sizes must still match. A GREASE value compares equal to any other, and nothing else is excused unless the profile's `DRAWN` names it. A JA4 alone misses a wrong order or a wrong size; verify catches both. Then `pybrws probe` asks an outside service what arrived over a real network.

## Byte for byte, offline

The profile from step 3 against the capture from step 1:

```console
pybrws verify --local --profile my_firefox.py --capture firefox.hex
```

```text
$ pybrws verify --local --profile my_firefox.py --capture firefox.hex

capture  firefox.hex
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

Line by line:

- **The first line** repeats the command, so a report pasted somewhere says what produced it.
- **`sni`**: verify builds the hello for the name in the capture's `server_name`. The name's length moves every length field that contains it, so a hello built for another host could not be compared byte for byte. `--hostname` sets another name, and the report then says so.
- **`ours` and `real`**: the sizes of the two hellos. They must be equal, unless the profile's `DRAWN` names `length` and the sizes it excuses account for the difference.
- **`version`, `cipher suites`, `extensions`**: compared in order. `version` covers the record's version and the hello's. In a list that carries GREASE, each GREASE value compares equal to any other.
- **`payloads`**: how many extension payloads are the same, byte for byte.
- **Every field that differs**, with the reason. `must` marks a field drawn afresh for every connection: the random, the session id, the keys and the greased ECH. A hello that copied those from the capture would be broken, not closer. Their sizes are still compared.
- **`ja4`**: the JA4 of both hellos. "same string as the capture", with no field marked `UNEXPECTED`, is a pass, and verify exits 0.

## A browser that draws

Chrome's hellos differ from each other, so a Chrome profile cannot match any one capture the way Firefox's does. Its GREASE values need nothing: verify compares any GREASE value as equal to any other. What else Chrome draws per connection, the order of its extensions and the size of its ECH payload, is named in the profile's `DRAWN`. A copy of chrome155 made with one import inherits it:

```python
from pybrws.profiles.chrome155 import *

NAME = "my_chrome"
```

Against the second of my six captures:

```console
pybrws verify --local --profile my_chrome.py --capture chrome-2.hex
```

```text
$ pybrws verify --local --profile my_chrome.py --capture chrome-2.hex

capture  chrome-2.hex
sni      pybrws.127.0.0.1.nip.io   (taken from the capture)
ours     1937 bytes   drawn (ECH payload length drawn from 144, 208, 240)
real     2001 bytes

version ....... match
cipher suites . match   15, same order, 1 greased
payloads ...... 16 of 18   13 byte for byte, 3 with GREASE normalised

random ........ differs   must (32 fresh random bytes)
session_id .... differs   must (32 fresh random bytes)
extensions .... differs   drawn (order drawn per connection)
key_share ..... differs   must (a real keypair)
encrypted_client_hello  differs   drawn (payload length drawn from 144, 208, 240)

ja4  t13d1518h2_8daaf6152771_4980c97edce0
     same string as the capture
```

Line by line, what changed from Firefox's report:

- **The cipher suites match with their GREASE value**: one at the head, in both hellos.
- **16 of the 18 payloads match.** Thirteen match byte for byte, as step 2 found between the captures themselves. The other three are `supported_groups`, `signature_algorithms` and `supported_versions`, the same lists once each GREASE value is normalised.
- **`drawn` marks what the profile's `DRAWN` names**, with the reason it gives. The extensions are the same set in another order, and `DRAWN` excuses only the order: a missing or an extra extension would be `UNEXPECTED`.
- **Two sizes are drawn too.** In this run the profile drew a 144-byte ECH payload where the capture has 208, so the hellos are 1937 and 2001 bytes. `DRAWN` names the ECH extension's size, and that one difference accounts for the whole hello's. In a run that draws the capture's size, both hellos are 2001 bytes and the ECH line reads `must (greased payload)`.

## What a failure looks like

To see one, I swapped two extensions in a copy of firefox157:

```python
from pybrws.profiles import firefox157
from pybrws.profiles.firefox157 import *

NAME = "swapped"
EXTENSIONS = list(firefox157.EXTENSIONS)
EXTENSIONS[5], EXTENSIONS[6] = EXTENSIONS[6], EXTENSIONS[5]   # alpn before session_ticket
```

```console
pybrws verify --local --profile swapped.py --capture firefox.hex
```

```text
$ pybrws verify --local --profile swapped.py --capture firefox.hex

capture  firefox.hex
sni      pybrws.127.0.0.1.nip.io   (taken from the capture)
ours     1901 bytes
real     1901 bytes

version ....... match
cipher suites . match   15, same order
payloads ...... 15 of 17   byte for byte

random ........ differs   must (32 fresh random bytes)
session_id .... differs   must (32 fresh random bytes)
extensions .... differs   UNEXPECTED -- the same extensions in another order
key_share ..... differs   must (a real keypair)
encrypted_client_hello  differs   must (greased payload)

ja4  t13d1517h2_8daaf6152771_3cbfd9057e0d
     same string as the capture

Something differs that should not. Not a pass.
```

The JA4 still matches, because JA4 sorts the extensions before hashing them. verify compares the order. firefox157 draws nothing, so the order is `UNEXPECTED`; the report ends with "Not a pass." and verify exits 1.

## A wrong size

The bytes of a `must` field differ on every connection, whatever the profile does. Its size does not, so verify compares the sizes. Here is a copy of firefox157 whose greased ECH payload is 208 bytes where Firefox's is 240:

```python
from pybrws.profiles import firefox157
from pybrws.profiles.firefox157 import *
from pybrws.wire import u8, u16, vector

NAME = "wrong_ech"


def greased_ech(ctx):
    return (u8(0) + u16(1) + u16(1) + u8(ctx.random(1)[0])
            + vector(ctx.random(32), 2) + vector(ctx.random(208), 2))


EXTENSIONS = [(kind, greased_ech if kind == 65037 else payload)
              for kind, payload in firefox157.EXTENSIONS]
```

```console
pybrws verify --local --profile wrong_ech.py --capture firefox.hex
```

```text
$ pybrws verify --local --profile wrong_ech.py --capture firefox.hex

capture  firefox.hex
sni      pybrws.127.0.0.1.nip.io   (taken from the capture)
ours     1869 bytes   UNEXPECTED -- investigate
real     1901 bytes

version ....... match
cipher suites . match   15, same order
extensions .... match   17, same order
payloads ...... 15 of 17   byte for byte

random ........ differs   must (32 fresh random bytes)
session_id .... differs   must (32 fresh random bytes)
key_share ..... differs   must (a real keypair)
encrypted_client_hello  differs   UNEXPECTED -- 250 bytes, 282 in the capture

ja4  t13d1517h2_8daaf6152771_3cbfd9057e0d
     same string as the capture

Something differs that should not. Not a pass.
```

The JA4 still matches: it never reads the ECH extension. The sizes give it away, the hello's on the `ours` line and the field's on its own line: 250 bytes where the capture has 282, the 32 bytes missing from the payload. verify exits 1. A profile whose browser draws a size names it in `DRAWN`, as chrome155 does for its ECH payload, and verify then reports it as drawn.

## Checking the checker

verify and `pybrws ja4` compute JA4 with pybrws's own code, written from FoxIO's public specification. `--self-test` reproduces three values an outside service measured: two from Chrome 155 hellos in its published catalogue, and one from chrome155 as the service saw it over the network.

```console
pybrws ja4 --self-test
```

```text
  chrome 155, fresh hello                        cb7bf5808d99 ok
  chrome 155, resumed (pre_shared_key present)   e2d80978ab2e ok
  pybrws chrome155, as measured over the network 4980c97edce0 ok

all three reproduce values measured elsewhere
```

The first value is not the one my captures give. All six of my Chrome 155 hellos carry an extension of type `0x12e0`, two constant bytes whose purpose I do not know, and the hello in that catalogue has none. With it left out, chrome155 gives the catalogue's value. The output is trimmed after the `ja4` line:

```console
pybrws ja4 --profile chrome155 --drop 0x12e0
```

```text
chrome155  without 0x12e0
  ja4      t13d1517h2_8daaf6152771_cb7bf5808d99
```

Why two Chrome 155s differ there, my captures cannot say.

## From outside

verify proves the bytes pybrws builds. It cannot prove what arrives after a real network path and somebody else's parser. That is what an outside oracle is for. `pybrws probe` asks a service that reflects the fingerprints it sees, `https://thumbprint.me/api/v1/probe` by default. It asks over TCP with the profile, and over QUIC with `firefox157_quic`, then prints the two answers side by side:

```console
pybrws probe --profile my_firefox.py
```

!!! note "Screenshot pending: probe-terminal"
    The terminal after `pybrws probe --profile my_firefox.py`: the service's URL, the two arms and their profiles, the two status lines, and the first rows of the table, the JA4 rows, over TCP and over QUIC.

How I read it:

- The JA4 the service reports over TCP should be the string `pybrws ja4 --profile my_firefox.py` prints. If it is not, the hello that arrived is not the one verify checked.
- The two columns differ in more than the transport. The QUIC arm sends another profile, with its own cipher suites, extension order and headers. The tool says it under the table: a marked row "names a difference and not its cause".
- The QUIC arm needs the `http3` extra. `--only tcp` asks over TCP alone.

`pybrws verify` without `--local` is the other outside check. It fetches `https://tls.peet.ws/api/all` with firefox157 and compares that service's reading with the reading of Firefox 157 that ships in the package: the HTTP version and User-Agent, JA3, JA4, the service's own peetprint, the TLS versions, the HTTP/2 fingerprint, the HEADERS frame and its header order, and the TCP/IP signature. That last check is not about pybrws at all. The operating system's TCP stack writes the signature, and the reference was taken on Windows, so on another system that check fails whatever the profile does.

An outside service can be unreachable on any given day. The offline comparison is the one that needs nothing but the capture.
