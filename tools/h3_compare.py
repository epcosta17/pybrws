"""Measure pybrws and curl_cffi against our own QUIC server, side by side.

No third party is involved, for a measured reason: tls.peet.ws advertises h3
in its Alt-Svc header and does not serve it, which both clients agree on by
failing the handshake identically. So the oracle is our own server, the same
way catch_h2.py is the oracle for HTTP/2 -- which is better anyway, since it
reports the request headers as well as the hello.

    python tools/h3_compare.py

curl_cffi is a development dependency, so this needs `pip install curl_cffi`.
It impersonates firefox147 because that is the newest Firefox target it has,
against our profile's 157: some differences are therefore version differences
rather than modelling differences, and the write-up says which.
"""

import asyncio
import json
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

import catch_quic

from pybrws.model import extension_name
from pybrws.parser import parse_client_hello
from pybrws.quic import parameter_name, parse_transport_parameters

HOSTNAME = "pybrws.127.0.0.1.nip.io"
URL = "https://%s:%%d/" % HOSTNAME


def measure(port: int, drive, label: str) -> dict:
    """Run the server, drive one client at it, return what it saw."""
    catch_quic.captured.clear()
    catch_quic.requests.clear()

    result = {}

    def serve():
        result["hello"] = asyncio.run(
            catch_quic.run("127.0.0.1", port, HOSTNAME, wait=25.0))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    time.sleep(1.5)
    try:
        drive(port)
    except Exception as exc:
        print("  %s client: %s: %s" % (label, type(exc).__name__, str(exc)[:110]))
    thread.join(timeout=30)

    hello = result.get("hello")
    return {
        "label": label,
        "hello": parse_client_hello(hello) if hello else None,
        "raw": hello,
        "request": catch_quic.requests[0] if catch_quic.requests else None,
    }


def drive_pybrws(port: int) -> None:
    from pybrws import h3

    response = h3.get(URL % port, verify=False, timeout=20)
    print("  pybrws got %s, %d bytes" % (response.status, len(response.body)))


def drive_curl_cffi(port: int) -> None:
    from curl_cffi import requests as cffi
    from curl_cffi.const import CurlHttpVersion

    response = cffi.get(URL % port, impersonate="firefox147", verify=False,
                        http_version=CurlHttpVersion.V3ONLY, timeout=20)
    print("  curl_cffi got %s, %d bytes" % (response.status_code,
                                            len(response.content)))


def report(a: dict, b: dict) -> None:
    for side in (a, b):
        hello = side["hello"]
        if hello is None:
            print("\n%s: no ClientHello captured" % side["label"])
            continue
        print("\n%s" % side["label"])
        print("  hello %d bytes, %d extensions, %d cipher suites, session id %d"
              % (len(side["raw"]), len(hello.extensions),
                 len(hello.cipher_suites), len(hello.session_id)))
        print("  extension order: "
              + " ".join(str(e.type) for e in hello.extensions))
        print("  cipher suites:   "
              + " ".join("0x%04x" % c for c in hello.cipher_suites))
        try:
            params = parse_transport_parameters(hello.extension(57).data)
            print("  transport parameters (%d): " % len(params)
                  + " ".join(parameter_name(i) for i, _ in params))
        except Exception:
            print("  no quic_transport_parameters")
        request = side["request"]
        if request:
            pseudo = [n for n, _ in request if n.startswith(":")]
            real = [n for n, _ in request if not n.startswith(":")]
            print("  pseudo order:    " + " ".join(pseudo))
            print("  headers (%d):     " % len(real) + " ".join(real))
        else:
            print("  no request captured")

    if a["hello"] is None or b["hello"] is None:
        return

    print("\n--- side by side ---")
    sa = frozenset(e.type for e in a["hello"].extensions)
    sb = frozenset(e.type for e in b["hello"].extensions)
    print("  extension sets identical: %s" % (sa == sb))
    if sa != sb:
        only_a = [f"{extension_name(x)} ({x})" for x in sorted(sa - sb)]
        only_b = [f"{extension_name(x)} ({x})" for x in sorted(sb - sa)]
        print("    only %s: %s" % (a["label"], ", ".join(only_a) or "nothing"))
        print("    only %s: %s" % (b["label"], ", ".join(only_b) or "nothing"))
    print("  cipher suites identical: %s"
          % (list(a["hello"].cipher_suites) == list(b["hello"].cipher_suites)))
    print("  session id lengths: %d vs %d"
          % (len(a["hello"].session_id), len(b["hello"].session_id)))
    if a["request"] and b["request"]:
        pa = [n for n, _ in a["request"] if n.startswith(":")]
        pb = [n for n, _ in b["request"] if n.startswith(":")]
        print("  pseudo order identical: %s" % (pa == pb))
        ha = [n for n, _ in a["request"] if not n.startswith(":")]
        hb = [n for n, _ in b["request"] if not n.startswith(":")]
        print("  header order identical: %s" % (ha == hb))
        if ha != hb:
            print("    %-10s %s" % (a["label"], " ".join(ha)))
            print("    %-10s %s" % (b["label"], " ".join(hb)))


def main(rounds: int = 1, base: int = 4511) -> None:
    for round_number in range(rounds):
        port = base + round_number * 2
        ours = measure(port, drive_pybrws, "pybrws")
        theirs = measure(port + 1, drive_curl_cffi, "curl_cffi firefox147")
        if rounds > 1:
            print("\n===== round %d =====" % (round_number + 1))
        report(ours, theirs)


if __name__ == "__main__":
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    main(rounds)
