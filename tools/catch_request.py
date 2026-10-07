#!/usr/bin/env python3
"""Capture a browser's HTTP request over TLS.

Serves a self-signed certificate so the request arrives decrypted, which
tools/catch_hello.py cannot do. That matters: over cleartext Firefox omits the
Sec-Fetch-* headers and drops br and zstd from Accept-Encoding, so a plaintext
capture is not a valid reference for an HTTPS client.

    python tools/catch_request.py fixtures/firefox-h1-tls.txt

Then open https://pybrws.127.0.0.1.nip.io:4443 and accept the certificate
warning. Use --alpn h2 to capture the HTTP/2 preamble instead.

With --set-cookie the first request is answered with a Set-Cookie and a page
that reloads itself, and the request captured is the second one, which
carries the Cookie header. That is the only way to learn which slot the
header occupies, since the order is part of the fingerprint.
"""

from __future__ import annotations

import argparse
import datetime
import socket
import ssl
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from pybrws.hexio import hexdump  # noqa: E402


def self_signed(hostname: str, directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


CRLF = chr(13) + chr(10)

RELOADING_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<meta http-equiv=refresh content=1>"
    b"<p>cookie set, reloading to capture the request that carries it"
)


FORM_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<form id=f method=post action=/submit "
    b"enctype=application/x-www-form-urlencoded>"
    b"<input name=field value=value></form>"
    b"<script>document.getElementById('f').submit()</script>"
    b"<p>submitting a form, to capture the POST a navigation sends"
)

FETCH_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<script>fetch('/submit',{method:'POST',"
    b"headers:{'Content-Type':'application/json'},"
    b"body:JSON.stringify({field:'value'})})</script>"
    b"<p>calling fetch, to capture the POST an XHR sends"
)


CLICK_PAGE = (
    b"<!doctype html><title>pybrws</title>"
    b"<style>body{font:16px system-ui;padding:3rem}"
    b"button{font:inherit;padding:.6rem 1.2rem}</style>"
    b"<form method=post action=/submit "
    b"enctype=application/x-www-form-urlencoded>"
    b"<input type=hidden name=field value=value>"
    b"<p>Click the button. Submitting by hand, rather than by script, is the "
    b"difference being measured: only a user-activated navigation carries "
    b"Sec-Fetch-User."
    b"<p><button type=submit>Submit</button></form>"
)

def page_response(page: bytes) -> bytes:
    lines = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: " + str(len(page)),
        "Connection: close",
    ]
    return (CRLF.join(lines) + CRLF + CRLF).encode("latin-1") + page


def not_found() -> bytes:
    lines = [
        "HTTP/1.1 404 Not Found",
        "Content-Length: 0",
        "Connection: close",
    ]
    return (CRLF.join(lines) + CRLF + CRLF).encode("latin-1")


def cookie_response() -> bytes:
    lines = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Set-Cookie: pybrws_probe=1; Path=/",
        "Set-Cookie: pybrws_second=2; Path=/",
        "Content-Length: " + str(len(RELOADING_PAGE)),
        "Connection: close",
    ]
    head = CRLF.join(lines) + CRLF + CRLF
    return head.encode("latin-1") + RELOADING_PAGE


def capture(host: str, port: int, hostname: str, alpn: str, wait: float,
            quiet_after: float, set_cookie: bool = False,
            want_document: bool = True,
            want_post: str | None = None) -> tuple[bytes, str | None]:
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = self_signed(hostname, Path(tmp))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.set_alpn_protocols([alpn])

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(8)
        print("listening on https://%s:%d, offering ALPN %r" % (hostname, port, alpn))
        print("the certificate is self-signed; accept the browser's warning")
        print("(speculative connections that fail before the warning are normal)")

        deadline = time.monotonic() + wait
        attempt = 0
        try:
            while time.monotonic() < deadline:
                listener.settimeout(max(deadline - time.monotonic(), 0.1))
                try:
                    raw, peer = listener.accept()
                except TimeoutError:
                    break

                attempt += 1
                try:
                    tls = context.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    print("  attempt %d from port %d: handshake failed (%s)"
                          % (attempt, peer[1], type(exc).__name__))
                    raw.close()
                    continue

                # Everything that touches the connection, including the reply,
                # has to happen before this block closes it.
                with tls:
                    negotiated = tls.selected_alpn_protocol()
                    tls.settimeout(quiet_after)
                    chunks = []
                    while True:
                        try:
                            chunk = tls.recv(65535)
                        except TimeoutError:
                            break
                        except (ConnectionResetError, ssl.SSLError, OSError):
                            # A client closing without close_notify lands here
                            # on Windows. What already arrived is still valid.
                            break
                        if not chunk:
                            break
                        chunks.append(chunk)

                    data = b"".join(chunks)
                    if not data:
                        print("  attempt %d from port %d: handshake only, no request"
                              % (attempt, peer[1]))
                        continue

                    lines = data.split(CRLF.encode())
                    has_cookie = any(
                        line.lower().startswith(b"cookie:") for line in lines
                    )
                    # A browser fetches the favicon as soon as a page loads,
                    # and that request arrives before the reload. Capturing it
                    # yields a subresource, not the navigation being asked for.
                    is_document = not any(
                        line.lower().startswith(b"sec-fetch-dest: image")
                        or line.lower().startswith(b"sec-fetch-dest: style")
                        or line.lower().startswith(b"sec-fetch-dest: script")
                        or line.lower().startswith(b"sec-fetch-dest: font")
                        for line in lines
                    )
                    is_post = lines[0].split(b" ")[0].upper() == b"POST"
                    if want_post and not is_post:
                        target = lines[0].split(b" ")[1].decode("latin-1", "replace")
                        # Only a document request gets the trigger page; a
                        # favicon asking for it is noise, and answering it
                        # with the page invites a second submission.
                        page = None if not is_document else {
                            "form": FORM_PAGE,
                            "form-click": CLICK_PAGE,
                            "fetch": FETCH_PAGE,
                        }[want_post]
                        print("  attempt %d from port %d: %s %s, answering "
                              "with %s"
                              % (attempt, peer[1],
                                 lines[0].split(b" ")[0].decode(), target,
                                 "the page that triggers the POST" if page
                                 else "404"))
                        try:
                            tls.sendall(page_response(page) if page else not_found())
                            tls.settimeout(3.0)
                            while tls.recv(4096):
                                pass
                        except OSError:
                            pass
                        continue
                    if want_document and not want_post and not is_document:
                        target = lines[0].split(b" ")[1].decode("latin-1", "replace")
                        print("  attempt %d from port %d: subresource %s, "
                              "answering and still waiting"
                              % (attempt, peer[1], target))
                        try:
                            tls.sendall(not_found())
                            tls.settimeout(3.0)
                            while tls.recv(4096):
                                pass
                        except OSError:
                            pass
                        continue
                    if set_cookie and not has_cookie:
                        print("  attempt %d from port %d: %d bytes, no Cookie "
                              "yet; answering and waiting for the reload"
                              % (attempt, peer[1], len(data)))
                        try:
                            tls.sendall(cookie_response())
                            # Let the peer read it and hang up. Closing straight
                            # after the write discards the response.
                            tls.settimeout(3.0)
                            while tls.recv(4096):
                                pass
                        except OSError:
                            pass
                        continue

                    print("  attempt %d from port %d: %d bytes"
                          % (attempt, peer[1], len(data)))
                    return data, negotiated
        finally:
            listener.close()

        raise SystemExit("no request captured after %d connection(s)" % attempt)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("out", help="path to write the captured request to")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4443)
    parser.add_argument("--hostname", default="pybrws.127.0.0.1.nip.io",
                        help="name in the certificate, must match the URL")
    parser.add_argument("--alpn", default="http/1.1", choices=["http/1.1", "h2"])
    parser.add_argument("--post", choices=["form", "form-click", "fetch"],
                        dest="want_post",
                        help="answer with a page that posts, then capture that "
                             "POST. `form` submits by script and `form-click` "
                             "waits for a real click, which is the only way to "
                             "tell whether Sec-Fetch-User depends on user "
                             "activation here; `fetch` sends an XHR")
    parser.add_argument("--any-request", action="store_true",
                        help="capture subresources too, instead of waiting "
                             "for a document request")
    parser.add_argument("--set-cookie", action="store_true",
                        help="answer the first request with a Set-Cookie and "
                             "capture the reload, which carries Cookie")
    parser.add_argument("--wait", type=float, default=120.0)
    parser.add_argument("--quiet-after", type=float, default=1.0)
    args = parser.parse_args()

    data, negotiated = capture(args.host, args.port, args.hostname, args.alpn,
                               args.wait, args.quiet_after, args.set_cookie,
                               not args.any_request, args.want_post)

    Path(args.out).write_bytes(data)
    print("negotiated ALPN: %r" % negotiated)
    print("captured %d bytes -> %s" % (len(data), args.out))
    print()
    if args.alpn == "http/1.1":
        print(data.decode("latin-1"))
    else:
        print(hexdump(data[:256]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
