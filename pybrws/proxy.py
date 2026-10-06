"""A local HTTPS proxy that re-issues requests with a browser fingerprint.

Any language with proxy support can use this: set HTTPS_PROXY and the
outbound connection carries the profile's TLS and HTTP fingerprint instead of
the caller's.

    python -m pybrws.proxy
    HTTPS_PROXY=http://127.0.0.1:8080 ruby -rnet/http -e '...'

It terminates TLS rather than tunnelling it. A plain CONNECT tunnel would let
the caller perform its own handshake, which is exactly the fingerprint this
project exists to replace, so the proxy must sit inside the encryption. That
costs a certificate authority the caller has to trust.
"""

from __future__ import annotations

import argparse
import datetime
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .client import TooManyRedirects, UnsupportedUrl, get
from .message import Response
from .profiles import firefox157
from .records import TlsAlert

DEFAULT_CA_DIR = Path.home() / ".pybrws"
HOP_BY_HOP = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade",
        # The body is handed over already decoded.
        "content-encoding", "content-length",
    }
)


def _pem(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


class CertificateAuthority:
    """Generates, persists and uses a local CA to mint per-host certificates."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.cert_path = directory / "ca.pem"
        self.key_path = directory / "ca-key.pem"
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()
        self.certificate = self.key = None
        if self.cert_path.exists() and self.key_path.exists():
            certificate = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
            try:
                certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
            except x509.ExtensionNotFound:
                # Certificates minted before this extension was added cannot
                # satisfy a verifier that requires a matching authority key id.
                print("regenerating CA: the stored one has no subject key identifier")
            else:
                self.certificate = certificate
                self.key = serialization.load_pem_private_key(
                    self.key_path.read_bytes(), password=None
                )
        if self.certificate is None:
            self.certificate, self.key = self._create()

    def _create(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pybrws local CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        _pem(self.cert_path, certificate.public_bytes(serialization.Encoding.PEM))
        _pem(
            self.key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return certificate, key

    def _leaf(self, hostname: str):
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()
                ),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        return certificate, key

    def context_for(self, hostname: str) -> ssl.SSLContext:
        with self._lock:
            context = self._contexts.get(hostname)
            if context is not None:
                return context
            certificate, key = self._leaf(hostname)
            with tempfile.TemporaryDirectory() as tmp:
                cert_file = Path(tmp) / "leaf.pem"
                key_file = Path(tmp) / "leaf-key.pem"
                cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
                key_file.write_bytes(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert_file, key_file)
            # The caller talks HTTP/1.1 to us; the fingerprinted hop is outbound.
            context.set_alpn_protocols(["http/1.1"])
            self._contexts[hostname] = context
            return context


def read_head(stream) -> bytes:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = stream.recv(65535)
        if not chunk:
            return bytes(buffer)
        buffer += chunk
        if len(buffer) > (1 << 18):
            raise ValueError("request head too large")
    return bytes(buffer)


def parse_head(head: bytes) -> tuple[str, str, list[tuple[str, str]]]:
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) < 2:
        raise ValueError("malformed request line " + repr(lines[0][:80]))
    headers = []
    for raw in lines[1:]:
        if not raw:
            break
        name, _, value = raw.partition(b":")
        headers.append((name.decode("latin-1").strip(), value.decode("latin-1").strip()))
    return parts[0].upper(), parts[1], headers


def serialise(response: Response) -> bytes:
    lines = ["HTTP/1.1 " + str(response.status)]
    for name, value in response.headers:
        if name.lower() not in HOP_BY_HOP:
            lines.append(name + ": " + value)
    lines.append("Content-Length: " + str(len(response.body)))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + response.body


def error_response(status: int, message: str) -> bytes:
    body = message.encode()
    head = (
        "HTTP/1.1 " + str(status) + "\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: " + str(len(body)) + "\r\n"
        "Connection: close\r\n\r\n"
    )
    return head.encode("latin-1") + body


class Proxy:
    def __init__(self, ca: CertificateAuthority, *, profile=firefox157,
                 timeout: float = 20.0, verbose: bool = True) -> None:
        self.ca = ca
        self.profile = profile
        self.timeout = timeout
        self.verbose = verbose

    def log(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)

    def fetch(self, url: str, headers=None) -> bytes:
        try:
            response = get(url, profile=self.profile, timeout=self.timeout,
                           headers=headers)
        except (UnsupportedUrl, TooManyRedirects) as exc:
            return error_response(400, str(exc))
        except TlsAlert as exc:
            return error_response(502, str(exc))
        except OSError as exc:
            return error_response(504, str(exc))
        self.log("  %s -> %d, %d bytes" % (url, response.status, len(response.body)))
        return serialise(response)

    def handle(self, client: socket.socket, peer) -> None:
        client.settimeout(self.timeout)
        try:
            head = read_head(client)
            if not head:
                return
            method, target, _ = parse_head(head)
            if method != "CONNECT":
                client.sendall(
                    error_response(405, "this proxy only handles CONNECT; "
                                        "point HTTPS_PROXY at it")
                )
                return

            host, _, port = target.partition(":")
            self.log("CONNECT %s" % target)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            context = self.ca.context_for(host)
            try:
                tls = context.wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.log("  inner handshake failed: %s; is the CA trusted?" % exc)
                return

            with tls:
                tls.settimeout(self.timeout)
                while True:
                    try:
                        inner = read_head(tls)
                    except (OSError, ValueError):
                        return
                    if not inner:
                        return
                    inner_method, path, _ = parse_head(inner)
                    if inner_method != "GET":
                        tls.sendall(error_response(501, "only GET is implemented"))
                        return
                    authority = host if port in ("", "443") else target
                    tls.sendall(self.fetch("https://" + authority + path))
                    return  # Connection: close was announced
        except Exception as exc:  # one bad client must not take the proxy down
            self.log("  %s: %s" % (type(exc).__name__, exc))
        finally:
            try:
                client.close()
            except OSError:
                pass

    def serve(self, host: str, port: int) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(64)
        print("proxy listening on http://%s:%d, profile %s"
              % (host, port, self.profile.NAME))
        print("CA certificate: %s" % self.ca.cert_path)
        print("trust it, or disable verification in the calling client")
        try:
            while True:
                client, peer = listener.accept()
                threading.Thread(
                    target=self.handle, args=(client, peer), daemon=True
                ).start()
        except KeyboardInterrupt:
            print("stopping")
        finally:
            listener.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pybrws.proxy", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ca-dir", type=Path, default=DEFAULT_CA_DIR)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--print-ca", action="store_true",
                        help="print the CA certificate path and exit")
    args = parser.parse_args(argv)

    ca = CertificateAuthority(args.ca_dir)
    if args.print_ca:
        print(ca.cert_path)
        return 0
    Proxy(ca, timeout=args.timeout, verbose=not args.quiet).serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
