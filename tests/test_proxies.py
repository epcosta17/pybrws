"""Tests for pybrws.proxies, driven by fake proxies on loopback."""

import socket
import struct
import threading
import unittest

from pybrws.proxies import Proxy, ProxyError, open_socket, parse_proxy


class FakeProxy:
    """Accepts one connection, records what arrives, replays a script."""

    def __init__(self, handler):
        self.handler = handler
        self.received = bytearray()
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.error = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            self.listener.settimeout(10)
            conn, _ = self.listener.accept()
            with conn:
                conn.settimeout(10)
                self.handler(self, conn)
        except Exception as exc:  # surfaced by the test through self.error
            self.error = exc
        finally:
            self.listener.close()

    def read_until(self, conn, delimiter):
        while delimiter not in self.received:
            chunk = conn.recv(4096)
            if not chunk:
                raise AssertionError("client closed early")
            self.received += chunk
        return bytes(self.received)

    def read_exactly(self, conn, n):
        start = len(self.received)
        while len(self.received) - start < n:
            chunk = conn.recv(n - (len(self.received) - start))
            if not chunk:
                raise AssertionError("client closed early")
            self.received += chunk
        return bytes(self.received[start:start + n])

    def url(self, scheme, credentials=""):
        return scheme + "://" + credentials + "127.0.0.1:" + str(self.port)


class TestParseProxy(unittest.TestCase):
    def test_bare_host_and_port_defaults_to_http(self):
        self.assertEqual(parse_proxy("1.2.3.4:3128"),
                         Proxy("http", "1.2.3.4", 3128, None, None))

    def test_default_ports(self):
        self.assertEqual(parse_proxy("http://p.test").port, 8080)
        self.assertEqual(parse_proxy("socks5://p.test").port, 1080)

    def test_credentials_are_url_decoded(self):
        proxy = parse_proxy("http://user%40corp:p%3Ass@p.test:3128")
        self.assertEqual((proxy.username, proxy.password), ("user@corp", "p:ss"))

    def test_socks_detection(self):
        self.assertTrue(parse_proxy("socks5://p.test").is_socks)
        self.assertTrue(parse_proxy("socks5h://p.test").is_socks)
        self.assertFalse(parse_proxy("http://p.test").is_socks)

    def test_rejects_unknown_scheme(self):
        with self.assertRaises(ProxyError):
            parse_proxy("ftp://p.test")

    def test_str_hides_the_password(self):
        rendered = str(parse_proxy("http://user:secret@p.test:3128"))
        self.assertIn("user@", rendered)
        self.assertNotIn("secret", rendered)


class TestHttpConnect(unittest.TestCase):
    def test_sends_a_well_formed_connect(self):
        def handler(proxy, conn):
            proxy.read_until(conn, b"\r\n\r\n")
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        proxy = FakeProxy(handler)
        open_socket("example.test", 443, proxy=proxy.url("http")).close()
        proxy.thread.join(5)

        lines = bytes(proxy.received).decode().split("\r\n")
        self.assertEqual(lines[0], "CONNECT example.test:443 HTTP/1.1")
        self.assertIn("Host: example.test:443", lines)
        self.assertNotIn("Proxy-Authorization", bytes(proxy.received).decode())

    def test_sends_basic_credentials(self):
        def handler(proxy, conn):
            proxy.read_until(conn, b"\r\n\r\n")
            conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")

        proxy = FakeProxy(handler)
        open_socket("a.test", 443, proxy=proxy.url("http", "bob:s3cret@")).close()
        proxy.thread.join(5)
        # base64("bob:s3cret")
        self.assertIn(b"Proxy-Authorization: Basic Ym9iOnMzY3JldA==",
                      bytes(proxy.received))

    def test_refusal_raises(self):
        def handler(proxy, conn):
            proxy.read_until(conn, b"\r\n\r\n")
            conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

        proxy = FakeProxy(handler)
        with self.assertRaises(ProxyError) as caught:
            open_socket("a.test", 443, proxy=proxy.url("http"))
        self.assertIn("407", str(caught.exception))

    def test_garbage_response_raises(self):
        def handler(proxy, conn):
            proxy.read_until(conn, b"\r\n\r\n")
            conn.sendall(b"NOT A STATUS LINE\r\n\r\n")

        proxy = FakeProxy(handler)
        with self.assertRaises(ProxyError):
            open_socket("a.test", 443, proxy=proxy.url("http"))


class TestSocks5(unittest.TestCase):
    def test_no_auth_connect(self):
        def handler(proxy, conn):
            greeting = proxy.read_exactly(conn, 2)
            proxy.read_exactly(conn, greeting[1])
            conn.sendall(bytes([5, 0]))
            header = proxy.read_exactly(conn, 5)
            proxy.read_exactly(conn, header[4] + 2)
            conn.sendall(bytes([5, 0, 0, 1]) + bytes(4) + struct.pack("!H", 0))

        proxy = FakeProxy(handler)
        open_socket("example.test", 443, proxy=proxy.url("socks5")).close()
        proxy.thread.join(5)

        raw = bytes(proxy.received)
        self.assertEqual(raw[0], 5)
        request = raw[raw.index(b"\x05\x01\x00\x03"):]
        self.assertEqual(request[:4], b"\x05\x01\x00\x03")
        length = request[4]
        self.assertEqual(request[5:5 + length], b"example.test",
                         "the target must be sent as a name, not resolved here")
        self.assertEqual(struct.unpack("!H", request[5 + length:7 + length])[0], 443)

    def test_username_password_auth(self):
        seen = {}

        def handler(proxy, conn):
            greeting = proxy.read_exactly(conn, 2)
            methods = proxy.read_exactly(conn, greeting[1])
            seen["methods"] = list(methods)
            conn.sendall(bytes([5, 2]))
            head = proxy.read_exactly(conn, 2)
            user = proxy.read_exactly(conn, head[1])
            plen = proxy.read_exactly(conn, 1)[0]
            secret = proxy.read_exactly(conn, plen)
            seen["credentials"] = (user.decode(), secret.decode())
            conn.sendall(bytes([1, 0]))
            header = proxy.read_exactly(conn, 5)
            proxy.read_exactly(conn, header[4] + 2)
            conn.sendall(bytes([5, 0, 0, 1]) + bytes(4) + struct.pack("!H", 0))

        proxy = FakeProxy(handler)
        open_socket("a.test", 443, proxy=proxy.url("socks5", "bob:s3cret@")).close()
        proxy.thread.join(5)
        self.assertEqual(seen["methods"], [0, 2])
        self.assertEqual(seen["credentials"], ("bob", "s3cret"))

    def test_rejected_credentials_raise(self):
        def handler(proxy, conn):
            greeting = proxy.read_exactly(conn, 2)
            proxy.read_exactly(conn, greeting[1])
            conn.sendall(bytes([5, 2]))
            head = proxy.read_exactly(conn, 2)
            proxy.read_exactly(conn, head[1])
            plen = proxy.read_exactly(conn, 1)[0]
            proxy.read_exactly(conn, plen)
            conn.sendall(bytes([1, 1]))

        proxy = FakeProxy(handler)
        with self.assertRaises(ProxyError) as caught:
            open_socket("a.test", 443, proxy=proxy.url("socks5", "bob:wrong@"))
        self.assertIn("credentials", str(caught.exception))

    def test_no_acceptable_method_raises(self):
        def handler(proxy, conn):
            greeting = proxy.read_exactly(conn, 2)
            proxy.read_exactly(conn, greeting[1])
            conn.sendall(bytes([5, 0xFF]))

        proxy = FakeProxy(handler)
        with self.assertRaises(ProxyError):
            open_socket("a.test", 443, proxy=proxy.url("socks5"))

    def test_connect_failure_is_named(self):
        def handler(proxy, conn):
            greeting = proxy.read_exactly(conn, 2)
            proxy.read_exactly(conn, greeting[1])
            conn.sendall(bytes([5, 0]))
            header = proxy.read_exactly(conn, 5)
            proxy.read_exactly(conn, header[4] + 2)
            conn.sendall(bytes([5, 0x04, 0, 1]) + bytes(4) + struct.pack("!H", 0))

        proxy = FakeProxy(handler)
        with self.assertRaises(ProxyError) as caught:
            open_socket("a.test", 443, proxy=proxy.url("socks5"))
        self.assertIn("host unreachable", str(caught.exception))

    def test_domain_bound_address_is_consumed(self):
        def handler(proxy, conn):
            greeting = proxy.read_exactly(conn, 2)
            proxy.read_exactly(conn, greeting[1])
            conn.sendall(bytes([5, 0]))
            header = proxy.read_exactly(conn, 5)
            proxy.read_exactly(conn, header[4] + 2)
            name = b"exit.node"
            conn.sendall(bytes([5, 0, 0, 3, len(name)]) + name + struct.pack("!H", 0))
            conn.sendall(b"PAYLOAD")

        proxy = FakeProxy(handler)
        sock = open_socket("a.test", 443, proxy=proxy.url("socks5"))
        with sock:
            # Anything after the reply must still be readable, which only
            # holds if the bound address was consumed exactly.
            self.assertEqual(sock.recv(7), b"PAYLOAD")


if __name__ == "__main__":
    unittest.main()
