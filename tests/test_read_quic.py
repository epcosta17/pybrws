"""Tests for tools/read_quic.py, the capture reader.

Packet parsing is fiddly in a way that fails quietly: an off-by-one in an IP
header length yields a payload that simply is not QUIC, which looks exactly
like a capture that held nothing. So the captures here are built byte by byte
around datagrams aioquic produced, and the reader has to find the same
ClientHello that went in.
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import read_quic  # noqa: E402

from pybrws.parser import parse_client_hello  # noqa: E402

try:
    from tests.test_quic import client_first_flight
except ImportError:  # pragma: no cover
    from test_quic import client_first_flight

ETHERNET = 1
LOOPBACK = 0
RAW_IP = 101


def ethernet(payload: bytes) -> bytes:
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + payload


def ipv4(payload: bytes) -> bytes:
    total = 20 + len(payload)
    return (
        bytes([0x45, 0x00])
        + struct.pack("!H", total)
        + b"\x00\x00\x00\x00"
        + bytes([64, 17])
        + b"\x00\x00"
        + bytes([192, 168, 1, 10])
        + bytes([93, 184, 216, 34])
        + payload
    )


def ipv6(payload: bytes) -> bytes:
    return (
        bytes([0x60, 0, 0, 0])
        + struct.pack("!H", len(payload))
        + bytes([17, 64])
        + bytes(16)
        + bytes(16)
        + payload
    )


def udp(payload: bytes, *, destination: int = 443) -> bytes:
    return (struct.pack("!HHHH", 51234, destination, 8 + len(payload), 0)
            + payload)


def pcap(frames, *, link: int = ETHERNET, endian: str = "<") -> bytes:
    out = bytearray(struct.pack(endian + "IHHiIII",
                                0xA1B2C3D4, 2, 4, 0, 0, 65535, link))
    for index, frame in enumerate(frames):
        out += struct.pack(endian + "IIII", 1700000000, index,
                           len(frame), len(frame))
        out += frame
    return bytes(out)


def pcapng(frames, *, link: int = ETHERNET) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        padding = (-len(body)) % 4
        total = 12 + len(body) + padding
        return (struct.pack("<II", kind, total) + body + bytes(padding)
                + struct.pack("<I", total))

    out = bytearray()
    out += block(0x0A0D0D0A,
                 struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", link, 0, 65535))
    for frame in frames:
        out += block(0x00000006,
                     struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame))
                     + frame)
    return bytes(out)


class CaptureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.datagrams, cls.expected = client_first_flight(padded=True)
        cls.frames = [ethernet(ipv4(udp(d))) for d in cls.datagrams]

    def write(self, data: bytes, suffix: str) -> Path:
        import tempfile

        handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        handle.write(data)
        handle.close()
        path = Path(handle.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def recover(self, path: Path, port: int = 443) -> bytes:
        payloads = read_quic.datagrams(path, port)
        groups = read_quic.by_connection(payloads)
        self.assertEqual(len(groups), 1, "one connection went in")
        group = next(iter(groups.values()))
        return read_quic.client_hello_from_datagrams(group)


class TestFileFormats(CaptureCase):
    def test_pcapng(self):
        path = self.write(pcapng(self.frames), ".pcapng")
        self.assertEqual(self.recover(path), self.expected)

    def test_pcap_little_endian(self):
        path = self.write(pcap(self.frames), ".pcap")
        self.assertEqual(self.recover(path), self.expected)

    def test_pcap_big_endian(self):
        # The magic is written in the writer's own byte order, so both exist
        # in the wild and the reader has to work out which it has.
        path = self.write(pcap(self.frames, endian=">"), ".pcap")
        self.assertEqual(self.recover(path), self.expected)

    def test_a_file_that_is_not_a_capture_is_refused(self):
        path = self.write(b"this is not a capture at all, not even close",
                          ".pcap")
        with self.assertRaises(read_quic.CaptureError):
            read_quic.datagrams(path, 443)

    def test_a_file_too_short_to_be_a_capture_is_refused(self):
        path = self.write(b"short", ".pcap")
        with self.assertRaises(read_quic.CaptureError):
            read_quic.datagrams(path, 443)


class TestLinkLayers(CaptureCase):
    def test_ethernet_over_ipv6(self):
        frames = [b"\xaa" * 6 + b"\xbb" * 6 + b"\x86\xdd" + ipv6(udp(d))
                  for d in self.datagrams]
        path = self.write(pcapng(frames), ".pcapng")
        self.assertEqual(self.recover(path), self.expected)

    def test_raw_ip(self):
        frames = [ipv4(udp(d)) for d in self.datagrams]
        path = self.write(pcapng(frames, link=RAW_IP), ".pcapng")
        self.assertEqual(self.recover(path), self.expected)

    def test_loopback(self):
        # What a capture of a local server looks like.
        frames = [struct.pack("<I", 2) + ipv4(udp(d)) for d in self.datagrams]
        path = self.write(pcapng(frames, link=LOOPBACK), ".pcapng")
        self.assertEqual(self.recover(path), self.expected)


class TestFiltering(CaptureCase):
    def test_other_ports_are_ignored(self):
        noise = [ethernet(ipv4(udp(b"dns-ish payload", destination=53)))]
        path = self.write(pcapng(noise + self.frames), ".pcapng")
        self.assertEqual(self.recover(path), self.expected)

    def test_port_zero_takes_everything(self):
        path = self.write(pcapng(self.frames), ".pcapng")
        self.assertEqual(self.recover(path, port=0), self.expected)

    def test_tcp_frames_are_ignored(self):
        tcp = bytes([0x45, 0x00]) + struct.pack("!H", 40) + b"\x00" * 5 \
            + bytes([6]) + b"\x00" * 11
        path = self.write(pcapng([ethernet(tcp)] + self.frames), ".pcapng")
        self.assertEqual(self.recover(path), self.expected)

    def test_two_connections_are_kept_apart(self):
        # The failure this prevents: CRYPTO offsets from two handshakes
        # reassembled into one hello, which would parse and be wrong.
        other, other_hello = client_first_flight(server_name="other.test",
                                                 padded=True)
        frames = []
        for first, second in zip(self.datagrams, other):
            frames.append(ethernet(ipv4(udp(first))))
            frames.append(ethernet(ipv4(udp(second))))
        path = self.write(pcapng(frames), ".pcapng")
        groups = read_quic.by_connection(read_quic.datagrams(path, 443))
        self.assertEqual(len(groups), 2)
        recovered = {read_quic.client_hello_from_datagrams(g)
                     for g in groups.values()}
        self.assertEqual(recovered, {self.expected, other_hello})

    def test_the_server_name_is_read_back(self):
        path = self.write(pcapng(self.frames), ".pcapng")
        hello = parse_client_hello(self.recover(path))
        self.assertEqual(read_quic.server_name_of(hello), "pybrws.test")

class TestTheChooser(CaptureCase):
    """What happens when --host names a connection that is not there.

    This started as a silent fallback to the largest hello, which on a real
    capture picked a different server and wrote the fixture anyway: a file
    labelled for one host holding a measurement of another. Writing nothing
    is strictly better.
    """

    def capture_of_two(self) -> Path:
        other, _ = client_first_flight(server_name="other.test", padded=True)
        frames = []
        for first, second in zip(self.datagrams, other):
            frames.append(ethernet(ipv4(udp(first))))
            frames.append(ethernet(ipv4(udp(second))))
        return self.write(pcapng(frames), ".pcapng")

    def run_tool(self, *arguments) -> tuple[int, str]:
        import subprocess

        tool = Path(__file__).resolve().parent.parent / "tools" / "read_quic.py"
        finished = subprocess.run([sys.executable, str(tool), *arguments],
                                  capture_output=True, text=True)
        return finished.returncode, finished.stdout + finished.stderr

    def test_an_absent_host_writes_nothing_and_fails(self):
        capture = self.capture_of_two()
        target = capture.with_suffix(".hex")
        self.addCleanup(target.unlink, missing_ok=True)
        code, output = self.run_tool(str(capture), "--host", "absent.test",
                                     "--out", str(target))
        self.assertEqual(code, 1)
        self.assertFalse(target.exists(), "no fixture for a host not captured")
        self.assertIn("Nothing written", output)

    def test_several_connections_without_a_host_writes_nothing(self):
        capture = self.capture_of_two()
        target = capture.with_suffix(".hex")
        self.addCleanup(target.unlink, missing_ok=True)
        code, _ = self.run_tool(str(capture), "--out", str(target))
        self.assertEqual(code, 1)
        self.assertFalse(target.exists())

    def test_the_named_host_is_written(self):
        capture = self.capture_of_two()
        target = capture.with_suffix(".hex")
        self.addCleanup(target.unlink, missing_ok=True)
        code, _ = self.run_tool(str(capture), "--host", "pybrws.test",
                                "--out", str(target))
        self.assertEqual(code, 0)
        from pybrws.hexio import load_hex
        self.assertEqual(load_hex(target), self.expected)

    def test_one_connection_needs_no_host(self):
        capture = self.write(pcapng(self.frames), ".pcapng")
        target = capture.with_suffix(".hex")
        self.addCleanup(target.unlink, missing_ok=True)
        code, _ = self.run_tool(str(capture), "--out", str(target))
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
