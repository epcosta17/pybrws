#!/usr/bin/env python3
"""Recover a ClientHello from a packet capture of QUIC traffic.

Initial packets are protected with keys derived from a salt printed in RFC
9001 and a connection ID the header carries in the clear, so a capture is
enough -- no keys, no local server, and no certificate for a browser to
object to. Point a browser at a real site that speaks HTTP/3, capture UDP
443, and the ClientHello is in there.

    # in Wireshark, or with dumpcap:
    #   capture filter: udp port 443
    # then:
    python tools/read_quic.py capture.pcapng
    python tools/read_quic.py capture.pcapng --host www.google.com --out fx.hex

A capture of port 443 holds more than one connection, and the datagrams of
several are interleaved. They are grouped by destination connection ID, which
is what keys the decryption, and each group is tried on its own. --host picks
the group whose ClientHello carries that server name.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pybrws.hexio import hexdump, save_hex  # noqa: E402
from pybrws.model import extension_name  # noqa: E402
from pybrws.parser import parse_client_hello  # noqa: E402
from pybrws.quic import (QuicError, client_hello_from_datagrams,  # noqa: E402
                         is_grease_parameter, parameter_name,
                         parse_long_header, parse_transport_parameters)

EXT_SERVER_NAME = 0
EXT_QUIC_TRANSPORT_PARAMETERS = 57

PCAPNG_SECTION_HEADER = 0x0A0D0D0A
PCAPNG_INTERFACE_DESCRIPTION = 0x00000001
PCAPNG_SIMPLE_PACKET = 0x00000003
PCAPNG_ENHANCED_PACKET = 0x00000006
PCAP_MAGIC_LE = 0xD4C3B2A1
PCAP_MAGIC_BE = 0xA1B2C3D4
PCAP_MAGIC_NANO_LE = 0x4D3CB2A1
PCAP_MAGIC_NANO_BE = 0xA1B23C4D

# Link types this reads. Loopback captures are common when the server is
# local, Ethernet when it is not.
LINK_NULL = 0
LINK_ETHERNET = 1
LINK_RAW = 101
LINK_LINUX_SLL = 113
LINK_IPV4 = 228
LINK_IPV6 = 229

PROTOCOL_UDP = 17


class CaptureError(Exception):
    pass


def _frames(path: Path):
    """Yield (link_type, frame_bytes) from a pcap or pcapng file."""
    data = path.read_bytes()
    if len(data) < 24:
        raise CaptureError("file is too short to be a capture")
    if int.from_bytes(data[:4], "little") == PCAPNG_SECTION_HEADER:
        yield from _pcapng_frames(data)
    else:
        yield from _pcap_frames(data)


def _pcapng_frames(data: bytes):
    offset = 0
    endian = "<"
    link_types: list[int] = []
    while offset + 12 <= len(data):
        block_type = int.from_bytes(data[offset:offset + 4], "little")
        if block_type == PCAPNG_SECTION_HEADER:
            # The byte-order magic decides how everything after it is read,
            # including this block's own length.
            magic = data[offset + 8:offset + 12]
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            link_types = []
        length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if length < 12 or offset + length > len(data):
            raise CaptureError("pcapng block at %d has length %d" % (offset, length))
        body = data[offset + 8:offset + length - 4]

        if block_type == PCAPNG_INTERFACE_DESCRIPTION:
            link_types.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif block_type == PCAPNG_ENHANCED_PACKET:
            interface, _high, _low, captured, _original = struct.unpack_from(
                endian + "IIIII", body, 0)
            frame = body[20:20 + captured]
            link = link_types[interface] if interface < len(link_types) else LINK_ETHERNET
            yield link, frame
        elif block_type == PCAPNG_SIMPLE_PACKET:
            yield (link_types[0] if link_types else LINK_ETHERNET), body[4:]
        offset += length


def _pcap_frames(data: bytes):
    magic = int.from_bytes(data[:4], "big")
    if magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NANO_BE):
        endian = ">"
    elif int.from_bytes(data[:4], "little") in (PCAP_MAGIC_BE, PCAP_MAGIC_NANO_BE):
        endian = "<"
    else:
        raise CaptureError("not a pcap or pcapng file (magic %08x)" % magic)

    link = struct.unpack_from(endian + "I", data, 20)[0]
    offset = 24
    while offset + 16 <= len(data):
        _sec, _frac, captured, _original = struct.unpack_from(
            endian + "IIII", data, offset)
        offset += 16
        yield link, data[offset:offset + captured]
        offset += captured


def _udp_payload(link: int, frame: bytes) -> tuple[int, bytes] | None:
    """Return (destination port, payload) if the frame carries UDP."""
    if link == LINK_ETHERNET:
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], "big")
        packet = frame[14:]
        if ether_type == 0x0800:
            return _ipv4(packet)
        if ether_type == 0x86DD:
            return _ipv6(packet)
        return None
    if link == LINK_NULL:
        if len(frame) < 4:
            return None
        family = int.from_bytes(frame[:4], "little")
        return _ipv4(frame[4:]) if family == 2 else _ipv6(frame[4:])
    if link == LINK_LINUX_SLL:
        if len(frame) < 16:
            return None
        protocol = int.from_bytes(frame[14:16], "big")
        if protocol == 0x0800:
            return _ipv4(frame[16:])
        if protocol == 0x86DD:
            return _ipv6(frame[16:])
        return None
    if link in (LINK_RAW, LINK_IPV4):
        return _ipv4(frame)
    if link == LINK_IPV6:
        return _ipv6(frame)
    return None


def _ipv4(packet: bytes) -> tuple[int, bytes] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    if packet[9] != PROTOCOL_UDP:
        return None
    header_length = (packet[0] & 0x0F) * 4
    return _udp(packet[header_length:])


def _ipv6(packet: bytes) -> tuple[int, bytes] | None:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    if packet[6] != PROTOCOL_UDP:
        # Extension headers are not chased; a browser's QUIC has none.
        return None
    return _udp(packet[40:])


def _udp(segment: bytes) -> tuple[int, bytes] | None:
    if len(segment) < 8:
        return None
    destination = int.from_bytes(segment[2:4], "big")
    length = int.from_bytes(segment[4:6], "big")
    payload = segment[8:length] if 8 <= length <= len(segment) else segment[8:]
    return destination, payload


def datagrams(path: Path, port: int) -> list[bytes]:
    found = []
    for link, frame in _frames(path):
        result = _udp_payload(link, frame)
        if result is None:
            continue
        destination, payload = result
        if payload and (port == 0 or destination == port):
            found.append(payload)
    return found


def by_connection(payloads) -> dict[bytes, list[bytes]]:
    """Group datagrams by the connection ID their decryption is keyed by.

    A capture of port 443 holds several connections at once and their
    datagrams interleave, so feeding the lot in as one stream would mix
    CRYPTO offsets from different handshakes together.
    """
    groups: dict[bytes, list[bytes]] = {}
    for payload in payloads:
        try:
            header, _ = parse_long_header(payload)
        except QuicError:
            continue
        groups.setdefault(header["destination_id"], []).append(payload)
    return groups


def server_name_of(hello) -> str | None:
    try:
        data = hello.extension(EXT_SERVER_NAME).data
    except Exception:
        return None
    if len(data) < 5:
        return None
    raw = data[5:5 + int.from_bytes(data[3:5], "big")]
    # The wire carries punycode ASCII. The idna codec is the nicer thing to
    # show, but it has no lenient error handler and raises on anything it
    # dislikes, so it is a bonus rather than the decode.
    name = raw.decode("ascii", "replace")
    try:
        return raw.decode("idna")
    except (UnicodeError, ValueError):
        return name


def report(raw: bytes) -> None:
    hello = parse_client_hello(raw)
    name = server_name_of(hello)
    print("  %d bytes, %d extensions, %d cipher suites%s"
          % (len(raw), len(hello.extensions), len(hello.cipher_suites),
             ", sni " + name if name else ""))
    print()
    print("  extensions, in wire order:")
    for extension in hello.extensions:
        print("    %-6d %-34s %5d" % (extension.type,
                                      extension_name(extension.type),
                                      len(extension.data)))
    try:
        parameters = parse_transport_parameters(
            hello.extension(EXT_QUIC_TRANSPORT_PARAMETERS).data)
    except Exception:
        print()
        print("  no quic_transport_parameters extension")
        return
    print()
    print("  quic_transport_parameters, in wire order:")
    for identifier, value in parameters:
        print("    0x%-6x %-34s %s" % (identifier, parameter_name(identifier),
                                       value.hex() or "(empty)"))


def compare(hellos) -> None:
    """Report what is the same and what differs across several hellos.

    This is the question a single capture cannot answer. If the extension
    order is stable there is an order to imitate; if it is shuffled per
    connection then the order is not the fingerprint and the set is. Chrome
    shuffles and Firefox does not on TCP, but a browser's QUIC stack need not
    be the same code -- Firefox's is neqo, not NSS.
    """
    parsed = [parse_client_hello(raw) for raw in hellos]
    orders = {}
    for hello, raw in zip(parsed, hellos):
        orders.setdefault(tuple(hello.extension_types()), []).append(
            server_name_of(hello))

    print("extension order across %d connections: %d distinct"
          % (len(parsed), len(orders)))
    for index, (order, names) in enumerate(orders.items(), 1):
        print("  order %d, seen on %d: %s" % (index, len(names),
                                              ", ".join(n or "?" for n in names)))
        print("    " + " ".join(str(t) for t in order))
    if len(orders) == 1:
        print("  -> stable. There is an order to imitate.")
    else:
        print("  -> not stable. The order is drawn per connection, so the set")
        print("     is the fingerprint and the order is noise to reproduce")
        print("     only in distribution.")

    print()
    print("transport parameters across the same connections:")
    sets = {}
    for hello in parsed:
        try:
            params = parse_transport_parameters(
                hello.extension(EXT_QUIC_TRANSPORT_PARAMETERS).data)
        except Exception:
            continue
        sets.setdefault(tuple(i for i, _ in params), []).append(
            server_name_of(hello))
    print("  %d distinct id sequences" % len(sets))
    for order, names in sets.items():
        print("    %s" % " ".join(parameter_name(i) for i in order))
        print("      on %d: %s" % (len(names),
                                   ", ".join(n or "?" for n in names)))

    greased = [
        [i for i, _ in parse_transport_parameters(
            hello.extension(EXT_QUIC_TRANSPORT_PARAMETERS).data)
         if is_grease_parameter(i)]
        for hello in parsed
        if any(e.type == EXT_QUIC_TRANSPORT_PARAMETERS for e in hello.extensions)
    ]
    flat = [i for row in greased for i in row]
    if flat:
        print()
        print("  grease-pattern ids seen: %s"
              % ", ".join(hex(i) for i in sorted(set(flat))))
        if len(set(flat)) == 1:
            print("  -> one value every time, so it is a constant to copy,")
            print("     not a value drawn per connection.")
        else:
            print("  -> it varies, so it is drawn per connection and has to")
            print("     be generated rather than copied.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="a .pcap or .pcapng file")
    parser.add_argument("--port", type=int, default=443,
                        help="UDP destination port, or 0 for every port")
    parser.add_argument("--host", help="keep the connection whose SNI is this")
    parser.add_argument("--out", type=Path, help="where to write the hello")
    parser.add_argument("--all", action="store_true",
                        help="compare every recovered hello: whether the "
                             "extension order is stable across connections, "
                             "and which parameters vary")
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()

    payloads = datagrams(args.capture, args.port)
    groups = by_connection(payloads)
    print("%d UDP datagrams, %d long-header connections"
          % (len(payloads), len(groups)))

    recovered: list[bytes] = []
    for connection_id, group in groups.items():
        try:
            recovered.append(client_hello_from_datagrams(group))
        except (QuicError, ValueError):
            continue

    if not recovered:
        print("no ClientHello recovered. Check the capture holds the start of "
              "a connection: a handshake already in progress has none.")
        return 1

    chosen = None
    for raw in recovered:
        name = server_name_of(parse_client_hello(raw))
        marker = ""
        if args.host and name == args.host:
            chosen, marker = raw, "   <- chosen"
        print("  recovered %d bytes, sni %s%s" % (len(raw), name, marker))

    if args.all:
        print()
        compare(recovered)
        if args.out is None:
            return 0

    if chosen is None and args.host:
        # Falling back to another connection would write a fixture for a
        # server nobody asked about, which is worse than writing nothing:
        # the file says Firefox and the measurement says some other host.
        print()
        print("no connection carried sni %r. Nothing written." % args.host)
        print("Captured names are listed above; --all compares all of them.")
        return 1
    if chosen is None:
        if len(recovered) > 1:
            print()
            print("several connections and no --host, so nothing is written.")
            print("Pass --host to pick one, or --all to compare them.")
            return 1
        chosen = recovered[0]

    print()
    report(chosen)
    if args.out is not None:
        save_hex(args.out, chosen)
        print()
        print("wrote " + str(args.out))
    if args.dump:
        print()
        print(hexdump(chosen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
