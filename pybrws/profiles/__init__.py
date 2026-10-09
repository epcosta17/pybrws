"""Browser profiles: the constants that make up a given client's ClientHello.

A profile is tied to a transport, because a browser does not send the same
hello over both. `firefox157_quic` carries three cipher suites and QUIC
transport parameters and is only meaningful through `pybrws.h3`; sending it
over TCP would produce a hello no browser has ever sent. So it is exported
separately from the two the TCP client can use, and `TCP` is what anything
choosing a profile by name should offer.
"""

from . import chrome155
from . import firefox157
from . import firefox157_quic

#: Profiles the TCP client (`pybrws.client`) can send.
TCP = {
    "firefox157": firefox157,
    "chrome155": chrome155,
}

#: Profiles `pybrws.h3` can send.
QUIC = {
    "firefox157_quic": firefox157_quic,
}

__all__ = ["chrome155", "firefox157", "firefox157_quic", "TCP", "QUIC"]
