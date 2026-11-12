"""Browser profiles: the constants that make up a given client's ClientHello.

A profile is tied to a transport, because a browser does not send the same
hello over both. `firefox157_quic` carries three cipher suites and QUIC
transport parameters and is only meaningful through `pybrws.h3`; sending it
over TCP would produce a hello no browser has ever sent. So it is exported
separately from the two the TCP client can use, and `TCP` is what anything
choosing a profile by name should offer.
"""

import importlib.util
import os
import re
import types
from pathlib import Path

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

REQUIRED_TCP = (
    "NAME", "RECORD_VERSION", "LEGACY_VERSION", "CIPHER_SUITES",
    "SESSION_ID_SIZE", "COMPRESSION_METHODS", "KEY_SHARE_GROUPS",
    "H1_HEADERS", "H1_COOKIE_BEFORE", "H2_SETTINGS",
    "H2_CONNECTION_WINDOW_UPDATE", "H2_FIRST_STREAM_ID", "H2_PSEUDO_ORDER",
    "H2_NAVIGATION_HEADERS", "H2_COOKIE_BEFORE",
)

REQUIRED_QUIC = (
    "NAME", "ALPN_PROTOCOLS", "CIPHER_SUITES", "SESSION_ID_SIZE",
    "LEGACY_COMPRESSION_METHODS", "KEY_SHARE_GROUPS", "CONNECTION_ID_SIZE",
    "IDLE_TIMEOUT_SECONDS", "MAX_DATA", "MAX_STREAM_DATA",
    "MAX_DATAGRAM_FRAME_SIZE", "STATIC_PAYLOADS", "EXT_SERVER_NAME",
    "EXT_KEY_SHARE", "EXT_QUIC_TRANSPORT_PARAMETERS",
    "EXT_ENCRYPTED_CLIENT_HELLO", "extension_order", "server_name",
    "transport_parameters", "greased_ech", "navigation_headers",
)

_EXTENSION_HINT = "EXTENSIONS, or extension_order and payload_for"


class ProfileError(ValueError):
    """A profile could not be found, imported or does not meet the contract."""


class WrongTransport(ProfileError):
    """A built-in profile of the other transport was asked for.

    `has` is the transport the named profile belongs to ("tcp" or "quic"),
    for a front end to turn into advice about its own flags.
    """

    def __init__(self, message: str, *, has: str):
        super().__init__(message)
        self.has = has


def is_path(spec) -> bool:
    if isinstance(spec, os.PathLike):
        return True
    return Path(spec).suffix == ".py" or "/" in spec or "\\" in spec


def _by_name(name: str, transport: str) -> types.ModuleType:
    if transport not in ("tcp", "quic", "any"):
        raise ValueError("transport must be 'tcp', 'quic' or 'any'")
    if transport == "any":
        table = {**TCP, **QUIC}
    else:
        table = QUIC if transport == "quic" else TCP
    if name in table:
        return table[name]

    # A profile belongs to a transport. Handing the QUIC profile to the TCP
    # client would build a hello with three cipher suites and QUIC transport
    # parameters over TCP, which no browser sends and which would be a worse
    # fingerprint than not trying. So asking for one from the other side
    # says which transport is needed; a front end that has a flag for it
    # adds the flag (see WrongTransport.has).
    http3 = transport == "quic"
    other = TCP if http3 else QUIC
    needed, have = ("QUIC", "TCP") if http3 else ("TCP", "QUIC")
    if name in other:
        raise WrongTransport(
            repr(name) + " is a " + have + " profile; this needs a " + needed
            + " profile: " + ", ".join(sorted(table)), has=have.lower())
    label = {"tcp": "TCP", "quic": "QUIC", "any": "any transport"}[transport]
    message = ("unknown profile " + repr(name) + "; available over " + label
               + ": " + ", ".join(sorted(table)))
    if not http3 and name.replace("-", "").replace("_", "").endswith("quic"):
        # The name people reach for first, without the underscore.
        raise WrongTransport(message + "; the QUIC profiles are: "
                             + ", ".join(sorted(QUIC)), has="quic")
    raise ProfileError(message)


def _from_file(spec) -> types.ModuleType:
    path = Path(spec)
    if not path.is_file():
        raise ProfileError("no profile file at " + str(path))
    module_name = "pybrws_profile_" + re.sub(r"\W", "_", path.stem)
    found = importlib.util.spec_from_file_location(module_name, path)
    if found is None or found.loader is None:
        raise ProfileError(str(path) + " cannot be loaded as a Python module")
    module = importlib.util.module_from_spec(found)
    try:
        found.loader.exec_module(module)
    except ImportError as exc:
        if "relative import" in str(exc):
            raise ProfileError(
                str(path) + " uses a relative import; a profile file is "
                "loaded on its own, so it must use absolute imports "
                "(from pybrws.profiles.firefox157 import *)") from exc
        raise ProfileError(
            str(path) + " failed to import: " + str(exc)) from exc
    except Exception as exc:
        raise ProfileError(str(path) + " failed to load: "
                           + type(exc).__name__ + ": " + str(exc)) from exc
    return module


def _check(module: types.ModuleType, transport: str) -> None:
    if transport == "any":
        transport = "quic" if hasattr(module, "transport_parameters") else "tcp"
    required = REQUIRED_QUIC if transport == "quic" else REQUIRED_TCP
    missing = [name for name in required if not hasattr(module, name)]
    if transport == "tcp" and not (
            hasattr(module, "EXTENSIONS")
            or (hasattr(module, "extension_order")
                and hasattr(module, "payload_for"))):
        missing.append(_EXTENSION_HINT)
    if missing:
        label = getattr(module, "NAME", module.__name__)
        raise ProfileError("profile " + repr(label) + " is missing: "
                           + ", ".join(missing))


def load(spec, *, transport: str = "tcp") -> types.ModuleType:
    """A profile module from a module, a built-in name or a .py file path.

    `transport` is "tcp", "quic" or "any". A file's contract is checked; the
    built-ins are returned as they are.
    """
    if isinstance(spec, types.ModuleType):
        return spec
    if is_path(spec):
        module = _from_file(spec)
        _check(module, transport)
        return module
    return _by_name(spec, transport)


__all__ = ["chrome155", "firefox157", "firefox157_quic", "TCP", "QUIC",
           "REQUIRED_TCP", "REQUIRED_QUIC", "ProfileError", "WrongTransport", "is_path", "load"]
