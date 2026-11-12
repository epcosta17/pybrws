"""Command line front end, shaped like curl."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urljoin

from . import profiles
from . import headers as header_tools
from .client import (REDIRECT_STATUSES, TooManyRedirects, UnsupportedUrl,
                     Unmeasured, redirect_headers, request)
from .message import DEFAULT_MAX_BODY, ContentEncodingError, Response
from .certs import CertificateError
from .h3 import Http3Error
from .handshake import HandshakeError, TruncatedStream
from .http1 import Http1Error
from .http2 import Http2Error
from .proxies import ProxyError, parse_proxy
from .quic_impersonate import NotInstalled
from .records import TlsAlert, UnexpectedRecord
from .tls12 import Tls12Error

# What the library raises for a server, a response, a profile or an input it
# will not take: reported in one line, as curl does, not as a traceback.
REPORTED = (UnsupportedUrl, TooManyRedirects, TlsAlert, ProxyError, CertificateError,
            Unmeasured, ContentEncodingError, Http1Error, Http2Error, Http3Error,
            HandshakeError, Tls12Error, UnexpectedRecord, TruncatedStream,
            UnicodeError, profiles.ProfileError, NotInstalled)


# `pybrws <name> ...` runs one of the method's tools; each module has
# main(argv) -> int. `capture` takes a second word, the kind of capture.
SUBCOMMANDS = {
    "read-quic": "pybrws.tools.read_quic",
    "ja4": "pybrws.tools.ja4",
    "verify": "pybrws.tools.verify",
    "probe": "pybrws.tools.probe_fingerprint",
    "ab": "pybrws.tools.ab_test",
    "isolate": "pybrws.tools.isolate",
    "waf": "pybrws.tools.detect_waf",
}
CAPTURE_KINDS = {
    "hello": "pybrws.tools.catch_hello",
    "request": "pybrws.tools.catch_request",
    "h2": "pybrws.tools.catch_h2",
    "quic": "pybrws.tools.catch_quic",
    "resumed": "pybrws.tools.catch_resumed",
}
# The optional dependency to name when an import of it fails.
EXTRA_FOR = {"httpx": "measure", "aioquic": "http3"}


def missing_extra(error: ModuleNotFoundError, what: str):
    """SystemExit naming the extra to install, or None for any other module."""
    extra = EXTRA_FOR.get((error.name or "").split(".")[0])
    if extra is None:
        return None
    return SystemExit("pybrws %s needs %s: pip install 'pybrws[%s]'"
                      % (what, error.name.split(".")[0], extra))


def run_tool(module_name: str, argv: list[str], what: str) -> int:
    import importlib

    try:
        return importlib.import_module(module_name).main(argv)
    except ModuleNotFoundError as error:
        exit_ = missing_extra(error, what)
        if exit_ is None:
            raise
        raise exit_ from None


def dispatch(argv: list[str]) -> int | None:
    """Run a subcommand if `argv` names one; None means it is a fetch."""
    if not argv:
        return None
    if argv[0] in SUBCOMMANDS:
        return run_tool(SUBCOMMANDS[argv[0]], argv[1:], argv[0])
    if argv[0] == "capture":
        kinds = ", ".join(CAPTURE_KINDS)
        if len(argv) < 2 or argv[1] in ("-h", "--help"):
            print("usage: pybrws capture KIND [options]\n\nKIND is one of: " + kinds)
            return 0
        if argv[1] not in CAPTURE_KINDS:
            raise SystemExit("pybrws capture: unknown kind %r; one of: %s"
                             % (argv[1], kinds))
        return run_tool(CAPTURE_KINDS[argv[1]], argv[2:], "capture " + argv[1])
    return None


def parse_header(raw: str) -> tuple[str, str]:
    name, separator, value = raw.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("expected 'Name: value', got " + repr(raw))
    return name.strip(), value.strip()


def resolve_profile(name: str, http3: bool):
    """The profile for the transport actually being used."""
    try:
        return profiles.load(name, transport="quic" if http3 else "tcp")
    except profiles.WrongTransport as error:
        # Only this front end has --http3, so only it can name the flag.
        raise SystemExit(str(error) + ("; add --http3" if error.has == "quic"
                                       else "; drop --http3"))
    except profiles.ProfileError as error:
        raise SystemExit(str(error))


def fetch_http3(args, profile, overrides) -> Response:
    """One HTTP/3 fetch, following redirects by hand.

    `pybrws.h3` returns the response it gets and does not follow anything,
    so the loop lives here. Without it `-L` would silently mean nothing on
    this path while meaning something on the other -- the same arm
    answering a different question, which is how a comparison between the
    two transports goes wrong.
    """
    from . import h3

    url = args.url
    history: list[Response] = []
    budget = args.max_redirs if args.location else 0
    for hop in range(budget + 1):
        # The method and body asked for: h3 refuses what it has no
        # capture for, where this used to send a GET whatever -X and -d said.
        response = h3.request(url, method=args.request.upper(), data=args.data,
                              timeout=args.timeout, headers=overrides or None,
                              profile=profile, verify=not args.insecure,
                              max_body_size=getattr(args, "max_body_size",
                                                    DEFAULT_MAX_BODY))
        response.url = url
        location = response.header("location")
        # The statuses client.request follows, so both arms agree on what
        # a redirect is; a 304 with a Location header is not one.
        if response.status not in REDIRECT_STATUSES or not location:
            break
        if hop == budget:
            if budget == 0:
                break   # --no-location: the redirect is the answer, as over TCP
            raise TooManyRedirects("still redirecting after %d hops, last %r"
                                   % (budget, urljoin(url, location)))
        history.append(response)
        next_url = urljoin(url, location)
        overrides = redirect_headers(overrides, url, next_url)
        url = next_url
    response.history = history
    return response


def describe_request(profile, args) -> str:
    lines = ["> " + args.url,
             "> transport: " + ("quic/h3" if args.http3 else "tcp"),
             "> profile: " + profile.NAME]
    if args.proxy:
        # str(Proxy) omits the password: -v output gets pasted into issues.
        lines.append("> proxy: " + str(parse_proxy(args.proxy)))
    for name, value in args.header:
        lines.append("> override: " + name + ": " + value)
    return "\n".join(lines)


def render_head(response: Response) -> str:
    version = response.http_version or "h2"
    lines = [version + " " + str(response.status)]
    lines += [name + ": " + value for name, value in response.headers]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pybrws",
        description="Fetch an https URL with a browser's protocol fingerprint.",
        epilog="subcommands (pybrws <name> --help): capture {%s}, %s"
               % (",".join(CAPTURE_KINDS), ", ".join(SUBCOMMANDS)),
    )
    parser.add_argument("url", help="the https URL to fetch")
    parser.add_argument("-X", "--request", default=None, metavar="METHOD",
                        help="HTTP method; defaults to GET, or POST with -d")
    parser.add_argument("-d", "--data", metavar="BODY",
                        help="request body; implies POST unless -X says otherwise")
    parser.add_argument("-H", "--header", action="append", default=[],
                        type=parse_header, metavar="'Name: value'",
                        help="replace or add a request header, repeatable")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write the body to FILE instead of stdout")
    parser.add_argument("-i", "--include", action="store_true",
                        help="print the response head before the body")
    parser.add_argument("-I", "--head-only", action="store_true",
                        help="print the response head and not the body")
    # curl needs -L; a browser always follows, and this tool imitates a
    # browser. --no-location restores curl's behaviour.
    parser.add_argument("-L", "--location", action="store_true", default=True,
                        help="follow redirects (the default)")
    parser.add_argument("--no-location", dest="location", action="store_false",
                        help="return the redirect instead of following it")
    parser.add_argument("--max-redirs", type=int, default=5, metavar="N")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="describe the request on stderr")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="suppress the status line on stderr")
    parser.add_argument("-x", "--proxy", metavar="URL",
                        help="http://, socks5:// or socks5h://, with optional "
                             "user:pass@")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="skip certificate verification, as curl's -k does")
    parser.add_argument("--profile", default=None, metavar="NAME",
                        help="firefox157 or chrome155 over TCP, "
                             "firefox157_quic with --http3; or a .py "
                             "profile file")
    parser.add_argument("--http3", action="store_true",
                        help="fetch over HTTP/3 instead of TCP. A separate "
                             "profile and a separate code path, not a "
                             "negotiation")
    parser.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS")
    parser.add_argument("--max-filesize", type=int, default=None, metavar="BYTES",
                        help="the most a response body may be, received or "
                             "decoded (default 128 MiB); 0 lifts the cap")
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    done = dispatch(list(argv))
    if done is not None:
        return done
    args = build_parser().parse_args(argv)
    if args.request is None:
        args.request = "POST" if args.data else "GET"
    if args.max_filesize is None:
        args.max_body_size = DEFAULT_MAX_BODY
    else:
        args.max_body_size = args.max_filesize or None   # 0: no cap
    overrides = list(args.header)
    if args.data and not header_tools.has(overrides, "content-type"):
        # curl's default for -d, and a server will otherwise guess.
        overrides.append(("Content-Type", "application/x-www-form-urlencoded"))

    if args.profile is None:
        args.profile = "firefox157_quic" if args.http3 else "firefox157"
    profile = resolve_profile(args.profile, args.http3)
    if args.http3 and args.proxy:
        raise SystemExit("--proxy does not apply to --http3: QUIC is UDP and "
                         "this client has no UDP proxy support")

    try:
        if args.verbose:
            # Inside the try: describing the proxy parses it, and a proxy
            # that does not parse is the ProxyError the request would raise.
            print(describe_request(profile, args), file=sys.stderr)
        if args.http3:
            response = fetch_http3(args, profile, overrides)
        else:
            response = request(
                args.url,
                method=args.request.upper(),
                headers=overrides or None,
                data=args.data,
                profile=profile,
                timeout=args.timeout,
                follow_redirects=args.max_redirs if args.location else 0,
                proxy=args.proxy,
                verify=not args.insecure,
                max_body_size=args.max_body_size,
            )
    except ModuleNotFoundError as exc:
        exit_ = missing_extra(exc, "--http3")
        if exit_ is None:
            raise
        raise exit_ from None
    except REPORTED as exc:
        raise SystemExit(type(exc).__name__ + ": " + str(exc))
    except OSError as exc:
        raise SystemExit("connection failed: " + str(exc))

    if not args.silent:
        for hop in response.history:
            print("* " + str(hop.status) + " -> " + (hop.header("location") or ""),
                  file=sys.stderr)
        print("* " + str(response.status) + " " + (response.http_version or "h2")
              + " " + str(len(response.body)) + " bytes", file=sys.stderr)

    if args.include or args.head_only:
        print(render_head(response))
        if not args.head_only:
            print()

    if not args.head_only:
        if args.output:
            Path(args.output).write_bytes(response.body)
        else:
            sys.stdout.buffer.write(response.body)
            sys.stdout.buffer.flush()

    return 0 if response.status < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
