"""Command line front end, shaped like curl."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urljoin

from . import profiles
from . import headers as header_tools
from .client import TooManyRedirects, UnsupportedUrl, request
from .message import Response
from .certs import CertificateError
from .proxies import ProxyError
from .records import TlsAlert


def parse_header(raw: str) -> tuple[str, str]:
    name, separator, value = raw.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("expected 'Name: value', got " + repr(raw))
    return name.strip(), value.strip()


def resolve_profile(name: str, http3: bool):
    """The profile for the transport actually being used.

    A profile belongs to a transport. Handing the QUIC profile to the TCP
    client would build a hello with three cipher suites and QUIC transport
    parameters over TCP, which no browser sends and which would be a worse
    fingerprint than not trying. So the two sets are kept apart and asking
    for one from the other side says which flag to use instead.
    """
    table = profiles.QUIC if http3 else profiles.TCP
    if name in table:
        return table[name]

    other = profiles.TCP if http3 else profiles.QUIC
    hint = ""
    if name in other:
        hint = ("; " + repr(name) + " is a "
                + ("TCP" if http3 else "QUIC") + " profile, so "
                + ("drop --http3" if http3 else "add --http3"))
    elif not http3 and name.replace("-", "").replace("_", "").endswith("quic"):
        # The name people reach for first, without the underscore.
        hint = "; for HTTP/3 use --http3"
    raise SystemExit("unknown profile " + repr(name) + "; available over "
                     + ("QUIC" if http3 else "TCP") + ": "
                     + ", ".join(sorted(table)) + hint)


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
    for _ in range(budget + 1):
        response = h3.get(url, timeout=args.timeout,
                          headers=overrides or None,
                          profile=profile, verify=not args.insecure)
        response.url = url
        if not 300 <= response.status < 400:
            break
        location = response.header("location")
        if not location:
            break
        history.append(response)
        url = urljoin(url, location)
    else:
        raise TooManyRedirects("more than %d redirects" % budget)
    response.history = history
    return response


def describe_request(profile, args) -> str:
    lines = ["> " + args.url,
             "> transport: " + ("quic/h3" if args.http3 else "tcp"),
             "> profile: " + profile.NAME]
    if args.proxy:
        lines.append("> proxy: " + args.proxy)
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
                             "firefox157_quic with --http3")
    parser.add_argument("--http3", action="store_true",
                        help="fetch over HTTP/3 instead of TCP. A separate "
                             "profile and a separate code path, not a "
                             "negotiation")
    parser.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.request is None:
        args.request = "POST" if args.data else "GET"
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
    if args.verbose:
        print(describe_request(profile, args), file=sys.stderr)

    try:
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
            )
    except (UnsupportedUrl, TooManyRedirects, TlsAlert, ProxyError,
            CertificateError) as exc:
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
