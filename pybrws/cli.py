"""Command line front end, shaped like curl."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

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


def resolve_profile(name: str):
    try:
        return getattr(profiles, name)
    except AttributeError:
        available = ", ".join(profiles.__all__)
        raise SystemExit("unknown profile " + repr(name) + "; available: " + available)


def describe_request(profile, args) -> str:
    lines = ["> " + args.url, "> profile: " + profile.NAME]
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
    parser.add_argument("--profile", default="firefox157", metavar="NAME")
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

    profile = resolve_profile(args.profile)
    if args.verbose:
        print(describe_request(profile, args), file=sys.stderr)

    try:
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
