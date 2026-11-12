"""Report internal links in a built site whose target file does not exist.

Usage: python tools/check_docs_links.py SITE_DIR
"""
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)


def _target(site, page, link):
    """The file a link points at, or None for external and in-page links."""
    parts = urlsplit(link)
    if parts.scheme or parts.netloc or not parts.path:
        return None
    path = unquote(parts.path)
    base = site if path.startswith("/") else page.parent
    target = (base / path.lstrip("/")).resolve()
    return target / "index.html" if path.endswith("/") or target.is_dir() else target


def broken_links(site):
    site = Path(site).resolve()
    broken = []
    for page in sorted(site.rglob("*.html")):
        parser = _Links()
        parser.feed(page.read_text(encoding="utf-8", errors="replace"))
        for link in parser.links:
            target = _target(site, page, link)
            if target is not None and not target.is_file():
                broken.append((page.relative_to(site), link))
    return broken


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    broken = broken_links(argv[1])
    for page, link in broken:
        print(f"{page}: {link}")
    print(f"{len(broken)} broken links")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
