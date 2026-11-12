"""Keep what is published honest: README, docs pages and the shipped code."""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MEASURED = ("cloudflare-quic.com", "crunchbase", "etsy", "g2.com", "glassdoor",
            "homedepot", "home depot", "indeed.com", "macys", "macy's",
            "quora", "seatgeek", "sephora", "stubhub", "ticketmaster",
            "yelp", "zillow")
BANNED = ("undetectable", "bypass", "indistinguishable")

SUBTITLE = ("Python + browser: an HTTPS client that sends what a real "
            "browser sends")


def published_files():
    files = [ROOT / "README.md"]
    files += sorted((ROOT / "docs").glob("**/*.md"))
    return [f for f in files if f.is_file()]


def shipped_files():
    return sorted(f for f in (ROOT / "pybrws").rglob("*")
                  if f.is_file() and "__pycache__" not in f.parts)


def _whole_word(term):
    return re.compile(r"(?<![\w])" + re.escape(term) + r"(?![\w])",
                      re.IGNORECASE)


def _read(path):
    return path.read_text(encoding="utf-8", errors="replace")


class PublishedTextTests(unittest.TestCase):
    def test_readme_exists(self):
        self.assertTrue((ROOT / "README.md").is_file())

    def test_readme_opens_with_the_subtitle(self):
        lines = _read(ROOT / "README.md").splitlines()
        i = lines.index("# pybrws")
        rest = [l for l in lines[i + 1:] if l.strip()]
        self.assertEqual(rest[0].strip(), SUBTITLE)

    def test_no_measured_site_is_named(self):
        patterns = [(t, _whole_word(t)) for t in MEASURED]
        for path in published_files() + shipped_files():
            text = _read(path)
            for term, pat in patterns:
                with self.subTest(file=str(path.relative_to(ROOT)), term=term):
                    self.assertIsNone(pat.search(text))

    def test_no_overselling_words(self):
        for path in published_files():
            text = _read(path).lower()
            for word in BANNED:
                with self.subTest(file=str(path.relative_to(ROOT)), word=word):
                    self.assertNotIn(word, text)

    def test_no_local_paths(self):
        for path in published_files():
            text = _read(path)
            for bad in ("/Users/", "C:\\Users"):
                with self.subTest(file=str(path.relative_to(ROOT)), bad=bad):
                    self.assertNotIn(bad, text)

    def test_readme_links_are_absolute(self):
        text = _read(ROOT / "README.md")
        targets = re.findall(r"\]\(([^)\s]+)", text)
        targets += re.findall(r"^\[[^\]]+\]:\s*(\S+)", text, re.MULTILINE)
        self.assertTrue(targets)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue(target.startswith("https://"))

    def test_python_examples_compile(self):
        fence = re.compile(r"```python\n(.*?)```", re.DOTALL)
        for path in published_files():
            for n, block in enumerate(fence.findall(_read(path)), 1):
                with self.subTest(file=str(path.relative_to(ROOT)), block=n):
                    tree = ast.parse(block)
                    compile(tree, str(path), "exec")
                    imports = [node for node in tree.body
                               if isinstance(node, (ast.Import,
                                                    ast.ImportFrom))]
                    module = ast.Module(body=imports, type_ignores=[])
                    exec(compile(module, str(path), "exec"), {})


if __name__ == "__main__":
    unittest.main()
