"""The documentation site: its config, its pages, its build recipe and tools."""
import ast
import inspect
import importlib
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from tests.test_published_text import BANNED, MEASURED, _whole_word

ROOT = Path(__file__).resolve().parent.parent
API_MODULES = ("pybrws.client", "pybrws.session", "pybrws.pool",
               "pybrws.h3", "pybrws.profiles", "pybrws.message")


def _config():
    with open(ROOT / "zensical.toml", "rb") as f:
        return tomllib.load(f)


def _nav_paths(nav):
    for item in nav:
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for value in item.values():
                if isinstance(value, str):
                    yield value
                else:
                    yield from _nav_paths(value)


def _docstrings(module):
    """The module's docstring and those of its public classes, functions
    and methods, as (name, text) pairs."""
    found = [(module.__name__, inspect.getdoc(module) or "")]
    for name, obj in vars(module).items():
        if name.startswith("_") or getattr(obj, "__module__", None) != module.__name__:
            continue
        if inspect.isclass(obj):
            found.append((name, inspect.getdoc(obj) or ""))
            for mname, member in vars(obj).items():
                if mname.startswith("_") and mname != "__init__":
                    continue
                if inspect.isfunction(member):
                    found.append((f"{name}.{mname}", inspect.getdoc(member) or ""))
        elif inspect.isfunction(obj):
            found.append((name, inspect.getdoc(obj) or ""))
    return found


class DocsConfigTests(unittest.TestCase):
    def test_site_url_is_read_the_docs(self):
        self.assertEqual(_config()["project"]["site_url"],
                         "https://pybrws.readthedocs.io/")

    def test_every_nav_page_exists(self):
        paths = [p for p in _nav_paths(_config()["project"]["nav"])
                 if p.endswith(".md")]
        self.assertTrue(paths)
        for path in paths:
            self.assertTrue((ROOT / "docs" / path).is_file(), path)

    def test_every_api_module_has_a_page(self):
        text = "\n".join(p.read_text(encoding="utf-8")
                         for p in (ROOT / "docs" / "api").glob("*.md"))
        for module in API_MODULES:
            self.assertIn(module, text)

    def test_read_the_docs_runs_zensical(self):
        text = (ROOT / ".readthedocs.yaml").read_text(encoding="utf-8")
        self.assertIn("zensical build", text)
        self.assertIn("$READTHEDOCS_OUTPUT/html", text)

    def test_link_checker_finds_a_broken_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp)
            (site / "index.html").write_text(
                '<a href="missing.html">x</a><a href="other/">y</a>'
                '<a href="https://example.com/">z</a>', encoding="utf-8")
            (site / "other").mkdir()
            (site / "other" / "index.html").write_text("ok", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "check_docs_links.py"),
                 tmp], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing.html", result.stdout + result.stderr)
        self.assertNotIn("other", result.stdout + result.stderr)

    def test_link_checker_passes_a_clean_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "index.html").write_text(
                '<a href="#top">x</a>', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "check_docs_links.py"),
                 tmp], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("0 broken links", result.stdout)

    def test_rendered_docstrings_are_clean(self):
        for name in API_MODULES:
            module = importlib.import_module(name)
            for where, doc in _docstrings(module):
                for word in BANNED:
                    self.assertIsNone(_whole_word(word).search(doc),
                                      f"{name}:{where} has {word!r}")
                for site in MEASURED:
                    self.assertIsNone(_whole_word(site).search(doc),
                                      f"{name}:{where} names {site!r}")


if __name__ == "__main__":
    unittest.main()
