"""The method articles: a TL;DR first, commands that exist, marked screenshots."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from pybrws import cli

ROOT = Path(__file__).resolve().parent.parent
METHOD = ROOT / "docs" / "method"
ARTICLES = ("01-capture.md", "02-compare.md", "03-profile.md",
            "04-verify.md", "05-measure.md")
TLDR = '!!! abstract "TL;DR"'

# A command is a line of a console block, or a line after a `$ ` prompt in
# any block, as verify echoes its own. Other blocks are output, where a line
# such as "pybrws chrome155, as measured over the network" is not a command,
# and `pybrws` further along a line is an argument, such as the arm in
# `--arms pybrws pybrws-h3`.
COMMAND = re.compile(r"^[ \t]*pybrws[ \t]+(\S+)(?:[ \t]+(\S+))?", re.MULTILINE)
PROMPTED = re.compile(r"^[ \t]*\$[ \t]+pybrws[ \t]+(\S+)(?:[ \t]+(\S+))?",
                      re.MULTILINE)
PLACEHOLDER = re.compile(
    r'^!!! note "Screenshot pending: ([a-z0-9]+(?:-[a-z0-9]+)*)"$')
# Where a screenshot goes once it is taken: assets/screenshots/<id>.png.
TAKEN = re.compile(r"!\[[^\]]*\]\((?:\.\./)*assets/screenshots/"
                   r"([a-z0-9]+(?:-[a-z0-9]+)*)\.png\)")


def _text(name: str) -> str:
    return (METHOD / name).read_text(encoding="utf-8")


def _pages():
    return sorted(METHOD.glob("*.md"))


def code_blocks(text: str) -> list[tuple[str, str]]:
    """The fenced code blocks of a page, indented ones included, as
    (language, body) pairs."""
    blocks, fence, language, lines = [], None, "", []
    for line in text.splitlines():
        stripped = line.strip()
        if fence is None:
            opening = re.match(r"(`{3,}|~{3,})\s*([\w-]*)", stripped)
            if opening:
                fence, language, lines = opening.group(1), opening.group(2), []
        elif stripped.startswith(fence) and not stripped.strip(fence[0]):
            blocks.append((language, "\n".join(lines)))
            fence = None
        else:
            lines.append(line)
    return blocks


def commands(language: str, body: str) -> list[tuple[str, str]]:
    """The `pybrws` commands in a code block, as (word, following word)."""
    found = PROMPTED.findall(body)
    if language == "console":
        found += COMMAND.findall(body)
    return found


class MethodArticlesTests(unittest.TestCase):
    def test_five_articles_each_open_with_a_tldr(self):
        for name in ARTICLES:
            with self.subTest(article=name):
                text = _text(name)
                lines = [line for line in text.splitlines() if line.strip()]
                self.assertGreaterEqual(len(lines), 3)
                self.assertTrue(lines[0].startswith("# "), lines[0])
                self.assertEqual(lines[1], TLDR)
                self.assertTrue(lines[2].startswith("    "),
                                "the TL;DR has no body")
                self.assertTrue(code_blocks(text), "no fenced code block")

    def test_commands_in_articles_exist(self):
        found = []
        for page in _pages():
            for language, body in code_blocks(page.read_text(encoding="utf-8")):
                for word, following in commands(language, body):
                    found.append(word)
                    with self.subTest(page=page.name, command=word,
                                      following=following):
                        if word == "capture":
                            self.assertIn(following, cli.CAPTURE_KINDS)
                        elif not word.startswith("https://"):
                            self.assertIn(word, cli.SUBCOMMANDS)
        self.assertTrue(found, "no pybrws command in any code block")

    def test_screenshot_placeholders_are_marked(self):
        ids = []
        for page in _pages():
            lines = page.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines):
                mentions = "screenshot pending" in line.lower()
                titled = (line.lstrip().startswith(("!!!", "???"))
                          and "screenshot" in line.lower())
                if not (mentions or titled):
                    continue
                with self.subTest(page=page.name, line=number + 1):
                    marked = PLACEHOLDER.match(line)
                    self.assertIsNotNone(marked, line)
                    following = lines[number + 1:number + 2]
                    self.assertTrue(following and following[0].startswith("    ")
                                    and following[0].strip(),
                                    "the placeholder does not say what goes there")
                    ids.append(marked.group(1))
            ids += TAKEN.findall("\n".join(lines))
        self.assertTrue(ids, "the method shows no screenshot, pending or taken")
        repeated = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual(repeated, [], "screenshot ids used twice")


if __name__ == "__main__":
    unittest.main()
