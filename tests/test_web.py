"""Static checks that the web UI's scripts and pages agree.

A redesign that renames or removes an element breaks the script that looks it up, and
nothing else notices until an analyst hits a TypeError. These tests fail first.
"""

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parent.parent / "sandbox" / "web"
PAGES = sorted(WEB.glob("*.html"))

_LOOKUPS = [
    re.compile(r"getElementById\(\s*'([^']+)'\s*\)"),
    re.compile(r"\bsection\(\s*'([^']+)'\s*\)"),
    re.compile(r"querySelector(?:All)?\(\s*'#([A-Za-z0-9_-]+)"),
]
# Lookups that are guarded on purpose (the element exists on some pages only).
_OPTIONAL = {("theme.js", "theme-toggle"), ("report.js", "tl-net")}


def _scripts(html: str) -> list[str]:
    return re.findall(r'<script src="([^"?]+)', html)


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_every_element_a_script_looks_up_is_on_its_page(page):
    html = page.read_text(encoding="utf-8")
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    missing = []
    for src in _scripts(html):
        code = (WEB / src).read_text(encoding="utf-8")
        created = set(re.findall(r"\bid:\s*'([^']+)'", code))  # elements the script builds
        for pattern in _LOOKUPS:
            for element_id in set(pattern.findall(code)):
                name = Path(src).name
                if element_id not in ids | created and (name, element_id) not in _OPTIONAL:
                    missing.append(f"{name} -> #{element_id}")
    assert not missing, f"{page.name} lacks elements its scripts use: {sorted(missing)}"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_named_inputs_a_script_reads_are_on_its_page(page):
    html = page.read_text(encoding="utf-8")
    names = set(re.findall(r'\bname="([^"]+)"', html))
    missing = []
    for src in _scripts(html):
        code = (WEB / src).read_text(encoding="utf-8")
        missing += [n for n in re.findall(r'input\[name="([^"]+)"\]', code) if n not in names]
    assert not missing, f"{page.name} lacks inputs its scripts read: {missing}"


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_page_assets_exist_and_are_versioned(page):
    """Versioned URLs make browsers fetch new scripts after a deploy instead of running a
    cached old script against a new page."""
    html = page.read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="((?:js|css)/[^"]+)"', html)
    assert refs
    for ref in refs:
        path, _, query = ref.partition("?")
        assert (WEB / path).is_file(), f"{page.name} references missing {path}"
        assert query.startswith("v="), f"{page.name} loads {path} without ?v="
    versions = {ref.partition("?v=")[2] for ref in refs}
    assert len(versions) == 1, f"{page.name} mixes asset versions {versions}"
