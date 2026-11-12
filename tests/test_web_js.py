"""Runs the lookup page's JavaScript unit tests (tests/js, node:test) under Node.

The page's scripts are plain browser scripts; tests/js/harness.mjs loads them into a
VM context with a stub window, so no browser is needed. Skipped where Node is absent
(the api image), so run them on a machine with Node: ``node --test tests/js/``.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

JS_TESTS = Path(__file__).resolve().parent / "js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_lookup_page_javascript():
    files = sorted(str(p) for p in JS_TESTS.glob("*.test.mjs"))
    result = subprocess.run(["node", "--test", *files], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
