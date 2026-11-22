"""Compose refuses a .env with a line that is neither a comment nor KEY=value
("key cannot contain a space"), so .env.example must stay parseable."""

import re
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"


def test_every_line_is_a_comment_or_an_assignment():
    if not EXAMPLE.exists():
        pytest.skip(".env.example not in this checkout")
    for number, line in enumerate(EXAMPLE.read_text().splitlines(), 1):
        stripped = line.strip()
        assert not stripped or stripped.startswith("#") or re.match(r"^[A-Z0-9_]+=", stripped), (
            f".env.example line {number} is not a comment or KEY=value: {line!r}"
        )
