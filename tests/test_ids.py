import time

import pytest

from sandbox.ids import new_id


def test_prefix_and_length():
    value = new_id("an")
    assert value.startswith("an_")
    assert len(value) == 3 + 26


def test_sortable_by_time():
    first = new_id("an")
    time.sleep(0.002)
    assert new_id("an") > first


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("plain", "plain"),
        ("a\x00b", "a�b"),
        ("lone \ud83d surrogate", "lone � surrogate"),
        ("paired \U0001f600 emoji", "paired \U0001f600 emoji"),
        ("literal \\u0000 text", "literal \\u0000 text"),  # backslash text is left alone
    ],
)
def test_json_safe_strings(raw, clean):
    from sandbox.db.engine import json_safe

    assert json_safe(raw) == clean


def test_json_safe_walks_nested_values_and_keys():
    from sandbox.db.engine import _serialize, json_safe

    value = {"a\x00": [{"b": "c\x00"}, ("d", 1, None, True)]}
    assert json_safe(value) == {"a�": [{"b": "c�"}, ["d", 1, None, True]]}
    assert "\\u0000" not in _serialize(value)
