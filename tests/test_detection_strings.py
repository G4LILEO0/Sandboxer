"""Detection strings (sandbox.detections.strings): shipped TOML defaults, bound globals, overrides."""

import re

import pytest

from sandbox.analysis import domains
from sandbox.detections import strings as detection
from sandbox.detections import clickfix, lures, network


@pytest.fixture(autouse=True)
def _clean():
    detection.reset()
    yield
    detection.reset()


def test_every_shipped_entry_loads_and_is_documented():
    entries = detection.entries()
    assert len(entries) >= 90
    for key, e in entries.items():
        assert e.title and e.description, key
        assert e.compiled is not None, key


def test_every_entry_is_used_by_the_code():
    """An entry no binding reads would be an edit that silently does nothing."""
    bound = {b.key for b in detection._state.bindings}
    assert bound == set(detection.entries())


def test_bound_globals_follow_the_active_value():
    for b in detection._state.bindings:
        module = b.namespace["__name__"]
        assert module.startswith("sandbox.detections.") or b.namespace is vars(domains), module
        value = detection.get(b.key)
        expected = b.convert(value) if b.convert else value
        assert b.namespace[b.name] == expected, b.name


def test_threatmetrix_host_pattern_matches():
    """The shipped host pattern used to carry a stray backspace and never matched."""
    assert network._fraud_vendor(["https://h.online-metrix.net/abc.js"]) == "threatmetrix"


def test_override_changes_detection_and_revert_restores_it():
    assert domains.free_hosting("kit.newhost.example") is None
    shipped = detection.entries()["hosting.free_hosting"].default["values"]
    problems = detection.apply_overrides(
        [{"key": "hosting.free_hosting", "value": {"values": [*shipped, "newhost.example"]}}]
    )
    assert problems == []
    assert domains.free_hosting("kit.newhost.example") == "newhost.example"
    assert domains.site("kit.newhost.example") == "kit.newhost.example"
    v_edited = detection.version()

    detection.reset()
    assert domains.free_hosting("kit.newhost.example") is None
    assert detection.version() != v_edited


def test_regex_override_reaches_clickfix_traits():
    text = "please run zzfetch https://x.example/a | zzrun"
    assert clickfix._clickfix_traits(text) is None
    entry = detection.entries()["clickfix.unambiguous_traits"]
    items = [*entry.default["items"], {"pattern": r"\bzzfetch\b.*\|\s*zzrun", "flags": "i"}]
    assert (
        detection.apply_overrides(
            [{"key": "clickfix.unambiguous_traits", "value": {"items": items}}]
        )
        == []
    )
    assert clickfix._clickfix_traits(text) == "unambiguous"


def test_a_broken_override_is_skipped_and_the_default_kept():
    problems = detection.apply_overrides(
        [
            {"key": "clickfix.run_dialog", "value": {"pattern": "(unclosed", "flags": "i"}},
            {"key": "no.such_entry", "value": {"values": []}},
        ]
    )
    assert len(problems) == 2
    entry = detection.entries()["clickfix.run_dialog"]
    assert entry.error and entry.compiled.pattern == entry.default["pattern"]
    assert lures._RUN_DIALOG.search("Press Win + R")


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("clickfix.run_dialog", {"pattern": "(", "flags": "i"}, "not a valid regular expression"),
        ("clickfix.run_dialog", {"pattern": "a", "flags": "q"}, "flags"),
        ("clickfix.run_dialog", {"pattern": "", "flags": ""}, "empty"),
        ("scripts.libraries", {"items": [{"pattern": "x", "flags": ""}]}, "name"),
        ("network.remote_access_ports", {"values": {"ssh": "ssh"}}, "port"),
        ("forms.prompt_points", {"values": {"password": "lots"}}, "whole number"),
        ("downloads.executable_extensions", {"values": ["exe", ""]}, "non-empty"),
        ("clickfix.fetch_and_run", {"items": []}, "at least one"),
    ],
)
def test_invalid_values_are_rejected_with_a_reason(key, value, message):
    with pytest.raises(detection.DetectionValueError, match=message):
        detection.check_value(key, value)


def test_defaults_are_stored_without_inline_flag_groups():
    """Flags live in the flags field, so the Admin checkboxes show the truth."""
    for e in detection.entries().values():
        patterns = (
            [e.default]
            if e.type == "regex"
            else e.default.get("items", [])
            if e.type == "regex_list"
            else []
        )
        for p in patterns:
            assert not re.match(r"^\(\?[imsx]+\)", p["pattern"]), e.key
