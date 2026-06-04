"""Tests for core/semver_util.bump_patch — used by the republish flow."""
from __future__ import annotations

import pytest

from src.core.semver_util import bump_patch


@pytest.mark.parametrize(
    "input_version,expected",
    [
        ("v1.0.0",      "v1.0.1"),
        ("v0.1.0",      "v0.1.1"),
        ("v2.5.99",     "v2.5.100"),   # double-digit patches keep working
        ("1.0.0",       "1.0.1"),      # leading 'v' preserved when absent
        ("  v3.4.5  ",  "v3.4.6"),     # whitespace tolerated
    ],
)
def test_bump_patch_happy(input_version: str, expected: str) -> None:
    assert bump_patch(input_version) == expected


@pytest.mark.parametrize(
    "bad_version",
    [
        "v1",
        "v1.0",
        "v1.0.0-rc1",
        "v1.0.0.4",
        "invalid",
        "",
        "1",
        ".1.0",
    ],
)
def test_bump_patch_rejects_unparseable(bad_version: str) -> None:
    """Republish endpoint translates None → 400 forcing the caller to
    supply new_version_semver explicitly. Tests pin the boundary
    so an over-eager regex tweak can't accidentally accept tags."""
    assert bump_patch(bad_version) is None


def test_bump_patch_pure() -> None:
    """No side effects — calling it doesn't mutate the input string."""
    inp = "v1.2.3"
    bump_patch(inp)
    assert inp == "v1.2.3"
