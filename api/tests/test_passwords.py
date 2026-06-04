"""Tests for core/passwords — bcrypt hash/verify + NIST-aligned
strength check.

Pinning the strength rules because the password policy is the
exposed contract: a future "we made it tighter" change shouldn't
silently lock out a customer's existing users.
"""
from __future__ import annotations

import pytest

from src.core.passwords import (
    PasswordTooWeak,
    check_strength,
    hash_password,
    verify_password,
)


# ── strength ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "password",
    [
        "Correct-Horse-1!",      # all 4 classes, well above 12 chars
        "abcdefghijkl123!",       # lower + digit + symbol  (3 classes)
        "ABCDEFGHIJKL123$",       # upper + digit + symbol  (3 classes)
        "abcdEFGHijkl!",          # lower + upper + symbol  (3 classes)
    ],
)
def test_check_strength_accepts_valid(password: str) -> None:
    check_strength(password)  # raises on failure


@pytest.mark.parametrize(
    "password,reason",
    [
        ("short!1A",                 "too short"),
        ("alllowercase1234",         "only 2 classes (lower + digit)"),
        ("ALLUPPERCASE1234",         "only 2 classes (upper + digit)"),
        ("abcdefghijklmnop",         "only 1 class (lower)"),
        ("",                          "empty"),
    ],
)
def test_check_strength_rejects_weak(password: str, reason: str) -> None:
    with pytest.raises(PasswordTooWeak):
        check_strength(password)


def test_check_strength_minimum_length_is_12() -> None:
    """The min-length floor is part of the public contract — make any
    change to it explicit by failing this test."""
    eleven_chars = "Abcd123!Abc"  # 11 chars, all 4 classes
    twelve_chars = eleven_chars + "x"
    with pytest.raises(PasswordTooWeak):
        check_strength(eleven_chars)
    check_strength(twelve_chars)


# ── hash + verify ─────────────────────────────────────────────────────


async def test_hash_verify_round_trip() -> None:
    pw = "Correct-Horse-Battery-Staple-1!"
    hashed = hash_password(pw)
    assert hashed != pw
    assert hashed.startswith("$2b$")     # bcrypt prefix
    assert await verify_password(pw, hashed) is True


async def test_hash_verify_rejects_wrong_password() -> None:
    hashed = hash_password("Correct-Horse-1!")
    assert await verify_password("Wrong-Password-9?", hashed) is False


async def test_hash_is_salted() -> None:
    """Two hashes of the same plaintext must differ (bcrypt salts)."""
    pw = "Correct-Horse-1!"
    h1 = hash_password(pw)
    h2 = hash_password(pw)
    assert h1 != h2
    assert await verify_password(pw, h1) is True
    assert await verify_password(pw, h2) is True
