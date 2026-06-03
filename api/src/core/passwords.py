"""Password hashing + verification + strength checking for tenant users.

Bcrypt with cost factor 12 — same as tenant_tokens.token_secret_hash in
core/tenant_auth.py. Verify runs in a thread to keep the event loop
responsive under load (bcrypt is CPU-bound, ~50ms at cost 12).

Strength check: minimum length from settings (default 12), and at least
three of {lowercase, uppercase, digit, symbol}. This is intentionally
relaxed compared to per-character classes-required rules (which NIST
SP 800-63B 5.1.1.2 explicitly recommends against). The hard floor is
length; complexity is a tiebreaker.
"""
from __future__ import annotations

import asyncio
import re

import bcrypt

from .config import get_settings


_CLASS_PATTERNS = {
    "lower": re.compile(r"[a-z]"),
    "upper": re.compile(r"[A-Z]"),
    "digit": re.compile(r"[0-9]"),
    "symbol": re.compile(r"[^a-zA-Z0-9]"),
}


class PasswordTooWeak(ValueError):
    """Raised by check_strength; routers translate to 400."""


def check_strength(password: str) -> None:
    s = get_settings()
    if len(password) < s.password_min_length:
        raise PasswordTooWeak(
            f"password must be at least {s.password_min_length} characters"
        )
    classes_present = sum(1 for pat in _CLASS_PATTERNS.values() if pat.search(password))
    if classes_present < 3:
        raise PasswordTooWeak(
            "password must include at least three of: "
            "lowercase, uppercase, digit, symbol"
        )


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


async def verify_password(password: str, hashed: str) -> bool:
    return await asyncio.to_thread(
        bcrypt.checkpw,
        password.encode("utf-8"),
        hashed.encode("utf-8"),
    )
