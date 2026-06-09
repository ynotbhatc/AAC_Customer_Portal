"""Pin the canonical audit-action taxonomy.

These tests guard the backend ↔ frontend contract for the strings
written into `policy_audit_log.action`. If a router adds a new
INSERT with an action literal, this test fails until the literal is
added to `AuditAction` (and to the frontend `AUDIT_ACTIONS` constant).
"""
from __future__ import annotations

import re
from pathlib import Path

from src.core.audit_actions import ALL_AUDIT_ACTIONS, AuditAction


# Captures the action literal in an INSERT INTO policy_audit_log VALUES
# clause when the third value position is a single-quoted token. Matches
# both old-style 'foo' and new-style {AuditAction.FOO.value} f-strings,
# because we want to assert the f-string form across the codebase.
_LITERAL_INSERT_PATTERN = re.compile(
    r"INSERT\s+INTO\s+policy_audit_log[^;]*?VALUES\s*\(.*?'([a-z_]+)'",
    re.DOTALL | re.IGNORECASE,
)


def _router_files() -> list[Path]:
    root = Path(__file__).resolve().parent.parent / "src" / "routers"
    return sorted(root.glob("*.py"))


def test_enum_lists_only_unique_values():
    """No duplicate action strings — Enum already enforces this, but the
    test makes the invariant visible in case the data model changes."""
    values = [a.value for a in list(AuditAction)]
    assert len(values) == len(set(values))


def test_enum_values_are_snake_case():
    """Strings stored on disk should follow the project convention."""
    for a in list(AuditAction):
        assert re.fullmatch(r"[a-z][a-z0-9_]*", a.value), (
            f"AuditAction.{a.name} value {a.value!r} is not snake_case"
        )


def test_no_inline_audit_action_literals_remain_in_routers():
    """Every `INSERT INTO policy_audit_log ... 'literal'` site should now
    use `{AuditAction.X.value}` (i.e. emit the literal through the enum,
    not from a hardcoded string). This catches future regressions where
    a router silently re-introduces an inline string."""
    offenders: list[tuple[str, str]] = []
    for path in _router_files():
        text = path.read_text()
        for match in _LITERAL_INSERT_PATTERN.finditer(text):
            # The f-string form embeds the literal at runtime as
            # `'uploaded'`, so it WILL still match the regex against the
            # rendered file content — BUT only when the file is compiled
            # and run. As source, the f-string contains the curly-brace
            # placeholder before the quote. Static text contains the bare
            # quoted literal.
            literal = match.group(1)
            # If the curly-brace expression precedes the literal, this is
            # an f-string and OK. Otherwise it's a raw inline literal.
            preceding = text[max(0, match.start()) : match.end()]
            if "{AuditAction." in preceding:
                continue
            offenders.append((path.name, literal))
    assert offenders == [], (
        "Inline audit-action literals must use AuditAction enum: "
        + ", ".join(f"{f}:{lit}" for f, lit in offenders)
    )


def test_enum_membership_matches_public_set():
    """ALL_AUDIT_ACTIONS is a documented public surface; it must equal
    the enum value set, so consumers (tests, validators) can rely on it."""
    assert ALL_AUDIT_ACTIONS == frozenset(a.value for a in list(AuditAction))
