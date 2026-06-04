"""Semver helpers — split out so unit tests can import without
dragging the full router dependency tree."""
from __future__ import annotations

import re

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def bump_patch(version_semver: str) -> str | None:
    """Bump the patch component of a `vMAJ.MIN.PATCH` string.

    Preserves the leading `v` if present. Returns None if the input
    doesn't parse — the caller decides whether to require explicit
    new_version input or 400 the request."""
    match = _SEMVER_RE.match(version_semver.strip())
    if not match:
        return None
    major, minor, patch = (int(g) for g in match.groups())
    prefix = "v" if version_semver.lstrip().startswith("v") else ""
    return f"{prefix}{major}.{minor}.{patch + 1}"
