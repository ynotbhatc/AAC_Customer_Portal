"""Wrapper around the `opa` CLI binary.

We shell out to `opa check` because it is the canonical Rego type-checker
and matches what AAC's policy library uses. Wrapping the subprocess instead
of embedding a Go module keeps the dependency surface clean.

Honest about what `opa check` proves:
  - Syntax is valid Rego v1
  - Types check (e.g. you didn't try to add a string to a number)

What it does NOT prove:
  - The Rego semantically matches the IR / customer intent.
  - The Rego will return a useful answer on real input.

Intent validation is the human review screen's job (PR 8+); the
generator's job is to produce input that `opa check` accepts.

Subprocess invocation note: we use asyncio.create_subprocess_exec which
takes argv as a list and never spawns a shell — no command injection
risk even if rego_text contains shell metacharacters.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from typing import NamedTuple

from .config import get_settings


class OpaBinaryMissing(RuntimeError):
    """Routers translate to 503. opa not on PATH / not at configured path."""


class OpaVersionTooOld(RuntimeError):
    """opa is present but too old for Rego v1 syntax."""


class CheckResult(NamedTuple):
    """Output of `opa check`. `ok` is True iff opa returned exit 0."""
    ok: bool
    stdout: str
    stderr: str


_VERSION_RE = re.compile(r"Version:\s*(\d+)\.(\d+)\.(\d+)")
_verified: bool = False


async def assert_opa_available() -> None:
    """Raise if opa is missing or below the configured minimum version.

    Cached after the first successful call — the binary version doesn't
    change at runtime.
    """
    global _verified
    if _verified:
        return

    s = get_settings()
    path = shutil.which(s.opa_binary_path) or (
        s.opa_binary_path if os.path.isfile(s.opa_binary_path) else None
    )
    if path is None:
        raise OpaBinaryMissing(
            f"opa binary {s.opa_binary_path!r} not on PATH; "
            "install opa >= "
            f"{s.opa_min_version_major}.{s.opa_min_version_minor} in the EE / image"
        )

    proc = await asyncio.create_subprocess_exec(
        path,
        "version",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, _ = await proc.communicate()
    match = _VERSION_RE.search(stdout_b.decode("utf-8", errors="replace"))
    if match is None:
        raise OpaVersionTooOld(
            f"could not parse opa version from {stdout_b!r}"
        )
    major, minor, _ = (int(g) for g in match.groups())
    if (major, minor) < (s.opa_min_version_major, s.opa_min_version_minor):
        raise OpaVersionTooOld(
            f"opa {major}.{minor} < required "
            f"{s.opa_min_version_major}.{s.opa_min_version_minor}"
        )
    _verified = True


async def opa_check(*, rego_text: str) -> CheckResult:
    """Run `opa check` on a single Rego module.

    Writes to a temp file inside a dedicated tempdir (so opa's filename
    in error messages is predictable) and tears it down on exit.
    """
    await assert_opa_available()
    s = get_settings()

    with tempfile.TemporaryDirectory(prefix="rego_check_") as td:
        rego_path = os.path.join(td, "policy.rego")
        with open(rego_path, "w", encoding="utf-8") as fh:
            fh.write(rego_text)

        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    s.opa_binary_path,
                    "check",
                    "--v1-compatible",
                    rego_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=s.opa_check_timeout_seconds,
            )
        except asyncio.TimeoutError:
            return CheckResult(ok=False, stdout="", stderr="opa check timed out")

        stdout_b, stderr_b = await proc.communicate()
        return CheckResult(
            ok=proc.returncode == 0,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
        )
