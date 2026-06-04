"""Filesystem index over the operator-shipped Rego policy library.

The portal container bundles a frozen snapshot of rego_policy_libraries
at build time (Containerfile `git clone --depth 1 ...`). This module:

  - walks the snapshot once at startup and builds an in-memory tree
  - exposes browse helpers (categories, files in a path, file content)
  - validates fork-target paths against the index to prevent directory
    traversal escapes via crafted request bodies

The standard library is READ-ONLY from the portal's perspective.
Customer overlays + edits go through customer_policy_targets, not
back into this tree.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import get_settings


class LibraryNotConfigured(RuntimeError):
    """Raised when standard_library_path is unset or points at a
    non-existent directory. Routers translate to 503."""


class FileNotInLibrary(ValueError):
    """Crafted path that escapes the library root, OR a path that
    exists in the filesystem but the indexer skipped (non-Rego)."""


@dataclass(frozen=True)
class StandardFile:
    """One indexed Rego policy file."""
    path: str          # relative to the library root, posix slashes
    bytes_size: int
    sha256: str
    package_name: str  # extracted from the file's `package …` header


_index: dict[str, StandardFile] | None = None
_categories: list[str] | None = None


def _ensure_loaded() -> tuple[dict[str, StandardFile], list[str]]:
    global _index, _categories
    if _index is not None and _categories is not None:
        return _index, _categories

    s = get_settings()
    if not s.standard_library_path:
        raise LibraryNotConfigured("standard_library_path is empty")
    root = Path(s.standard_library_path)
    if not root.is_dir():
        raise LibraryNotConfigured(
            f"standard_library_path={s.standard_library_path!r} is not a directory"
        )

    idx: dict[str, StandardFile] = {}
    for rego_path in root.rglob("*.rego"):
        rel = rego_path.relative_to(root).as_posix()
        data = rego_path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()

        package = ""
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("package "):
                package = line.split("package ", 1)[1].split(maxsplit=1)[0]
                break

        idx[rel] = StandardFile(
            path=rel, bytes_size=len(data), sha256=sha, package_name=package
        )

    # Top-level directories that contain at least one Rego file. Used by
    # the "browse categories" endpoint.
    cats = sorted({p.split("/", 1)[0] for p in idx.keys()})

    _index = idx
    _categories = cats
    return idx, cats


def categories() -> list[str]:
    _, cats = _ensure_loaded()
    return list(cats)


def list_files(prefix: str | None = None) -> list[StandardFile]:
    """Return all indexed files whose relative path starts with `prefix`
    (no trailing slash needed). Sorted by path."""
    idx, _ = _ensure_loaded()
    if prefix:
        norm = prefix.rstrip("/") + "/"
        out = [f for p, f in idx.items() if p.startswith(norm)]
    else:
        out = list(idx.values())
    out.sort(key=lambda f: f.path)
    return out


def get_file(path: str) -> tuple[StandardFile, str]:
    """Return (metadata, file_contents). Rejects paths not in the
    pre-built index, which prevents directory traversal."""
    idx, _ = _ensure_loaded()
    meta = idx.get(path)
    if meta is None:
        raise FileNotInLibrary(f"{path!r} not in standard library index")
    s = get_settings()
    full = os.path.join(s.standard_library_path, path)
    with open(full, "r", encoding="utf-8") as fh:
        return meta, fh.read()


def stats() -> dict[str, Any]:
    idx, cats = _ensure_loaded()
    return {
        "file_count": len(idx),
        "category_count": len(cats),
        "library_version": get_settings().standard_library_version,
    }
