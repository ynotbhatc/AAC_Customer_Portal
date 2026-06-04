"""Tests for core/standard_library — the filesystem indexer +
path-traversal protection that Path B's fork endpoint depends on.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """get_settings is lru_cached; monkeypatch.setenv won't take effect
    unless the cache is invalidated each test."""
    from src.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def fake_library(tmp_path: Path, monkeypatch) -> Path:
    """Build a small standard library in a tempdir with three .rego
    files across two top-level categories. Point the settings at it
    and reset the module cache so each test sees a clean index."""
    root = tmp_path / "standard-library"
    (root / "benchmarks" / "cis" / "rhel_9").mkdir(parents=True)
    (root / "frameworks" / "iso27001").mkdir(parents=True)

    (root / "benchmarks" / "cis" / "rhel_9" / "pam.rego").write_text(
        "package cis_rhel9.pam\nimport rego.v1\n"
    )
    (root / "benchmarks" / "cis" / "rhel_9" / "ssh.rego").write_text(
        "package cis_rhel9.ssh\nimport rego.v1\n"
    )
    (root / "frameworks" / "iso27001" / "iso.rego").write_text(
        "package iso27001\nimport rego.v1\n"
    )
    # A non-.rego file to confirm the indexer skips it.
    (root / "README.md").write_text("not a policy")

    monkeypatch.setenv("STANDARD_LIBRARY_PATH", str(root))
    monkeypatch.setenv("STANDARD_LIBRARY_VERSION", "test-abc123")

    # Reset the module cache so the test owns the indexer load.
    import src.core.standard_library as sl
    sl._index = None
    sl._categories = None
    return root


def test_categories(fake_library: Path) -> None:
    from src.core.standard_library import categories
    assert categories() == ["benchmarks", "frameworks"]


def test_list_files_all(fake_library: Path) -> None:
    from src.core.standard_library import list_files
    files = list_files()
    paths = [f.path for f in files]
    assert paths == [
        "benchmarks/cis/rhel_9/pam.rego",
        "benchmarks/cis/rhel_9/ssh.rego",
        "frameworks/iso27001/iso.rego",
    ]


def test_list_files_with_prefix(fake_library: Path) -> None:
    from src.core.standard_library import list_files
    files = list_files(prefix="benchmarks/cis")
    paths = [f.path for f in files]
    assert paths == [
        "benchmarks/cis/rhel_9/pam.rego",
        "benchmarks/cis/rhel_9/ssh.rego",
    ]


def test_list_files_prefix_no_match(fake_library: Path) -> None:
    from src.core.standard_library import list_files
    assert list_files(prefix="doesnt/exist") == []


def test_get_file_returns_content_and_meta(fake_library: Path) -> None:
    from src.core.standard_library import get_file
    meta, text = get_file("frameworks/iso27001/iso.rego")
    assert meta.path == "frameworks/iso27001/iso.rego"
    assert meta.package_name == "iso27001"
    assert text == "package iso27001\nimport rego.v1\n"
    expected_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert meta.sha256 == expected_sha


def test_get_file_rejects_unknown_path(fake_library: Path) -> None:
    """Path-traversal protection: requested path must be in the index,
    not just on disk. A crafted ../etc/passwd doesn't make it past
    this gate because the indexer never inserted such a key."""
    from src.core.standard_library import FileNotInLibrary, get_file
    with pytest.raises(FileNotInLibrary):
        get_file("../README.md")


def test_get_file_rejects_non_rego_in_tree(fake_library: Path) -> None:
    """A .md file that exists in the library root must NOT be reachable
    via the index — the indexer only adds .rego."""
    from src.core.standard_library import FileNotInLibrary, get_file
    with pytest.raises(FileNotInLibrary):
        get_file("README.md")


def test_stats(fake_library: Path) -> None:
    from src.core.standard_library import stats
    s = stats()
    assert s["file_count"] == 3
    assert s["category_count"] == 2
    assert s["library_version"] == "test-abc123"


def test_library_not_configured(monkeypatch, tmp_path: Path) -> None:
    """Settings point at a path that doesn't exist."""
    monkeypatch.setenv("STANDARD_LIBRARY_PATH", str(tmp_path / "no_such_dir"))
    import src.core.standard_library as sl
    sl._index = None
    sl._categories = None
    from src.core.standard_library import LibraryNotConfigured, categories
    with pytest.raises(LibraryNotConfigured):
        categories()
