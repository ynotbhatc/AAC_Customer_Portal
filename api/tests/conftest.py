"""Shared pytest fixtures + env setup for the portal API.

Pure-function tests don't need a DB or live LLM — they just need
the env vars that `core/config.py` reads at settings construction.
This conftest sets safe defaults so any test can `from src.core...`
import without crashing on missing PG_PASSWORD.
"""
from __future__ import annotations

import os
import sys

# Ensure `src/...` imports resolve when pytest is invoked from the api/ root.
_API_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _API_ROOT not in sys.path:
    sys.path.insert(0, _API_ROOT)

# Settings defaults — pytest-env is optional; this is the belt-and-
# suspenders path that works without it.
os.environ.setdefault("PG_PASSWORD", "test")
os.environ.setdefault("PORTAL_PG_PASSWORD", "test")
os.environ.setdefault("PORTAL_ADMIN_TOKEN", "test-admin-token")
