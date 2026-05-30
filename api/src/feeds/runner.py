"""
CLI + programmatic runner for the feed adapters.

CLI:
    python -m src.feeds.runner nvd --lookback-days 2
    python -m src.feeds.runner cisa_kev
    python -m src.feeds.runner all

Programmatic:
    from src.feeds.runner import run
    summary = await run('nvd', lookback_days=2)
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from datetime import timedelta

from ..core.portal_db import close_portal_pool, get_portal_pool
from . import cisa_kev, classifier, nvd
from .common import utcnow

ADAPTERS = {
    "nvd": nvd.ingest,
    "cisa_kev": cisa_kev.ingest,
}


async def run(source: str, *, classify: bool = True, **kwargs: Any) -> dict:
    if source not in ADAPTERS:
        raise ValueError(f"unknown source '{source}' — known: {list(ADAPTERS)}")
    pool = await get_portal_pool()
    feed_result = await ADAPTERS[source](pool, **kwargs)
    if classify and feed_result.get("status") == "success":
        # Classify everything modified during this pull window (+ small slack).
        since = utcnow() - timedelta(hours=1)
        feed_result["classify"] = await classifier.classify_recent(pool, since=since)
    return feed_result


async def run_all(*, classify: bool = True, **kwargs: Any) -> dict[str, dict]:
    pool = await get_portal_pool()
    out: dict[str, dict] = {}
    for name, fn in ADAPTERS.items():
        adapter_kwargs = {k: v for k, v in kwargs.items() if k in fn.__code__.co_varnames}
        out[name] = await fn(pool, **adapter_kwargs)
    if classify and any(r.get("status") == "success" for r in out.values()):
        since = utcnow() - timedelta(hours=1)
        out["classify"] = await classifier.classify_recent(pool, since=since)
    return out


async def _main() -> int:
    parser = argparse.ArgumentParser(description="Run portal CVE feed adapters")
    parser.add_argument("source", choices=[*ADAPTERS.keys(), "all", "classify"])
    parser.add_argument("--lookback-days", type=int, default=2,
                        help="(nvd) days back from latest cursor when no prior run")
    parser.add_argument("--no-classify", action="store_true",
                        help="skip the classifier pass after feed pull")
    parser.add_argument("--full-rebuild", action="store_true",
                        help="(classify) re-tag every cve_events row")
    args = parser.parse_args()

    try:
        if args.source == "classify":
            pool = await get_portal_pool()
            result = await classifier.classify_recent(
                pool, full_rebuild=args.full_rebuild,
            )
        elif args.source == "all":
            result = await run_all(
                lookback_days=args.lookback_days,
                classify=not args.no_classify,
            )
        else:
            kwargs = {"classify": not args.no_classify}
            if args.source == "nvd":
                kwargs["lookback_days"] = args.lookback_days
            result = await run(args.source, **kwargs)
    finally:
        await close_portal_pool()

    import json
    print(json.dumps(result, indent=2, default=str))
    return 0 if (
        (isinstance(result, dict) and result.get("status") == "success")
        or (isinstance(result, dict) and all(v.get("status") == "success" for v in result.values()))
    ) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
