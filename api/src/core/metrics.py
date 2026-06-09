"""Prometheus metrics for the portal API.

Two series, both essential for the alerting setup in
docs/security_roadmap.md ("Alerting on 5xx spike"):

- `portal_http_requests_total{method, route, status_code}` — counter.
  Drives request-rate and 4xx/5xx alerts. The `route` label is the
  FastAPI *template* (e.g. `/portal/v1/me/policies/{policy_id}`),
  not the rendered URL, so we don't blow up the cardinality with
  one series per UUID.

- `portal_http_request_duration_seconds{method, route}` — histogram
  with the default Prometheus buckets. The `_count` and `_sum`
  series let consumers compute mean; `_bucket` series support p50 /
  p95 / p99 via `histogram_quantile`.

Both metrics intentionally exclude `/metrics` itself and `/health`
from the recorded sample set — they would otherwise dominate the
counter with synthetic traffic from the scrape loop and the
container orchestrator's liveness probe.
"""
from __future__ import annotations

import time
from typing import Awaitable, Callable

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# Standalone registry — keeps the portal's metrics decoupled from the
# default registry, which is shared process-wide and can include
# default Python collectors we don't want exposed to operators.
REGISTRY = CollectorRegistry()


REQUESTS_TOTAL = Counter(
    "portal_http_requests_total",
    "Total HTTP requests served by the portal API.",
    ["method", "route", "status_code"],
    registry=REGISTRY,
)


REQUEST_DURATION_SECONDS = Histogram(
    "portal_http_request_duration_seconds",
    "HTTP request handling latency in seconds.",
    ["method", "route"],
    registry=REGISTRY,
)


# Paths excluded from instrumentation — they create high-frequency
# synthetic traffic (Prometheus scrapes / container liveness probes)
# that swamps real-traffic signal in the same series.
_EXCLUDED_PATHS = frozenset({"/metrics", "/health"})


def _route_template(request: Request) -> str:
    """Return the FastAPI route template, or `unmatched` if Starlette
    didn't resolve a route. We never use the raw URL — that would
    explode label cardinality (one series per UUID path segment).
    """
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return route.path
    return "unmatched"


class MetricsMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that records one Counter and one Histogram
    observation per non-excluded request. Catches exceptions so a
    handler crash is still counted with status_code=500.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path in _EXCLUDED_PATHS:
            return await call_next(request)

        method = request.method
        start = time.perf_counter()
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            # The handler chain raised before producing a response.
            # FastAPI's exception middleware will translate this to a
            # 500 downstream; record that status here too so dashboards
            # show real outages, not "missing data."
            elapsed = time.perf_counter() - start
            route = _route_template(request)
            REQUESTS_TOTAL.labels(method=method, route=route, status_code="500").inc()
            REQUEST_DURATION_SECONDS.labels(method=method, route=route).observe(elapsed)
            raise

        elapsed = time.perf_counter() - start
        route = _route_template(request)
        REQUESTS_TOTAL.labels(
            method=method, route=route, status_code=str(status_code)
        ).inc()
        REQUEST_DURATION_SECONDS.labels(method=method, route=route).observe(elapsed)
        return response


def metrics_response() -> Response:
    """Render the registry to Prometheus exposition format."""
    payload = generate_latest(REGISTRY)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)
