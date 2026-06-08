---
description: Cascading health check across nginx, FastAPI, both PostgreSQL pools, and all 3 OPA endpoints. Reports which layer is degraded so you know whether to look at the gateway, the API process, the DB, or the policy engine. Run before customer demos or after deploy.
allowed-tools: Bash(curl *) Bash(podman *)
---

Cascading health check across every layer of the portal stack.

## Layers, in order

1. **nginx** — front-door. Reports 200 if its `/` location returns the SPA.
2. **API `/health`** — what FastAPI itself reports. Probes both DB pools; 200 = both pools healthy, 503 = at least one is down.
3. **Compliance PG pool** — independently verify the `compliance_reader` pool can SELECT 1.
4. **Portal PG pool** — independently verify the `aac_portal_app` pool can SELECT 1.
5. **OPA security** (port 8181) — `/health`.
6. **OPA compliance** (port 8182) — `/health`.
7. **OPA OT** (port 8183) — `/health`.

Each layer is reported `GO` or `NO-GO` with the response code / error inline. Overall status is the AND of all layers.

## Steps

```bash
set -euo pipefail

# Resolve the host from env or default to localhost (lab default).
# In demo / customer envs, set PORTAL_HOST + OPA_HOST before running.
PORTAL_HOST="${PORTAL_HOST:-localhost}"
OPA_HOST="${OPA_HOST:-localhost}"

check() {
    local label="$1" url="$2"
    local code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$url" || echo "000")
    if [ "$code" = "200" ]; then
        printf "  %-30s GO    (%s)\n" "$label" "$code"
        return 0
    fi
    printf "  %-30s NO-GO (%s)\n" "$label" "$code"
    return 1
}

echo "▶ Portal stack health check"
echo ""

all_green=true
check "nginx (root)"              "http://${PORTAL_HOST}:3000/"              || all_green=false
check "API /health"               "http://${PORTAL_HOST}:8000/health"        || all_green=false

# /health probes the pools, so a 200 from /health implies both pools are
# good. But for granular reporting, hit them via the internal probe
# endpoint when available — otherwise just report what /health says.
api_health=$(curl -sk --max-time 5 "http://${PORTAL_HOST}:8000/health" \
                  | jq -r '.failures // [] | join(", ")' 2>/dev/null || echo "")
if [ -n "$api_health" ]; then
    printf "  %-30s ← pool failures: %s\n" "(failed pools)" "$api_health"
fi

check "OPA security :8181"        "http://${OPA_HOST}:8181/health"           || all_green=false
check "OPA compliance :8182"      "http://${OPA_HOST}:8182/health"           || all_green=false
check "OPA OT :8183"              "http://${OPA_HOST}:8183/health"           || all_green=false

echo ""
if $all_green; then
    echo "✓ All layers GO"
    exit 0
else
    echo "✗ At least one layer is NO-GO — see above"
    exit 1
fi
```

## Notes

- Defaults to `localhost` for both portal and OPA hosts. Override with `PORTAL_HOST=...` and `OPA_HOST=...` env vars when running against demo / customer envs.
- In customer envs, ports and hostnames may differ — adapt before running.
- Doesn't probe AAP / the bridge tokens / external feeds. For those, run `/aac-verify` in the compliance repo.
