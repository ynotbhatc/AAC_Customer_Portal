---
description: Curl a portal URL and verify every security header configured in frontend/nginx.conf is actually being applied by the running nginx. Run after editing nginx.conf or to verify a deploy.
allowed-tools: Bash(curl *)
argument-hint: "<url>"
---

Verify that nginx is actually emitting every security header `frontend/nginx.conf` configures.

## What it checks

| Header | Configured value (in nginx.conf) | Status |
|---|---|---|
| `X-Frame-Options` | `DENY` | Present + matches |
| `X-Content-Type-Options` | `nosniff` | Present + matches |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Present + max-age ≥ 31536000 |
| `Content-Security-Policy` | configured directives | Present + non-empty |
| `Referrer-Policy` | (optional) | Reported as info only |

Missing headers are NO-GO. Mismatched values are NO-GO. Present + matches is GO.

## Steps

```bash
set -euo pipefail

URL="${1:?usage: /nginx-test-headers <url>}"

# Pull headers
headers=$(curl -sk -I --max-time 5 "$URL" || {
    echo "✗ Could not fetch $URL — is the portal reachable?" >&2
    exit 1
})

get_header() {
    echo "$headers" | grep -i "^$1:" | head -1 | sed -E "s/^[^:]+:[[:space:]]*//; s/\r$//"
}

check_present() {
    local name="$1" expected="$2"
    local actual=$(get_header "$name")
    if [ -z "$actual" ]; then
        printf "  %-30s NO-GO  (missing)\n" "$name"
        return 1
    fi
    if [ -n "$expected" ] && [ "$actual" != "$expected" ]; then
        printf "  %-30s NO-GO  (got: %s)\n" "$name" "$actual"
        printf "  %-30s        (want: %s)\n" "" "$expected"
        return 1
    fi
    printf "  %-30s GO     (%s)\n" "$name" "$actual"
    return 0
}

echo "▶ Checking security headers on $URL"
echo ""

all_green=true
check_present "X-Frame-Options"           "DENY"                                                    || all_green=false
check_present "X-Content-Type-Options"    "nosniff"                                                 || all_green=false
check_present "Strict-Transport-Security" "max-age=31536000; includeSubDomains"                     || all_green=false
check_present "Content-Security-Policy"   ""                                                        || all_green=false

# Referrer-Policy: present is good, missing is informational only
rp=$(get_header "Referrer-Policy")
if [ -n "$rp" ]; then
    printf "  %-30s GO     (%s)\n" "Referrer-Policy" "$rp"
else
    printf "  %-30s INFO   (not set — consider adding for additional privacy)\n" "Referrer-Policy"
fi

echo ""
if $all_green; then
    echo "✓ All required security headers present"
    exit 0
else
    echo "✗ At least one required header is missing or wrong — see above"
    echo "  Check frontend/nginx.conf and reload (nginx -t && nginx -s reload)"
    exit 1
fi
```

## Notes

- Uses `-sk` so it doesn't fail on self-signed certs in dev. Customer envs should use proper certs and this skill still works.
- CSP value isn't compared because it's a long string; just verifies it's set. Use `/nginx-csp-check` (proposed) for full CSP validation against the SPA contents.
