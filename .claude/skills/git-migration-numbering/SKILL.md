---
description: Pre-commit check for migration files. Warns if a new migration file isn't strictly N+1 of the prior numbered migration, and refuses (printable warning) if a committed migration is being edited (migrations are append-only — must add new file instead). Run before committing changes to api/migrations/.
allowed-tools: Bash(git *) Bash(ls *)
---

Check that migration changes follow the append-only numbered-file convention.

## Why this is a skill

`api/migrations/` is the source of truth for the portal's DB schema. Two rules:

1. **Numbered strictly sequentially** — `014_x.sql` requires `013_*.sql` to exist; `015_x.sql` can't skip `014`. Apply order matters; gaps break it.
2. **Once committed, NEVER edit** — every env replays migrations from scratch. Editing a merged migration would mean the production DB has the old version and the dev DB has the new version. Always add a new migration.

This skill catches both at shift-left time before the commit lands.

## Steps

```bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
MIG_DIR="$REPO_ROOT/api/migrations"

if [ ! -d "$MIG_DIR" ]; then
    echo "  (no api/migrations/ directory — skipping check)"
    exit 0
fi

# 1. Anyone editing a previously-merged migration?
modified=$(git diff --cached --name-only -- "$MIG_DIR" | grep -E "^api/migrations/[0-9]+_.*\.sql$" || true)
if [ -n "$modified" ]; then
    # Edits to NEW files are fine (the file didn't exist on main).
    # Edits to files that exist on origin/main are not.
    illegal=""
    for f in $modified; do
        if git cat-file -e "origin/main:$f" 2>/dev/null; then
            illegal+="$f
"
        fi
    done
    if [ -n "$illegal" ]; then
        echo "✗ Editing a previously-committed migration is forbidden:"
        echo "$illegal" | sed 's/^/    /'
        echo ""
        echo "  Migrations are append-only. Add a new migration file instead."
        echo "  Pick the next number after the highest existing migration:"
        next=$(ls "$MIG_DIR"/[0-9]*_*.sql 2>/dev/null \
                 | xargs -n1 basename \
                 | sed -E 's/^([0-9]+).*/\1/' \
                 | sort -n \
                 | tail -1)
        next=$((10#${next:-0} + 1))
        printf "    %03d_<descriptive_name>.sql\n" "$next"
        exit 1
    fi
fi

# 2. Are added files strictly sequential?
added=$(git diff --cached --name-only --diff-filter=A -- "$MIG_DIR" | grep -E "^api/migrations/[0-9]+_.*\.sql$" || true)
if [ -n "$added" ]; then
    # Highest existing number on disk (including new files about to be committed)
    highest=$(ls "$MIG_DIR"/[0-9]*_*.sql 2>/dev/null \
                | xargs -n1 basename \
                | sed -E 's/^([0-9]+).*/\1/' \
                | sort -n \
                | tail -1)
    # Highest on origin/main
    highest_main=$(git ls-tree -r origin/main api/migrations/ 2>/dev/null \
                | grep -E "[0-9]+_.*\.sql$" \
                | awk '{print $NF}' \
                | xargs -I{} basename {} \
                | sed -E 's/^([0-9]+).*/\1/' \
                | sort -n \
                | tail -1)
    expected_next=$((10#${highest_main:-0} + 1))

    for f in $added; do
        num=$(basename "$f" | sed -E 's/^([0-9]+).*/\1/')
        if [ "$((10#$num))" -ne "$expected_next" ]; then
            echo "✗ Migration $f is numbered $num but the next sequential number is $expected_next"
            printf "  Rename to %03d_<name>.sql\n" "$expected_next"
            exit 1
        fi
        expected_next=$((expected_next + 1))
    done
fi

echo "✓ Migration changes follow the numbering + append-only rules"
```

## Notes

- The "previously committed" check uses `origin/main` — make sure your local main is fetched. The skill works against fetched state, not on-disk state of someone else's branch.
- The number-detection regex `^[0-9]+_` matches the established `NNN_descriptive_name.sql` pattern. Files that don't match (legacy / non-numbered) are ignored.
