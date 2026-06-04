# Portal API Tests

`pytest`-based unit + integration tests for the FastAPI backend.

## Running

```bash
# From api/ root:
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

## Layout

```
tests/
├── conftest.py                 # Shared fixtures + env setup
├── test_passwords.py           # core/passwords — bcrypt + strength
├── test_bundle_signer.py       # core/bundle_signer — ed25519 sign/verify
├── test_standard_library.py    # core/standard_library — filesystem index
├── test_semver.py              # routers/policies — version bump helper
└── README.md                   # (this file)
```

The first batch covers pure functions and library code with no DB
dependency. Future PRs will add:

- DB integration tests (via `testcontainers-postgres` or a fixture-
  managed dedicated DB)
- Router-level integration tests (via FastAPI `TestClient`)
- LLM mocking for the IR extractor + Rego generator paths

## macOS local development caveat

`pydantic-core` and `asyncpg` don't ship pre-built wheels for
arm64/macOS in the pinned versions; local `pip install` requires
a Rust toolchain + libpq. CI runs on Linux where wheels are
available. If you can't get the dev env on macOS, push and let CI
run the test suite — most pure-function tests can be exercised
locally with the targeted dependencies (e.g. `pip install pynacl`
+ `pytest`).
