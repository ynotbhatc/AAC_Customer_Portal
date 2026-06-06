from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # PostgreSQL — compliance_reader (read-only, customer compliance DB).
    # Hosts default to localhost to avoid silently connecting to a
    # specific production environment if the operator forgets to set
    # env vars. Passwords have no default — Pydantic raises at startup
    # if PG_PASSWORD / PORTAL_PG_PASSWORD aren't set.
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_database: str = "compliance"
    pg_user: str = "compliance_reader"
    pg_password: str

    # PostgreSQL — portal's OWN database (tenants, cve_events, artifacts).
    portal_pg_host: str = "localhost"
    portal_pg_port: int = 5432
    portal_pg_database: str = "aac_portal"
    portal_pg_user: str = "aac_portal_app"
    portal_pg_password: str

    # AAP Controller. verify_ssl defaults to True; operators who really
    # need to talk to a self-signed AAP must opt out explicitly with
    # AAP_VERIFY_SSL=false.
    aap_url: str = ""
    aap_token: str = ""
    aap_verify_ssl: bool = True

    # OPA. Localhost defaults so a missing env var is obviously wrong
    # rather than silently hitting production.
    opa_security_url: str = "http://localhost:8181"
    opa_compliance_url: str = "http://localhost:8182"
    opa_ot_url: str = "http://localhost:8183"

    # Portal. secret_key has no default — Pydantic raises if SECRET_KEY
    # is unset, so the app can't start signed with a well-known key.
    secret_key: str
    allowed_origins: list[str] = ["http://localhost:3000"]
    debug: bool = False

    # Operator-admin bearer token (gates tenant/token admin endpoints)
    portal_admin_token: str = ""

    # Tenant-user session policy
    session_lifetime_hours: int = 12          # session expires after this
    password_reset_lifetime_hours: int = 24   # reset link valid window
    password_min_length: int = 12

    # Policy document upload limits (Phase 2 — Path A ingestion)
    max_upload_bytes: int = 15 * 1024 * 1024  # 15 MiB
    parser_timeout_seconds: int = 30

    # LLM IR extraction (Phase 2 — Path A)
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"
    ir_extraction_max_input_chars: int = 50_000   # 413 above this
    ir_extraction_max_tokens: int = 4096
    ir_extraction_timeout_seconds: int = 90
    ir_schema_version: str = "v1"

    # Rego generation (Phase 2 — Path A finish)
    opa_binary_path: str = "opa"            # name or absolute path
    opa_min_version_major: int = 0
    opa_min_version_minor: int = 60         # require >= 0.60 (Rego v1 syntax)
    opa_check_timeout_seconds: int = 15
    rego_generation_max_tokens: int = 2048
    rego_generation_timeout_seconds: int = 60
    rego_llm_repair_attempts: int = 1       # 1 initial + 1 repair = 2 calls max

    # Bundle delivery (PR 9 — publish + signed tarball)
    bundle_signing_key_path: str = ""       # path to ed25519 PEM (32-byte seed)
    bundle_signing_key_id: str = "portal-mvp-2026-06"  # rotated in operator playbook
    opa_build_timeout_seconds: int = 60

    # Path B — standard library fork-and-tweak (PR 10)
    standard_library_path: str = "/standard-library"
    # Frozen at portal container build time (git short SHA of the
    # rego_policy_libraries pin). Used as parent_standard_version
    # when a customer forks a file so upstream-diff can identify
    # which baseline they branched from.
    standard_library_version: str = "unset"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
