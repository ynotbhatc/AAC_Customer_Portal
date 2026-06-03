from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # PostgreSQL — compliance_reader (read-only, customer compliance DB)
    pg_host: str = "192.168.4.62"
    pg_port: int = 5432
    pg_database: str = "compliance"
    pg_user: str = "compliance_reader"
    pg_password: str

    # PostgreSQL — portal's OWN database (tenants, cve_events, artifacts)
    # Defaults to the same host but a different DB.
    portal_pg_host: str = "192.168.4.62"
    portal_pg_port: int = 5432
    portal_pg_database: str = "aac_portal"
    portal_pg_user: str = "aac_portal_app"
    portal_pg_password: str = ""

    # AAP Controller
    aap_url: str = "https://192.168.4.62"
    aap_token: str = ""
    aap_verify_ssl: bool = False

    # OPA
    opa_security_url: str = "http://192.168.4.62:8181"
    opa_compliance_url: str = "http://192.168.4.62:8182"
    opa_ot_url: str = "http://192.168.4.62:8183"

    # Portal
    secret_key: str = "change-me-in-production"
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

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
