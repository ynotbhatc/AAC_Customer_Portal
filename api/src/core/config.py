from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # PostgreSQL — compliance_reader (read-only)
    pg_host: str = "192.168.4.62"
    pg_port: int = 5432
    pg_database: str = "compliance"
    pg_user: str = "compliance_reader"
    pg_password: str

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

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
