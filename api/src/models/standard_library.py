"""Pydantic models for browsing the standard policy library and forking."""
from uuid import UUID

from pydantic import BaseModel, Field


class StandardFileMeta(BaseModel):
    """One indexed Rego file from the library."""
    path: str = Field(
        ...,
        description="Relative path under the library root, posix slashes. "
        "Use this in subsequent /files/{path} calls and /fork bodies.",
    )
    bytes_size: int
    sha256: str
    package_name: str


class StandardFileContent(StandardFileMeta):
    rego_text: str


class LibraryStats(BaseModel):
    file_count: int
    category_count: int
    library_version: str


class ForkRequest(BaseModel):
    """Body for POST /portal/v1/me/policies/fork.

    framework_bucket is what the customer will see this policy under
    in their dashboard (e.g. 'cis_rhel9', 'iso27001', 'corporate').
    Often matches the directory the source file lives in but the
    customer can override — corporate overlays often re-categorize."""
    standard_library_path: str = Field(
        ...,
        description="Relative path of the source file to fork.",
    )
    framework_bucket: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=255)


class ForkResponse(BaseModel):
    customer_policy_id: UUID
    customer_policy_target_id: UUID
    parent_standard_ref: str
    parent_standard_version: str
    target_system: str  # inferred from path; "unknown" if no signal


class UpstreamDiff(BaseModel):
    """Returned by GET /policies/{id}/upstream-diff.

    Unified diff in standard `--- a/path` / `+++ b/path` format so
    any standard renderer in the UI can show it side-by-side."""
    customer_policy_id: UUID
    parent_standard_ref: str
    parent_standard_version: str
    current_upstream_sha256: str
    fork_sha256: str
    overlay_sha256: str
    upstream_changed_since_fork: bool
    unified_diff: str = Field(
        ...,
        description="Unified diff of customer overlay vs current upstream.",
    )
