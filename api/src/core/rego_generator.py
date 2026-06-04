"""Hybrid Rego generator.

Two paths, picked per (abstract_control_key × target_system):

  Template path:
    target_mappings has a row with template_ref set → render the
    filesystem Jinja template under api/src/policy_ingestion/templates/.
    Output guaranteed to pass opa check (the template was vetted).
    confidence_score = 1.0.

  LLM-fallback path:
    No template row → ask the LLM to author Rego for the IR control
    against the target. Run opa check; on failure, one repair attempt
    feeding the validator stderr back. Bounded — 2 LLM calls max.
    confidence_score = None (requires human review).

For controls the IR marked freeform (abstract_control_key=null), or
for unmapped target systems, every target goes through LLM-fallback.
"""
from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any

import asyncpg
import jinja2

from .config import get_settings
from .llm_client import LlmClient, LlmError
from .rego_validator import (
    OpaBinaryMissing,
    OpaVersionTooOld,
    opa_check,
)


# ── Template loader ───────────────────────────────────────────────────


_TEMPLATES_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "policy_ingestion",
    "templates",
)

_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(_TEMPLATES_ROOT),
    autoescape=False,                # Rego is not HTML
    undefined=jinja2.StrictUndefined,  # explode loudly on missing vars
    keep_trailing_newline=True,
)


# ── Outputs ───────────────────────────────────────────────────────────


@dataclass
class GeneratedRego:
    """One target_system worth of Rego, plus metadata for the audit log."""
    target_system: str
    target_subtype: str | None
    rego_text: str
    generation_method: str        # 'template_mapped' | 'llm_fallback'
    confidence_score: float | None
    review_status: str            # 'pending' on success, 'rejected' on persistent opa-check failure
    opa_check_ok: bool
    opa_check_stderr: str         # populated on failure; empty on success
    llm_attempts: int             # 0 for templates, 1 or 2 for LLM
    model: str | None             # populated for LLM-generated only


# ── Tenant slug helper ────────────────────────────────────────────────


def _tenant_slug(tenant_id: str) -> str:
    """Rego package names allow [a-z0-9_]. Strip hyphens, prefix to
    avoid leading digit."""
    safe = re.sub(r"[^a-z0-9]", "_", tenant_id.lower())
    return f"t_{safe}"


# ── Public entrypoint ─────────────────────────────────────────────────


async def generate_targets(
    *,
    pool: asyncpg.Pool,
    tenant_id: str,
    policy_name: str,
    effective_date: str | None,
    ir_control: dict[str, Any],
    llm: LlmClient,
) -> list[GeneratedRego]:
    """Walk the IR control's applicability list, generate one Rego per
    target system.

    For each target:
      1. Look up target_mappings row for (abstract_control_key, target_system).
      2. If hit → render Jinja with the control's parameters.
      3. If miss → LLM-fallback (with one repair attempt on opa-check fail).
      4. Run opa check; populate review_status accordingly.
    """
    control_key = ir_control.get("abstract_control_key")
    parameters = ir_control.get("parameters") or {}
    applicability: list[str] = ir_control.get("applicability") or []
    source_quote = ir_control.get("source_quote", "")

    if not applicability:
        # Unspecified applicability = nothing to generate yet. The review
        # screen surfaces this so the user can pick targets manually.
        return []

    results: list[GeneratedRego] = []

    for target_system in applicability:
        mapping = await _lookup_mapping(pool, control_key, target_system) if control_key else None

        if mapping and mapping["template_ref"]:
            rego_text = _render_template(
                template_ref=mapping["template_ref"],
                tenant_id=tenant_id,
                policy_name=policy_name,
                effective_date=effective_date,
                parameters=parameters,
            )
            check = await opa_check(rego_text=rego_text)
            results.append(
                GeneratedRego(
                    target_system=target_system,
                    target_subtype=mapping["target_subtype"],
                    rego_text=rego_text,
                    generation_method="template_mapped",
                    confidence_score=1.0 if check.ok else 0.5,
                    review_status="pending" if check.ok else "rejected",
                    opa_check_ok=check.ok,
                    opa_check_stderr=check.stderr,
                    llm_attempts=0,
                    model=None,
                )
            )
            continue

        # LLM-fallback path.
        results.append(
            await _generate_via_llm(
                tenant_id=tenant_id,
                policy_name=policy_name,
                control_key=control_key,
                target_system=target_system,
                parameters=parameters,
                source_quote=source_quote,
                llm=llm,
            )
        )

    return results


# ── Template path ─────────────────────────────────────────────────────


def _render_template(
    *,
    template_ref: str,
    tenant_id: str,
    policy_name: str,
    effective_date: str | None,
    parameters: dict[str, Any],
) -> str:
    template_path = f"{template_ref}.rego.j2"
    template = _jinja_env.get_template(template_path)
    return template.render(
        tenant_id=tenant_id,
        tenant_slug=_tenant_slug(tenant_id),
        policy_name=policy_name,
        effective_date=effective_date,
        **parameters,
    )


# ── DB lookup ─────────────────────────────────────────────────────────


async def _lookup_mapping(
    pool: asyncpg.Pool,
    control_key: str,
    target_system: str,
) -> dict[str, Any] | None:
    row = await pool.fetchrow(
        """
        SELECT tm.template_engine, tm.template_ref, tm.template_body,
               tm.target_subtype
          FROM target_mappings tm
          JOIN abstract_controls ac ON ac.id = tm.abstract_control_id
         WHERE ac.key = $1
           AND tm.target_system = $2
           AND tm.quality_grade != 'deprecated'
         ORDER BY tm.quality_grade DESC
         LIMIT 1
        """,
        control_key,
        target_system,
    )
    return dict(row) if row else None


# ── LLM-fallback path ─────────────────────────────────────────────────


_LLM_SYSTEM_PROMPT = """You author OPA Rego v1 policies that enforce a
single control intent against a specific target system. You will be given:
  - the abstract control key (e.g. password_complexity, or null for freeform)
  - the target system label (e.g. linux, windows)
  - extracted parameters from the customer policy
  - the verbatim source quote from the policy document

Your output MUST be a single Rego v1 module that:
  - starts with `package customer.<tenant_slug>.<control>.<target>`
  - imports `rego.v1`
  - defines `default compliant := false`
  - emits `violations` as a set of strings
  - defines `compliant if count(violations) == 0`
  - exposes a `compliance_report` rule with at least
    {policy, control, target, compliant, violations} fields

Do not include narrative commentary outside the Rego text.
Do not include markdown fences."""


async def _generate_via_llm(
    *,
    tenant_id: str,
    policy_name: str,
    control_key: str | None,
    target_system: str,
    parameters: dict[str, Any],
    source_quote: str,
    llm: LlmClient,
) -> GeneratedRego:
    s = get_settings()

    user_msg = (
        f"tenant_slug:         {_tenant_slug(tenant_id)}\n"
        f"abstract_control_key: {control_key or 'null (freeform)'}\n"
        f"target_system:       {target_system}\n"
        f"parameters:          {parameters}\n"
        f"policy_name:         {policy_name}\n\n"
        f"<source_quote>\n{source_quote}\n</source_quote>"
    )

    rego_text = await _llm_one_shot(llm, _LLM_SYSTEM_PROMPT, user_msg)
    check = await opa_check(rego_text=rego_text)

    if check.ok:
        return GeneratedRego(
            target_system=target_system,
            target_subtype=None,
            rego_text=rego_text,
            generation_method="llm_fallback",
            confidence_score=None,
            review_status="pending",
            opa_check_ok=True,
            opa_check_stderr="",
            llm_attempts=1,
            model=s.anthropic_model,
        )

    # One repair attempt — bounded retry per advisor brief.
    if s.rego_llm_repair_attempts < 1:
        return GeneratedRego(
            target_system=target_system,
            target_subtype=None,
            rego_text=rego_text,
            generation_method="llm_fallback",
            confidence_score=None,
            review_status="rejected",
            opa_check_ok=False,
            opa_check_stderr=check.stderr,
            llm_attempts=1,
            model=s.anthropic_model,
        )

    repair_msg = (
        f"{user_msg}\n\n"
        f"Your previous attempt failed `opa check` with:\n"
        f"<opa_stderr>\n{check.stderr}\n</opa_stderr>\n\n"
        f"Your previous Rego was:\n"
        f"<previous_rego>\n{rego_text}\n</previous_rego>\n\n"
        f"Produce a corrected Rego module."
    )
    rego_text_v2 = await _llm_one_shot(llm, _LLM_SYSTEM_PROMPT, repair_msg)
    check_v2 = await opa_check(rego_text=rego_text_v2)

    return GeneratedRego(
        target_system=target_system,
        target_subtype=None,
        rego_text=rego_text_v2,
        generation_method="llm_fallback",
        confidence_score=None,
        review_status="pending" if check_v2.ok else "rejected",
        opa_check_ok=check_v2.ok,
        opa_check_stderr=check_v2.stderr if not check_v2.ok else "",
        llm_attempts=2,
        model=s.anthropic_model,
    )


async def _llm_one_shot(
    llm: LlmClient, system: str, user: str
) -> str:
    """Single Messages-API call asking for raw Rego in the tool result.

    Wraps the output in a tool to keep the response shape predictable.
    """
    s = get_settings()
    tool_schema = {
        "type": "object",
        "required": ["rego"],
        "properties": {
            "rego": {
                "type": "string",
                "description": "The complete Rego v1 module, no markdown fences.",
            }
        },
    }
    result = await llm.call_tool(
        system=system,
        user=user,
        tool_name="emit_rego_module",
        tool_description="Emit a complete Rego v1 module.",
        tool_input_schema=tool_schema,
        max_tokens=s.rego_generation_max_tokens,
        timeout_seconds=s.rego_generation_timeout_seconds,
    )
    rego_text = str(result.input.get("rego", "")).strip()
    if not rego_text:
        raise LlmError("LLM returned empty rego field")
    return rego_text
