-- Migration 010 — Target-mapping schema tweak + password_complexity templates
--
-- Two parts:
--
-- 1. Schema: make target_mappings.template_body nullable and add
--    template_ref (filesystem-slug pointer). Library-shipped templates
--    live as tracked files under api/src/policy_ingestion/templates/
--    and the row references them via template_ref. The template_body
--    column survives for the operator-uploaded-override case (customers
--    or implementers who want to pin a custom Rego template for a
--    (control × target) pair without redeploying the API).
--
-- 2. Seed: four (password_complexity × target) rows. Phase 2 of the
--    library — proves the end-to-end path; PR 8 expands to the
--    remaining 9 controls.
--
-- Templates referenced by these rows:
--   api/src/policy_ingestion/templates/password_complexity/linux.rego.j2
--   api/src/policy_ingestion/templates/password_complexity/windows.rego.j2
--   api/src/policy_ingestion/templates/password_complexity/kubernetes.rego.j2
--   api/src/policy_ingestion/templates/password_complexity/network_device.rego.j2

BEGIN;

-- Schema tweak — additive + nullability relax. Both safe to re-apply.
ALTER TABLE target_mappings
    ALTER COLUMN template_body DROP NOT NULL;

ALTER TABLE target_mappings
    ADD COLUMN IF NOT EXISTS template_ref text;

-- Generator contract: exactly one of (template_ref, template_body) must
-- be set. Enforced as a CHECK so a row with both NULL or both populated
-- is rejected at write time. UPDATEs after this point have to respect it.
ALTER TABLE target_mappings
    DROP CONSTRAINT IF EXISTS target_mappings_template_source_chk;

ALTER TABLE target_mappings
    ADD CONSTRAINT target_mappings_template_source_chk
    CHECK ((template_ref IS NOT NULL) <> (template_body IS NOT NULL));


-- Seed: password_complexity × {linux, windows, kubernetes, network_device}.
-- ON CONFLICT (abstract_control_id, target_system, target_subtype) DO NOTHING
-- so re-runs are no-ops.
WITH ctrl AS (
    SELECT id FROM abstract_controls WHERE key = 'password_complexity'
)
INSERT INTO target_mappings
    (abstract_control_id, target_system, target_subtype,
     template_engine, template_ref, input_contract_schema, quality_grade)
SELECT
    ctrl.id, t.target_system, NULL,
    'jinja2', t.template_ref, t.input_contract::jsonb, 'library_v1'
FROM ctrl,
(VALUES
    (
        'linux',
        'password_complexity/linux',
        '{
          "type": "object",
          "properties": {
            "pam_pwquality_conf": {"type": "object"}
          }
        }'
    ),
    (
        'windows',
        'password_complexity/windows',
        '{
          "type": "object",
          "properties": {
            "secedit": {"type": "object"}
          }
        }'
    ),
    (
        'kubernetes',
        'password_complexity/kubernetes',
        '{
          "type": "object",
          "properties": {
            "psa_labels": {"type": "object"}
          }
        }'
    ),
    (
        'network_device',
        'password_complexity/network_device',
        '{
          "type": "object",
          "properties": {
            "running_config_lines": {"type": "array"}
          }
        }'
    )
) AS t(target_system, template_ref, input_contract)
ON CONFLICT (abstract_control_id, target_system, target_subtype) DO NOTHING;

COMMIT;
