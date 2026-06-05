-- Migration 011 — Template library batch 2 (PR 8 of Piece 46)
--
-- Adds target_mappings rows for two more controls × all 4 target families:
--   session_timeout       × {linux, windows, kubernetes, network_device}
--   audit_log_retention   × {linux, windows, kubernetes, network_device}
--
-- Templates live under api/src/policy_ingestion/templates/<control>/<target>.rego.j2.
-- All 8 templates render + pass `opa check --v1-compatible` locally.
--
-- ON CONFLICT DO NOTHING — re-runs are no-ops. Compatible with operators
-- who may have added their own overrides via template_body.

BEGIN;

WITH ctrl AS (
    SELECT id, key FROM abstract_controls
     WHERE key IN ('session_timeout', 'audit_log_retention')
)
INSERT INTO target_mappings
    (abstract_control_id, target_system, target_subtype,
     template_engine, template_ref, input_contract_schema, quality_grade)
SELECT
    ctrl.id, m.target_system, NULL,
    'jinja2', format('%s/%s', ctrl.key, m.target_system),
    m.input_contract::jsonb, 'library_v1'
FROM ctrl,
(VALUES
    -- session_timeout
    ('session_timeout', 'linux',
        '{"type":"object","properties":{"shell":{"type":"object"},"sshd":{"type":"object"}}}'),
    ('session_timeout', 'windows',
        '{"type":"object","properties":{"secedit":{"type":"object"}}}'),
    ('session_timeout', 'kubernetes',
        '{"type":"object","properties":{"api_server":{"type":"object"}}}'),
    ('session_timeout', 'network_device',
        '{"type":"object","properties":{"running_config_lines":{"type":"array"}}}'),

    -- audit_log_retention
    ('audit_log_retention', 'linux',
        '{"type":"object","properties":{"auditd_conf":{"type":"object"},"auditd_retention_days_estimated":{"type":"integer"}}}'),
    ('audit_log_retention', 'windows',
        '{"type":"object","properties":{"event_log":{"type":"object"}}}'),
    ('audit_log_retention', 'kubernetes',
        '{"type":"object","properties":{"api_server":{"type":"object"}}}'),
    ('audit_log_retention', 'network_device',
        '{"type":"object","properties":{"running_config_lines":{"type":"array"}}}')
) AS m(control_key, target_system, input_contract)
WHERE ctrl.key = m.control_key
ON CONFLICT (abstract_control_id, target_system, target_subtype) DO NOTHING;

COMMIT;
