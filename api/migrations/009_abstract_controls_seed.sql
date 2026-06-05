-- Migration 009 — Seed the abstract_controls library (PR 6 of Piece 46)
--
-- Phase 2 starter set: 10 abstract controls across 4 domains. These are
-- the keys the LLM IR extractor (PR 6) is allowed to emit. PR 7's
-- hybrid Rego generator picks the Jinja template for each (control × target)
-- mapping; without these rows, every IR would have null control keys and
-- PR 7 would fall through to LLM-only generation 100% of the time.
--
-- Adding a control later is a one-row INSERT (and a target_mappings entry
-- per target system) — no schema change. New controls are additive.
--
-- parameters_schema is a hint for the review UI and the optional generator-
-- side validation in PR 7; PR 6 does not enforce it.
--
-- ON CONFLICT DO NOTHING — re-running the migration is a no-op even if
-- the operator has added their own custom keys.

BEGIN;

INSERT INTO abstract_controls (key, display_name, description, domain, parameters_schema) VALUES
    (
        'password_complexity',
        'Password complexity requirements',
        'Minimum length, character classes, and forbidden patterns for user passwords.',
        'authentication',
        '{
          "type": "object",
          "properties": {
            "min_length":              {"type": "integer", "minimum": 1},
            "require_lowercase":       {"type": "boolean"},
            "require_uppercase":       {"type": "boolean"},
            "require_digit":           {"type": "boolean"},
            "require_symbol":          {"type": "boolean"},
            "min_character_classes":   {"type": "integer", "minimum": 1, "maximum": 4}
          }
        }'::jsonb
    ),
    (
        'password_rotation',
        'Password rotation policy',
        'How often passwords must change, and whether reuse of recent passwords is forbidden.',
        'authentication',
        '{
          "type": "object",
          "properties": {
            "max_age_days":             {"type": "integer", "minimum": 1},
            "min_age_days":             {"type": "integer", "minimum": 0},
            "history_remembered":       {"type": "integer", "minimum": 0}
          }
        }'::jsonb
    ),
    (
        'account_lockout',
        'Account lockout on failed authentication',
        'Number of failed attempts before lockout and the lockout duration.',
        'authentication',
        '{
          "type": "object",
          "properties": {
            "failed_attempts_threshold": {"type": "integer", "minimum": 1},
            "lockout_duration_minutes":  {"type": "integer", "minimum": 1},
            "reset_window_minutes":      {"type": "integer", "minimum": 1}
          }
        }'::jsonb
    ),
    (
        'mfa_enforcement',
        'Multi-factor authentication enforcement',
        'Which users / roles / interactive sessions must complete a second factor.',
        'authentication',
        '{
          "type": "object",
          "properties": {
            "required_for_roles":       {"type": "array", "items": {"type": "string"}},
            "required_for_remote":      {"type": "boolean"},
            "permitted_factor_types":   {"type": "array", "items": {"type": "string"}}
          }
        }'::jsonb
    ),
    (
        'session_timeout',
        'Idle session timeout',
        'How long a session may remain idle before automatic logout / re-authentication.',
        'authentication',
        '{
          "type": "object",
          "properties": {
            "idle_timeout_minutes":     {"type": "integer", "minimum": 1},
            "absolute_timeout_minutes": {"type": "integer", "minimum": 1}
          }
        }'::jsonb
    ),
    (
        'ssh_hardening',
        'SSH server hardening',
        'SSH configuration for inbound administrative access — protocol version, root login, key vs password.',
        'network',
        '{
          "type": "object",
          "properties": {
            "permit_root_login":        {"type": "string", "enum": ["yes", "no", "prohibit-password"]},
            "password_authentication":  {"type": "boolean"},
            "permit_empty_passwords":   {"type": "boolean"},
            "protocol_version":         {"type": "integer", "enum": [2]}
          }
        }'::jsonb
    ),
    (
        'audit_log_retention',
        'Audit log retention period',
        'Minimum time security audit logs must be preserved for forensic review.',
        'audit',
        '{
          "type": "object",
          "properties": {
            "retention_days":           {"type": "integer", "minimum": 1}
          }
        }'::jsonb
    ),
    (
        'audit_log_protection',
        'Audit log integrity + immutability',
        'Restrictions on who can read / modify / delete audit logs, and forwarding to a central collector.',
        'audit',
        '{
          "type": "object",
          "properties": {
            "immutable":                {"type": "boolean"},
            "forward_to_central":       {"type": "boolean"},
            "restricted_to_role":       {"type": "string"}
          }
        }'::jsonb
    ),
    (
        'encryption_at_rest',
        'Encryption at rest',
        'Disk-level / volume-level encryption requirements for stored data.',
        'cryptography',
        '{
          "type": "object",
          "properties": {
            "algorithm":                {"type": "string"},
            "fips_validated":           {"type": "boolean"},
            "key_rotation_days":        {"type": "integer", "minimum": 1}
          }
        }'::jsonb
    ),
    (
        'network_segmentation',
        'Network segmentation / firewall posture',
        'Default-deny firewall posture, segment isolation, and allowed inter-segment flows.',
        'network',
        '{
          "type": "object",
          "properties": {
            "default_action":           {"type": "string", "enum": ["deny", "allow"]},
            "permitted_inbound_ports":  {"type": "array", "items": {"type": "integer"}},
            "permitted_outbound_ports": {"type": "array", "items": {"type": "integer"}}
          }
        }'::jsonb
    )
ON CONFLICT (key) DO NOTHING;

COMMIT;
