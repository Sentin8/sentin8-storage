-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Storage — object storage service.
-- Sentin8:Storage stores WASM binaries (Sentin8:Func), statements (Bank8:Ledger), and other large
-- binary payloads. It does not currently own any PostgreSQL tables — all
-- object metadata lives in the owning service's tables (e.g. sentin8_func_modules,
-- bank8_ledger_statements) and the binary content is referenced by sentin8_storage_path /
-- storage object key.
--
-- This file is intentionally empty of table definitions. It exists so the
-- init directory has a stable one-file-per-service layout ordered by the
-- master plan. If Sentin8:Storage later needs persistent metadata (e.g. bucket
-- registry, multipart upload state), add it here.


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: storage.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("storage").
CREATE TABLE IF NOT EXISTS storage.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_storage_outbox_unrelayed
    ON storage.outbox (created_at) WHERE relayed = false;
ALTER TABLE storage.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON storage.outbox;
CREATE POLICY outbox_select ON storage.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON storage.outbox;
CREATE POLICY outbox_insert ON storage.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON storage.outbox;
CREATE POLICY outbox_update ON storage.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION storage.storage_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('storage_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON storage.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON storage.outbox
    FOR EACH ROW
    EXECUTE FUNCTION storage.storage_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("storage").
CREATE TABLE IF NOT EXISTS storage.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_storage_audit_journal_unpushed
    ON storage.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE storage.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON storage.audit_journal;
CREATE POLICY audit_journal_dml ON storage.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned — the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA storage TO sentin8_storage_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.outbox TO sentin8_storage_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA storage TO sentin8_storage_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.audit_journal TO sentin8_storage_service;
