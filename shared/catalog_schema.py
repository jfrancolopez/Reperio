"""Initial SQLite catalog schema for Reperio control-plane state."""

from __future__ import annotations

import sqlite3
from pathlib import Path

INITIAL_SCHEMA_VERSION = 1

CANONICAL_TIMESTAMP_CHECK = """
length({column}) = 20
AND substr({column}, 5, 1) = '-'
AND substr({column}, 8, 1) = '-'
AND substr({column}, 11, 1) = 'T'
AND substr({column}, 14, 1) = ':'
AND substr({column}, 17, 1) = ':'
AND substr({column}, 20, 1) = 'Z'
"""


def connect_catalog(path: Path) -> sqlite3.Connection:
    """Open a catalog connection with required safety pragmas enabled."""

    connection = sqlite3.connect(path, isolation_level=None, timeout=30.0)
    configure_connection(connection)
    return connection


def configure_connection(connection: sqlite3.Connection) -> None:
    """Enable required SQLite behavior for every connection."""

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA busy_timeout = 30000")


def create_initial_schema(connection: sqlite3.Connection) -> None:
    """Create the first normalized catalog schema without running migrations."""

    configure_connection(connection)
    with connection:
        for statement in initial_schema_statements():
            connection.execute(statement)


def initial_schema_statements() -> tuple[str, ...]:
    """Return executable statements for the initial schema migration."""

    return tuple(statement.strip() for statement in _SCHEMA_SQL.split(";") if statement.strip())


def _timestamp_check(column: str) -> str:
    return CANONICAL_TIMESTAMP_CHECK.format(column=column)


_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    stable_identity TEXT NOT NULL UNIQUE,
    media_kind TEXT NOT NULL CHECK (media_kind IN ('block', 'optical', 'floppy', 'image')),
    label TEXT,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sector_size INTEGER NOT NULL CHECK (sector_size > 0),
    fingerprint_sha256 TEXT NOT NULL CHECK (length(fingerprint_sha256) = 64),
    status TEXT NOT NULL CHECK (status IN ('candidate', 'approved', 'scanning', 'retired')),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")}),
    updated_at TEXT NOT NULL CHECK ({_timestamp_check("updated_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS scan_cases (
    case_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('created', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    policy_json TEXT NOT NULL CHECK (json_valid(policy_json)),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")}),
    updated_at TEXT NOT NULL CHECK ({_timestamp_check("updated_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS volumes (
    volume_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
    parent_volume_id TEXT REFERENCES volumes(volume_id) ON DELETE RESTRICT,
    volume_kind TEXT NOT NULL CHECK (volume_kind IN ('partition', 'filesystem', 'archive', 'session')),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    offset_bytes INTEGER NOT NULL CHECK (offset_bytes >= 0),
    length_bytes INTEGER CHECK (length_bytes IS NULL OR length_bytes >= 0),
    filesystem TEXT,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    UNIQUE (source_id, volume_kind, ordinal)
) STRICT;

CREATE TABLE IF NOT EXISTS contents (
    content_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    storage_uri TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('present', 'partial', 'missing')),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")}),
    UNIQUE (source_id, content_sha256, size_bytes)
) STRICT;

CREATE TABLE IF NOT EXISTS entries (
    entry_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    volume_id TEXT REFERENCES volumes(volume_id) ON DELETE RESTRICT,
    content_id TEXT REFERENCES contents(content_id) ON DELETE SET NULL,
    parent_entry_id TEXT REFERENCES entries(entry_id) ON DELETE RESTRICT,
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('file', 'directory', 'deleted', 'carved', 'metadata')),
    path_bytes BLOB NOT NULL,
    display_path TEXT NOT NULL,
    name_bytes BLOB NOT NULL,
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    mtime TEXT CHECK (mtime IS NULL OR ({_timestamp_check("mtime")})),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    discovered_at TEXT NOT NULL CHECK ({_timestamp_check("discovered_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    entry_id TEXT REFERENCES entries(entry_id) ON DELETE SET NULL,
    content_id TEXT REFERENCES contents(content_id) ON DELETE SET NULL,
    finding_type TEXT NOT NULL CHECK (finding_type IN ('document', 'photo', 'video', 'archive', 'browser', 'wallet', 'credential', 'other')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('new', 'reviewed', 'dismissed', 'exported')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('metadata', 'signature', 'text', 'thumbnail', 'hash', 'audit')),
    content_id TEXT REFERENCES contents(content_id) ON DELETE SET NULL,
    data_json TEXT NOT NULL CHECK (json_valid(data_json)),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    job_type TEXT NOT NULL CHECK (job_type IN ('scan', 'enrich', 'export', 'notify', 'maintenance')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'running', 'paused', 'retrying', 'completed', 'completed-warning', 'failed', 'cancelled')),
    input_json TEXT NOT NULL CHECK (json_valid(input_json)),
    idempotency_key TEXT NOT NULL UNIQUE,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 1 CHECK (max_attempts >= 1),
    lease_owner TEXT,
    lease_expires_at TEXT CHECK (lease_expires_at IS NULL OR ({_timestamp_check("lease_expires_at")})),
    retry_after_at TEXT CHECK (retry_after_at IS NULL OR ({_timestamp_check("retry_after_at")})),
    error_json TEXT CHECK (error_json IS NULL OR json_valid(error_json)),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")}),
    updated_at TEXT NOT NULL CHECK ({_timestamp_check("updated_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    case_id TEXT REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    source_fingerprint TEXT NOT NULL CHECK (length(source_fingerprint) = 64),
    stage TEXT NOT NULL,
    checkpoint_version INTEGER NOT NULL CHECK (checkpoint_version > 0),
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    cursor_json TEXT NOT NULL CHECK (json_valid(cursor_json)),
    counters_json TEXT NOT NULL CHECK (json_valid(counters_json)),
    blob BLOB NOT NULL,
    integrity_sha256 TEXT NOT NULL CHECK (length(integrity_sha256) = 64),
    supersedes_checkpoint_id TEXT REFERENCES checkpoints(checkpoint_id) ON DELETE RESTRICT,
    superseded_by_checkpoint_id TEXT REFERENCES checkpoints(checkpoint_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    job_id TEXT REFERENCES jobs(job_id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    published_at TEXT CHECK (published_at IS NULL OR ({_timestamp_check("published_at")})),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS review_actions (
    review_action_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('mark-reviewed', 'dismiss', 'restore', 'tag', 'note')),
    actor TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    content_id TEXT REFERENCES contents(content_id) ON DELETE SET NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('recovered-copy', 'report', 'checkpoint', 'log')),
    storage_uri TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS derivatives (
    derivative_id TEXT PRIMARY KEY,
    content_id TEXT NOT NULL REFERENCES contents(content_id) ON DELETE CASCADE,
    derivative_kind TEXT NOT NULL CHECK (derivative_kind IN ('thumbnail', 'ocr-text', 'transcript', 'metadata', 'preview')),
    storage_uri TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS browser_artifacts (
    browser_artifact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    entry_id TEXT REFERENCES entries(entry_id) ON DELETE SET NULL,
    content_id TEXT REFERENCES contents(content_id) ON DELETE SET NULL,
    profile_id TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('profile', 'visit', 'download', 'bookmark', 'search', 'session_tab', 'cookie_metadata', 'cache_entry', 'extension')),
    browser_family TEXT NOT NULL CHECK (browser_family IN ('chromium', 'firefox', 'legacy_ie_edge', 'safari', 'unknown')),
    raw_provenance_json TEXT NOT NULL CHECK (json_valid(raw_provenance_json)),
    artifact_json TEXT NOT NULL CHECK (json_valid(artifact_json)),
    recovery_confidence REAL NOT NULL CHECK (recovery_confidence >= 0.0 AND recovery_confidence <= 1.0),
    first_observed_at TEXT CHECK (first_observed_at IS NULL OR ({_timestamp_check("first_observed_at")})),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS exports (
    export_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('local', 'nas', 'sftp', 'webdav', 's3', 'cloud')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")}),
    updated_at TEXT NOT NULL CHECK ({_timestamp_check("updated_at")})
) STRICT;

CREATE TABLE IF NOT EXISTS audit_references (
    audit_reference_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES scan_cases(case_id) ON DELETE CASCADE,
    source_id TEXT REFERENCES sources(source_id) ON DELETE RESTRICT,
    audit_hash TEXT NOT NULL CHECK (length(audit_hash) = 64),
    audit_uri TEXT NOT NULL,
    created_at TEXT NOT NULL CHECK ({_timestamp_check("created_at")}),
    CHECK (case_id IS NOT NULL OR source_id IS NOT NULL)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_scan_cases_source ON scan_cases(source_id);
CREATE INDEX IF NOT EXISTS idx_volumes_source ON volumes(source_id);
CREATE INDEX IF NOT EXISTS idx_entries_case ON entries(case_id);
CREATE INDEX IF NOT EXISTS idx_entries_content ON entries(content_id);
CREATE INDEX IF NOT EXISTS idx_contents_source ON contents(source_id);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_query ON findings(case_id, created_at, finding_id);
CREATE INDEX IF NOT EXISTS idx_findings_filters ON findings(finding_type, severity, status);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_checkpoints_latest ON checkpoints(job_id, stage, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_case_sequence ON events(case_id, sequence) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_case_created ON events(case_id, created_at, event_id);
CREATE INDEX IF NOT EXISTS idx_events_unpublished ON events(created_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_browser_artifacts_case_kind ON browser_artifacts(case_id, artifact_kind, browser_family);
CREATE INDEX IF NOT EXISTS idx_browser_artifacts_profile ON browser_artifacts(case_id, profile_id, artifact_kind);
"""
