PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS store_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL,
  uri TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  FOREIGN KEY (source_id) REFERENCES sources(source_id)
);

CREATE TABLE IF NOT EXISTS transforms (
  transform_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  runtime_hash TEXT
);

CREATE TABLE IF NOT EXISTS derived_artifacts (
  artifact_id TEXT PRIMARY KEY,
  artifact_type TEXT NOT NULL,
  source_snapshot_id TEXT,
  transform_id TEXT NOT NULL,
  output_hash TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  derivation_verification_level TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  FOREIGN KEY (source_snapshot_id) REFERENCES source_snapshots(snapshot_id),
  FOREIGN KEY (transform_id) REFERENCES transforms(transform_id)
);

CREATE TABLE IF NOT EXISTS artifact_inputs (
  artifact_id TEXT NOT NULL,
  input_artifact_id TEXT NOT NULL,
  input_role TEXT NOT NULL,
  PRIMARY KEY (artifact_id, input_artifact_id, input_role)
);

CREATE TABLE IF NOT EXISTS receipts (
  receipt_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  derivation_verification_level TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  receipt_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS index_update_plans (
  plan_id TEXT PRIMARY KEY,
  previous_state_hash TEXT,
  proposed_state_hash TEXT NOT NULL,
  added_count INTEGER NOT NULL,
  updated_count INTEGER NOT NULL,
  deleted_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  plan_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_tombstones (
  artifact_id TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  tombstoned_at TEXT NOT NULL,
  receipt_id TEXT NOT NULL
);
