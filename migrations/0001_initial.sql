CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE policy_decisions(id TEXT PRIMARY KEY, at TEXT NOT NULL, target_ip TEXT NOT NULL, port INTEGER NOT NULL, allowed INTEGER NOT NULL, reason TEXT NOT NULL);
CREATE TABLE audit_events(id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, outcome TEXT NOT NULL, request_id TEXT NOT NULL DEFAULT '', details_json TEXT NOT NULL DEFAULT '{}');
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TABLE observations(
 id TEXT PRIMARY KEY, sensor_id TEXT NOT NULL, job_id TEXT NOT NULL DEFAULT '', asset_id TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL, ingested_at TEXT NOT NULL,
 source TEXT NOT NULL, target_ip TEXT NOT NULL, target_port INTEGER NOT NULL DEFAULT 0, transport TEXT NOT NULL DEFAULT '', application TEXT NOT NULL DEFAULT '',
 evidence_json TEXT NOT NULL, raw_digest TEXT NOT NULL, collector_version TEXT NOT NULL, policy_decision_id TEXT NOT NULL, truncated INTEGER NOT NULL DEFAULT 0, provenance_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX observations_source_time ON observations(source, observed_at DESC);
CREATE INDEX observations_target ON observations(target_ip, target_port, observed_at DESC);
CREATE INDEX observations_asset ON observations(asset_id, observed_at DESC);
CREATE TRIGGER observations_no_update BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END;
CREATE TRIGGER observations_no_delete BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END;
CREATE TABLE assets(id TEXT PRIMARY KEY, display_name TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL, device_class TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '', product_family TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', firmware TEXT NOT NULL DEFAULT '', operating_system TEXT NOT NULL DEFAULT '', identification_score REAL NOT NULL DEFAULT 0, ambiguous INTEGER NOT NULL DEFAULT 0, criticality TEXT NOT NULL DEFAULT 'normal', tags_json TEXT NOT NULL DEFAULT '[]', notes TEXT NOT NULL DEFAULT '', merged_into TEXT);
CREATE INDEX assets_status_last_seen ON assets(status,last_seen DESC);
CREATE TABLE asset_addresses(asset_id TEXT NOT NULL REFERENCES assets(id), address TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, current INTEGER NOT NULL, PRIMARY KEY(asset_id,address));
CREATE INDEX asset_addresses_address ON asset_addresses(address,current);
CREATE TABLE asset_identifiers(asset_id TEXT NOT NULL REFERENCES assets(id), kind TEXT NOT NULL, value TEXT NOT NULL, strength TEXT NOT NULL, provenance TEXT NOT NULL, observation_id TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(asset_id,kind,value));
CREATE INDEX asset_identifiers_lookup ON asset_identifiers(kind,value,strength);
CREATE TABLE asset_observations(asset_id TEXT NOT NULL REFERENCES assets(id), observation_id TEXT NOT NULL REFERENCES observations(id), resolver_version TEXT NOT NULL, reason TEXT NOT NULL, conflict INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(asset_id,observation_id));
CREATE TABLE fingerprint_candidates(id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id),rule_id TEXT NOT NULL,rule_version TEXT NOT NULL,device_class TEXT NOT NULL,vendor TEXT NOT NULL,product_family TEXT NOT NULL,model TEXT NOT NULL,score REAL NOT NULL,supporting_json TEXT NOT NULL,negative_json TEXT NOT NULL,source_diversity INTEGER NOT NULL,observation_ids_json TEXT NOT NULL,explanation TEXT NOT NULL,breakdown_json TEXT NOT NULL,evaluated_at TEXT NOT NULL,engine_version TEXT NOT NULL);
CREATE INDEX fingerprint_candidates_asset ON fingerprint_candidates(asset_id,score DESC);
CREATE TABLE findings(id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id),advisory_id TEXT NOT NULL,state TEXT NOT NULL,severity TEXT NOT NULL,evidence_score REAL NOT NULL,product_evidence_json TEXT NOT NULL,version_evidence_json TEXT NOT NULL,validation_evidence_json TEXT NOT NULL,source TEXT NOT NULL,rule_digest TEXT NOT NULL,first_seen TEXT NOT NULL,last_evaluated TEXT NOT NULL,remediation TEXT NOT NULL,operator_disposition TEXT NOT NULL DEFAULT '', UNIQUE(asset_id,advisory_id));
CREATE TABLE finding_history(id INTEGER PRIMARY KEY AUTOINCREMENT,finding_id TEXT NOT NULL REFERENCES findings(id),at TEXT NOT NULL,old_state TEXT NOT NULL,new_state TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL);
CREATE TABLE change_events(id TEXT PRIMARY KEY,dedupe_key TEXT NOT NULL UNIQUE,asset_id TEXT NOT NULL REFERENCES assets(id),type TEXT NOT NULL,previous_json TEXT NOT NULL,current_json TEXT NOT NULL,observation_ids_json TEXT NOT NULL,detected_at TEXT NOT NULL,first_occurrence TEXT NOT NULL,last_occurrence TEXT NOT NULL,occurrences INTEGER NOT NULL DEFAULT 1,acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE INDEX change_asset_time ON change_events(asset_id,detected_at DESC);
CREATE TABLE jobs(id TEXT PRIMARY KEY,type TEXT NOT NULL,state TEXT NOT NULL,payload_json TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,lease_owner TEXT,lease_expires_at TEXT,created_at TEXT NOT NULL,started_at TEXT,completed_at TEXT,cancel_requested INTEGER NOT NULL DEFAULT 0,error_summary TEXT NOT NULL DEFAULT '',progress_current INTEGER NOT NULL DEFAULT 0,progress_total INTEGER NOT NULL DEFAULT 0);
CREATE INDEX jobs_claim ON jobs(state,lease_expires_at,created_at);
CREATE TABLE auth_tokens(id TEXT PRIMARY KEY,token_hash BLOB NOT NULL UNIQUE,created_at TEXT NOT NULL,revoked_at TEXT);
CREATE TABLE sessions(id TEXT PRIMARY KEY,token_hash BLOB NOT NULL UNIQUE,csrf_hash BLOB NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT);
CREATE TABLE rule_loads(id TEXT PRIMARY KEY,at TEXT NOT NULL,digest TEXT NOT NULL,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '');
