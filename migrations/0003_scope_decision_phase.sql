ALTER TABLE policy_decisions ADD COLUMN phase TEXT NOT NULL DEFAULT 'execution';
CREATE INDEX policy_decisions_phase_time ON policy_decisions(phase,at DESC);
