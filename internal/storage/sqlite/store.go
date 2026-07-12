package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/telemetry"
	"github.com/cortalabs/cortasentry/migrations"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }
type Overview struct {
	ActiveAssets      int                  `json:"active_assets"`
	Observations      int                  `json:"observations"`
	OpenServices      int                  `json:"open_services"`
	AmbiguousAssets   int                  `json:"ambiguous_assets"`
	PotentialFindings int                  `json:"potential_findings"`
	RunningJobs       int                  `json:"running_jobs"`
	FailedJobs        int                  `json:"failed_jobs"`
	RecentChanges     []domain.ChangeEvent `json:"recent_changes"`
}

func (s *Store) GetOverview(ctx context.Context) (Overview, error) {
	var o Overview
	queries := []struct {
		q string
		v *int
	}{{"SELECT count(*) FROM assets WHERE status='active' AND merged_into IS NULL", &o.ActiveAssets}, {"SELECT count(*) FROM observations", &o.Observations}, {"SELECT count(DISTINCT target_ip||':'||target_port) FROM observations WHERE source='tcp_connect' AND json_extract(evidence_json,'$.state')='open'", &o.OpenServices}, {"SELECT count(*) FROM assets WHERE ambiguous=1 AND merged_into IS NULL", &o.AmbiguousAssets}, {"SELECT count(*) FROM findings WHERE state IN ('potentially_applicable','likely_applicable','version_confirmed','safely_validated')", &o.PotentialFindings}, {"SELECT count(*) FROM jobs WHERE state='running'", &o.RunningJobs}, {"SELECT count(*) FROM jobs WHERE state='failed'", &o.FailedJobs}}
	for _, x := range queries {
		if err := s.db.QueryRowContext(ctx, x.q).Scan(x.v); err != nil {
			return o, err
		}
	}
	o.RecentChanges, _ = s.ListChanges(ctx, "", 8)
	return o, nil
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_dqs=0"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.verifyPragmas(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"); err != nil {
		return err
	}
	var current int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&current); err != nil {
		return err
	}
	if current > 2 {
		return fmt.Errorf("database schema version %d is newer than supported version 2", current)
	}
	for v := current + 1; v <= 2; v++ {
		name := fmt.Sprintf("%04d_", v)
		entries, _ := migrations.FS.ReadDir(".")
		var file string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), name) && strings.HasSuffix(e.Name(), ".sql") {
				file = e.Name()
				break
			}
		}
		if file == "" {
			return fmt.Errorf("migration %d missing", v)
		}
		b, err := migrations.FS.ReadFile(file)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(b)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v, err)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", v, now()); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) verifyPragmas(ctx context.Context) error {
	var fk, timeout int
	var journal string
	if err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return err
	}
	if fk != 1 || timeout < 1000 || strings.ToLower(journal) != "wal" {
		return fmt.Errorf("unsafe sqlite pragmas foreign_keys=%d busy_timeout=%d journal=%s", fk, timeout, journal)
	}
	return nil
}
func now() string   { return time.Now().UTC().Format(time.RFC3339Nano) }
func newID() string { return uuid.Must(uuid.NewV7()).String() }

func (s *Store) ScopeDecision(d scope.Decision) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO policy_decisions(id,at,target_ip,port,allowed,reason) VALUES(?,?,?,?,?,?)", d.ID, d.At.Format(time.RFC3339Nano), d.Target, d.Port, d.Allowed, d.Reason); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"target": d.Target, "port": d.Port, "reason": d.Reason})
	if _, err = tx.Exec("INSERT INTO audit_events(id,at,actor,action,resource_type,resource_id,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?,?)", newID(), d.At.Format(time.RFC3339Nano), "system", "scope.decision", "target", d.Target, map[bool]string{true: "allowed", false: "denied"}[d.Allowed], "", string(details)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Audit(ctx context.Context, e domain.AuditEvent) error {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if len(e.Details) == 0 {
		e.Details = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit_events(id,at,actor,action,resource_type,resource_id,outcome,request_id,details_json) VALUES(?,?,?,?,?,?,?,?,?)", e.ID, e.At.Format(time.RFC3339Nano), e.Actor, e.Action, e.ResourceType, e.ResourceID, e.Outcome, e.RequestID, string(e.Details))
	return err
}
func (s *Store) AddObservation(ctx context.Context, o *domain.Observation) error {
	if o.ID == "" {
		o.ID = newID()
	}
	if o.IngestedAt.IsZero() {
		o.IngestedAt = time.Now().UTC()
	}
	if o.ObservedAt.IsZero() {
		o.ObservedAt = o.IngestedAt
	}
	if !o.TargetIP.IsValid() {
		return errors.New("observation target IP required")
	}
	if len(o.Evidence) == 0 || len(o.Evidence) > 1<<20 {
		return errors.New("observation evidence required and <=1 MiB")
	}
	if len(o.Provenance) == 0 {
		o.Provenance = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO observations(id,sensor_id,job_id,asset_id,observed_at,ingested_at,source,target_ip,target_port,transport,application,evidence_json,raw_digest,collector_version,policy_decision_id,truncated,provenance_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, o.ID, o.SensorID, o.JobID, o.AssetID, o.ObservedAt.Format(time.RFC3339Nano), o.IngestedAt.Format(time.RFC3339Nano), o.Source, o.TargetIP.Unmap().String(), o.TargetPort, o.Transport, o.Application, string(o.Evidence), o.RawDigest, o.CollectorVersion, o.PolicyDecisionID, o.Truncated, string(o.Provenance))
	if err == nil {
		telemetry.Observations.WithLabelValues(string(o.Source)).Inc()
	}
	return err
}
func (s *Store) ListObservations(ctx context.Context, assetID, source, ip string, limit, offset int) ([]domain.Observation, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	q := `SELECT o.id,o.sensor_id,o.job_id,COALESCE(ao.asset_id,o.asset_id),o.observed_at,o.ingested_at,o.source,o.target_ip,o.target_port,o.transport,o.application,o.evidence_json,o.raw_digest,o.collector_version,o.policy_decision_id,o.truncated,o.provenance_json FROM observations o LEFT JOIN asset_observations ao ON ao.observation_id=o.id WHERE (?='' OR ao.asset_id=?) AND (?='' OR o.source=?) AND (?='' OR o.target_ip=?) ORDER BY o.observed_at DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, assetID, assetID, source, source, ip, ip, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Observation{}
	for rows.Next() {
		var o domain.Observation
		var observed, ingested, target, evidence, prov string
		if err = rows.Scan(&o.ID, &o.SensorID, &o.JobID, &o.AssetID, &observed, &ingested, &o.Source, &target, &o.TargetPort, &o.Transport, &o.Application, &evidence, &o.RawDigest, &o.CollectorVersion, &o.PolicyDecisionID, &o.Truncated, &prov); err != nil {
			return nil, err
		}
		o.ObservedAt, _ = time.Parse(time.RFC3339Nano, observed)
		o.IngestedAt, _ = time.Parse(time.RFC3339Nano, ingested)
		o.TargetIP, _ = netip.ParseAddr(target)
		o.Evidence = []byte(evidence)
		o.Provenance = []byte(prov)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) CreateAsset(ctx context.Context, a *domain.Asset) error {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Status == "" {
		a.Status = "active"
	}
	tags, _ := json.Marshal(a.Tags)
	_, err := s.db.ExecContext(ctx, `INSERT INTO assets(id,display_name,first_seen,last_seen,status,device_class,vendor,product_family,model,firmware,operating_system,identification_score,ambiguous,criticality,tags_json,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.DisplayName, a.FirstSeen.Format(time.RFC3339Nano), a.LastSeen.Format(time.RFC3339Nano), a.Status, a.DeviceClass, a.Vendor, a.ProductFamily, a.Model, a.Firmware, a.OS, a.IdentificationScore, a.Ambiguous, a.Criticality, string(tags), a.Notes)
	return err
}
func (s *Store) AttachObservation(ctx context.Context, assetID string, o domain.Observation, reason string, conflict bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO asset_observations(asset_id,observation_id,resolver_version,reason,conflict) VALUES(?,?,?,?,?)", assetID, o.ID, "resolver/1.0.0", reason, conflict); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO asset_addresses(asset_id,address,first_seen,last_seen,current) VALUES(?,?,?,?,1) ON CONFLICT(asset_id,address) DO UPDATE SET last_seen=excluded.last_seen,current=1", assetID, o.TargetIP.String(), o.ObservedAt.Format(time.RFC3339Nano), o.ObservedAt.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE assets SET last_seen=?,status='active' WHERE id=?", o.ObservedAt.Format(time.RFC3339Nano), assetID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) AddIdentifier(ctx context.Context, assetID string, id domain.Identifier) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO asset_identifiers(asset_id,kind,value,strength,provenance,observation_id,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,kind,value) DO UPDATE SET last_seen=excluded.last_seen,observation_id=excluded.observation_id", assetID, id.Type, id.Value, id.Strength, id.Provenance, id.ObservationID, id.FirstSeen.Format(time.RFC3339Nano), id.LastSeen.Format(time.RFC3339Nano))
	return err
}
func (s *Store) FindAssetsByIdentifier(ctx context.Context, kind, value string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT asset_id FROM asset_identifiers WHERE kind=? AND value=? AND strength='strong'", kind, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *Store) FindContinuityAssets(ctx context.Context, address, serviceSet string, since time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT a.id FROM assets a JOIN asset_addresses aa ON aa.asset_id=a.id JOIN asset_identifiers ai ON ai.asset_id=a.id WHERE a.merged_into IS NULL AND aa.address=? AND aa.current=1 AND ai.kind='service_set' AND ai.value=? AND ai.last_seen>=?`, address, serviceSet, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
func (s *Store) ListAssets(ctx context.Context, status, vendor, class string, limit, offset int) ([]domain.Asset, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,display_name,first_seen,last_seen,status,device_class,vendor,product_family,model,firmware,operating_system,identification_score,ambiguous,criticality,tags_json,notes FROM assets WHERE merged_into IS NULL AND (?='' OR status=?) AND (?='' OR vendor=?) AND (?='' OR device_class=?) ORDER BY last_seen DESC LIMIT ? OFFSET ?`, status, status, vendor, vendor, class, class, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Asset{}
	for rows.Next() {
		var a domain.Asset
		var first, last, tags string
		if err = rows.Scan(&a.ID, &a.DisplayName, &first, &last, &a.Status, &a.DeviceClass, &a.Vendor, &a.ProductFamily, &a.Model, &a.Firmware, &a.OS, &a.IdentificationScore, &a.Ambiguous, &a.Criticality, &tags, &a.Notes); err != nil {
			return nil, err
		}
		a.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		a.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		_ = json.Unmarshal([]byte(tags), &a.Tags)
		addrs, _ := s.addresses(ctx, a.ID)
		a.CurrentAddresses = addrs
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) addresses(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT address FROM asset_addresses WHERE asset_id=? AND current=1 ORDER BY address", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) GetAsset(ctx context.Context, id string) (domain.Asset, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,display_name,first_seen,last_seen,status,device_class,vendor,product_family,model,firmware,operating_system,identification_score,ambiguous,criticality,tags_json,notes FROM assets WHERE id=? AND merged_into IS NULL`, id)
	var a domain.Asset
	var first, last, tags string
	if err := row.Scan(&a.ID, &a.DisplayName, &first, &last, &a.Status, &a.DeviceClass, &a.Vendor, &a.ProductFamily, &a.Model, &a.Firmware, &a.OS, &a.IdentificationScore, &a.Ambiguous, &a.Criticality, &tags, &a.Notes); err != nil {
		return a, err
	}
	a.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
	a.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
	_ = json.Unmarshal([]byte(tags), &a.Tags)
	a.CurrentAddresses, _ = s.addresses(ctx, a.ID)
	rows, err := s.db.QueryContext(ctx, "SELECT address,current FROM asset_addresses WHERE asset_id=? ORDER BY first_seen", id)
	if err == nil {
		defer rows.Close()
		a.CurrentAddresses = nil
		for rows.Next() {
			var address string
			var current bool
			if rows.Scan(&address, &current) == nil {
				if current {
					a.CurrentAddresses = append(a.CurrentAddresses, address)
				} else {
					a.HistoricalAddresses = append(a.HistoricalAddresses, address)
				}
			}
		}
	}
	identifierRows, err := s.db.QueryContext(ctx, "SELECT kind,value,strength,provenance,observation_id,first_seen,last_seen FROM asset_identifiers WHERE asset_id=? ORDER BY strength,kind", id)
	if err == nil {
		defer identifierRows.Close()
		for identifierRows.Next() {
			var identifier domain.Identifier
			var first, last string
			if identifierRows.Scan(&identifier.Type, &identifier.Value, &identifier.Strength, &identifier.Provenance, &identifier.ObservationID, &first, &last) == nil {
				identifier.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
				identifier.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
				a.Identifiers = append(a.Identifiers, identifier)
			}
		}
	}
	linkRows, err := s.db.QueryContext(ctx, "SELECT observation_id,conflict FROM asset_observations WHERE asset_id=? ORDER BY observation_id", id)
	if err == nil {
		defer linkRows.Close()
		for linkRows.Next() {
			var observationID string
			var conflict bool
			if linkRows.Scan(&observationID, &conflict) == nil {
				if conflict {
					a.ConflictingObservations = append(a.ConflictingObservations, observationID)
				} else {
					a.SupportingObservations = append(a.SupportingObservations, observationID)
				}
			}
		}
	}
	return a, nil
}
func (s *Store) UpdateClassification(ctx context.Context, id, deviceClass, vendor, family, model string, score float64, ambiguous bool) error {
	_, err := s.db.ExecContext(ctx, "UPDATE assets SET device_class=?,vendor=?,product_family=?,model=?,identification_score=?,ambiguous=? WHERE id=?", deviceClass, vendor, family, model, score, ambiguous, id)
	return err
}

func (s *Store) CreateJob(ctx context.Context, j *domain.Job) error {
	if j.ID == "" {
		j.ID = newID()
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	if j.State == "" {
		j.State = "queued"
	}
	if len(j.Payload) == 0 {
		j.Payload = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO jobs(id,type,state,payload_json,created_at,progress_total) VALUES(?,?,?,?,?,?)", j.ID, j.Type, j.State, string(j.Payload), j.CreatedAt.Format(time.RFC3339Nano), j.ProgressTotal)
	return err
}
func (s *Store) CreateJobBounded(ctx context.Context, j *domain.Job, maxQueued int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if j.IdempotencyKey != "" {
		var id, state, created string
		err = tx.QueryRowContext(ctx, "SELECT id,state,created_at FROM jobs WHERE type=? AND idempotency_key=?", j.Type, j.IdempotencyKey).Scan(&id, &state, &created)
		if err == nil {
			j.ID = id
			j.State = state
			j.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
			return tx.Commit()
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE state IN ('queued','running')").Scan(&n); err != nil {
		return err
	}
	if n >= maxQueued {
		return errors.New("job queue is full")
	}
	if j.ID == "" {
		j.ID = newID()
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	if j.State == "" {
		j.State = "queued"
	}
	if len(j.Payload) == 0 {
		j.Payload = []byte("{}")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO jobs(id,type,state,payload_json,created_at,progress_total,idempotency_key) VALUES(?,?,?,?,?,?,?)", j.ID, j.Type, j.State, string(j.Payload), j.CreatedAt.Format(time.RFC3339Nano), j.ProgressTotal, j.IdempotencyKey); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ClaimJob(ctx context.Context, owner string, lease time.Duration) (*domain.Job, error) {
	expires := time.Now().UTC().Add(lease).Format(time.RFC3339Nano)
	row := s.db.QueryRowContext(ctx, `UPDATE jobs SET state='running',attempt_count=attempt_count+1,lease_owner=?,lease_expires_at=?,started_at=COALESCE(started_at,?) WHERE id=(SELECT id FROM jobs WHERE cancel_requested=0 AND (state='queued' OR (state='running' AND lease_expires_at<?)) ORDER BY created_at LIMIT 1) RETURNING id,type,state,payload_json,attempt_count,created_at,progress_current,progress_total`, owner, expires, now(), now())
	var j domain.Job
	var payload, created string
	if err := row.Scan(&j.ID, &j.Type, &j.State, &payload, &j.AttemptCount, &created, &j.ProgressCurrent, &j.ProgressTotal); err != nil {
		return nil, err
	}
	j.Payload = []byte(payload)
	j.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	j.LeaseOwner = owner
	return &j, nil
}
func (s *Store) FinishJob(ctx context.Context, id, state, summary string) error {
	if state != "completed" && state != "failed" && state != "cancelled" {
		return errors.New("invalid terminal state")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE jobs SET state=?,error_summary=?,completed_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE id=?", state, summary, now(), id)
	return err
}
func (s *Store) RenewJob(ctx context.Context, id, owner string, lease time.Duration) error {
	r, err := s.db.ExecContext(ctx, "UPDATE jobs SET lease_expires_at=? WHERE id=? AND state='running' AND lease_owner=?", time.Now().UTC().Add(lease).Format(time.RFC3339Nano), id, owner)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("job lease lost")
	}
	return nil
}
func (s *Store) JobCancelled(ctx context.Context, id string) (bool, error) {
	var v bool
	err := s.db.QueryRowContext(ctx, "SELECT cancel_requested FROM jobs WHERE id=?", id).Scan(&v)
	return v, err
}
func (s *Store) UpdateJobProgress(ctx context.Context, id string, current, total int) error {
	_, err := s.db.ExecContext(ctx, "UPDATE jobs SET progress_current=?,progress_total=? WHERE id=?", current, total, id)
	return err
}
func (s *Store) CancelJob(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE jobs SET cancel_requested=1,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,completed_at=CASE WHEN state='queued' THEN ? ELSE completed_at END WHERE id=? AND state IN ('queued','running')`, now(), id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) ListJobs(ctx context.Context, limit int) ([]domain.Job, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,type,state,payload_json,attempt_count,created_at,cancel_requested,error_summary,progress_current,progress_total FROM jobs ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Job{}
	for rows.Next() {
		var j domain.Job
		var p, c string
		if err = rows.Scan(&j.ID, &j.Type, &j.State, &p, &j.AttemptCount, &c, &j.CancelRequested, &j.ErrorSummary, &j.ProgressCurrent, &j.ProgressTotal); err != nil {
			return nil, err
		}
		j.Payload = []byte(p)
		j.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Store) GetJob(ctx context.Context, id string) (domain.Job, error) {
	var j domain.Job
	var p, c string
	err := s.db.QueryRowContext(ctx, "SELECT id,type,state,payload_json,attempt_count,created_at,cancel_requested,error_summary,progress_current,progress_total FROM jobs WHERE id=?", id).Scan(&j.ID, &j.Type, &j.State, &p, &j.AttemptCount, &c, &j.CancelRequested, &j.ErrorSummary, &j.ProgressCurrent, &j.ProgressTotal)
	j.Payload = []byte(p)
	j.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
	return j, err
}
func (s *Store) JobState(ctx context.Context, id string) (string, error) {
	var state string
	err := s.db.QueryRowContext(ctx, "SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	return state, err
}

func (s *Store) AddCandidate(ctx context.Context, c domain.FingerprintCandidate) error {
	if c.ID == "" {
		c.ID = newID()
	}
	sup, _ := json.Marshal(c.SupportingPredicates)
	neg, _ := json.Marshal(c.NegativePredicates)
	obs, _ := json.Marshal(c.ObservationIDs)
	br, _ := json.Marshal(c.Breakdown)
	_, err := s.db.ExecContext(ctx, `INSERT INTO fingerprint_candidates(id,asset_id,rule_id,rule_version,device_class,vendor,product_family,model,score,supporting_json,negative_json,source_diversity,observation_ids_json,explanation,breakdown_json,evaluated_at,engine_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.ID, c.AssetID, c.RuleID, c.RuleVersion, c.DeviceClass, c.Vendor, c.ProductFamily, c.Model, c.Score, string(sup), string(neg), c.SourceDiversity, string(obs), c.Explanation, string(br), c.EvaluatedAt.Format(time.RFC3339Nano), c.EngineVersion)
	return err
}

func (s *Store) ListCandidates(ctx context.Context, assetID string, limit int) ([]domain.FingerprintCandidate, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,asset_id,rule_id,rule_version,device_class,vendor,product_family,model,score,supporting_json,negative_json,source_diversity,observation_ids_json,explanation,breakdown_json,evaluated_at,engine_version FROM fingerprint_candidates WHERE asset_id=? ORDER BY evaluated_at DESC,score DESC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.FingerprintCandidate
	for rows.Next() {
		var candidate domain.FingerprintCandidate
		var supporting, negative, observations, breakdown, evaluated string
		if err = rows.Scan(&candidate.ID, &candidate.AssetID, &candidate.RuleID, &candidate.RuleVersion, &candidate.DeviceClass, &candidate.Vendor, &candidate.ProductFamily, &candidate.Model, &candidate.Score, &supporting, &negative, &candidate.SourceDiversity, &observations, &candidate.Explanation, &breakdown, &evaluated, &candidate.EngineVersion); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(supporting), &candidate.SupportingPredicates)
		_ = json.Unmarshal([]byte(negative), &candidate.NegativePredicates)
		_ = json.Unmarshal([]byte(observations), &candidate.ObservationIDs)
		_ = json.Unmarshal([]byte(breakdown), &candidate.Breakdown)
		candidate.EvaluatedAt, _ = time.Parse(time.RFC3339Nano, evaluated)
		out = append(out, candidate)
	}
	return out, rows.Err()
}
func (s *Store) AddChange(ctx context.Context, c domain.ChangeEvent) error {
	if c.ID == "" {
		c.ID = newID()
	}
	obs, _ := json.Marshal(c.ObservationIDs)
	key := string(c.Type) + ":" + c.AssetID + ":" + string(c.Current)
	_, err := s.db.ExecContext(ctx, `INSERT INTO change_events(id,dedupe_key,asset_id,type,previous_json,current_json,observation_ids_json,detected_at,first_occurrence,last_occurrence) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(dedupe_key) DO UPDATE SET last_occurrence=excluded.last_occurrence,occurrences=occurrences+1`, c.ID, key, c.AssetID, c.Type, string(c.Previous), string(c.Current), string(obs), c.DetectedAt.Format(time.RFC3339Nano), c.FirstOccurrence.Format(time.RFC3339Nano), c.LastOccurrence.Format(time.RFC3339Nano))
	return err
}
func (s *Store) ListChanges(ctx context.Context, assetID string, limit int) ([]domain.ChangeEvent, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,asset_id,type,previous_json,current_json,observation_ids_json,detected_at,first_occurrence,last_occurrence,acknowledged FROM change_events WHERE (?='' OR asset_id=?) ORDER BY detected_at DESC LIMIT ?", assetID, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ChangeEvent
	for rows.Next() {
		var c domain.ChangeEvent
		var prev, cur, obs, det, first, last string
		if err = rows.Scan(&c.ID, &c.AssetID, &c.Type, &prev, &cur, &obs, &det, &first, &last, &c.Acknowledged); err != nil {
			return nil, err
		}
		c.Previous = []byte(prev)
		c.Current = []byte(cur)
		_ = json.Unmarshal([]byte(obs), &c.ObservationIDs)
		c.DetectedAt, _ = time.Parse(time.RFC3339Nano, det)
		c.FirstOccurrence, _ = time.Parse(time.RFC3339Nano, first)
		c.LastOccurrence, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) AcknowledgeChange(ctx context.Context, id string, ack bool) error {
	r, err := s.db.ExecContext(ctx, "UPDATE change_events SET acknowledged=? WHERE id=?", ack, id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) ListAudit(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,at,actor,action,resource_type,resource_id,outcome,request_id,details_json FROM audit_events ORDER BY at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var e domain.AuditEvent
		var at, d string
		if err = rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.ResourceType, &e.ResourceID, &e.Outcome, &e.RequestID, &d); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.Details = []byte(d)
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Store) ListFindings(ctx context.Context, assetID, severity string, limit int) ([]domain.Finding, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,asset_id,advisory_id,state,severity,evidence_score,product_evidence_json,version_evidence_json,validation_evidence_json,source,rule_digest,first_seen,last_evaluated,remediation,operator_disposition FROM findings WHERE (?='' OR asset_id=?) AND (?='' OR severity=?) ORDER BY last_evaluated DESC LIMIT ?", assetID, assetID, severity, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		var f domain.Finding
		var p, v, val, first, last string
		if err = rows.Scan(&f.ID, &f.AssetID, &f.AdvisoryID, &f.State, &f.Severity, &f.EvidenceScore, &p, &v, &val, &f.Source, &f.RuleDigest, &first, &last, &f.Remediation, &f.OperatorDisposition); err != nil {
			return nil, err
		}
		f.ProductEvidence = []byte(p)
		f.VersionEvidence = []byte(v)
		f.ValidationEvidence = []byte(val)
		f.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		f.LastEvaluated, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *Store) UpdateFindingDisposition(ctx context.Context, id, disposition string) error {
	allowed := map[string]bool{"": true, "accepted_risk": true, "false_positive": true, "remediated": true}
	if !allowed[disposition] {
		return errors.New("invalid disposition")
	}
	r, err := s.db.ExecContext(ctx, "UPDATE findings SET operator_disposition=? WHERE id=?", disposition, id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) UpsertFinding(ctx context.Context, f *domain.Finding) (bool, error) {
	if f.ID == "" {
		f.ID = newID()
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = time.Now().UTC()
	}
	if f.LastEvaluated.IsZero() {
		f.LastEvaluated = f.FirstSeen
	}
	for _, p := range []*json.RawMessage{&f.ProductEvidence, &f.VersionEvidence, &f.ValidationEvidence} {
		if len(*p) == 0 {
			*p = []byte("{}")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var existingID, oldState string
	err = tx.QueryRowContext(ctx, "SELECT id,state FROM findings WHERE asset_id=? AND advisory_id=?", f.AssetID, f.AdvisoryID).Scan(&existingID, &oldState)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return false, err
	}
	if created {
		_, err = tx.ExecContext(ctx, `INSERT INTO findings(id,asset_id,advisory_id,state,severity,evidence_score,product_evidence_json,version_evidence_json,validation_evidence_json,source,rule_digest,first_seen,last_evaluated,remediation,operator_disposition) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, f.ID, f.AssetID, f.AdvisoryID, f.State, f.Severity, f.EvidenceScore, string(f.ProductEvidence), string(f.VersionEvidence), string(f.ValidationEvidence), f.Source, f.RuleDigest, f.FirstSeen.Format(time.RFC3339Nano), f.LastEvaluated.Format(time.RFC3339Nano), f.Remediation, f.OperatorDisposition)
	} else {
		f.ID = existingID
		_, err = tx.ExecContext(ctx, "UPDATE findings SET state=?,severity=?,evidence_score=?,product_evidence_json=?,version_evidence_json=?,validation_evidence_json=?,source=?,rule_digest=?,last_evaluated=?,remediation=? WHERE id=?", f.State, f.Severity, f.EvidenceScore, string(f.ProductEvidence), string(f.VersionEvidence), string(f.ValidationEvidence), f.Source, f.RuleDigest, f.LastEvaluated.Format(time.RFC3339Nano), f.Remediation, f.ID)
	}
	if err != nil {
		return false, err
	}
	if created || oldState != string(f.State) {
		_, err = tx.ExecContext(ctx, "INSERT INTO finding_history(finding_id,at,old_state,new_state,actor,reason) VALUES(?,?,?,?,?,?)", f.ID, now(), oldState, f.State, "system", "advisory correlation")
	}
	if err != nil {
		return false, err
	}
	return created, tx.Commit()
}
func (s *Store) MergeAssets(ctx context.Context, source, target string) error {
	if source == target || source == "" || target == "" {
		return errors.New("invalid merge IDs")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM assets WHERE id IN (?,?) AND merged_into IS NULL", source, target).Scan(&n); err != nil || n != 2 {
		return errors.New("both active assets must exist")
	}
	rows, err := tx.QueryContext(ctx, "SELECT kind,value FROM asset_identifiers WHERE asset_id=? AND strength='strong'", source)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err = rows.Scan(&k, &v); err != nil {
			return err
		}
		var conflicts int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM asset_identifiers WHERE asset_id=? AND kind=? AND value<>? AND strength='strong'", target, k, v).Scan(&conflicts); err != nil {
			return err
		}
		if conflicts > 0 {
			return fmt.Errorf("strong identifier conflict for %s", k)
		}
	}
	rows.Close()
	if _, err = tx.ExecContext(ctx, "UPDATE assets SET merged_into=?,status='merged' WHERE id=?", target, source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO asset_addresses(asset_id,address,first_seen,last_seen,current) SELECT ?,address,first_seen,last_seen,current FROM asset_addresses WHERE asset_id=?", target, source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO asset_identifiers(asset_id,kind,value,strength,provenance,observation_id,first_seen,last_seen) SELECT ?,kind,value,strength,provenance,observation_id,first_seen,last_seen FROM asset_identifiers WHERE asset_id=?", target, source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO asset_observations(asset_id,observation_id,resolver_version,reason,conflict) SELECT ?,observation_id,resolver_version,'manual merge: '||reason,conflict FROM asset_observations WHERE asset_id=?", target, source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM asset_observations WHERE asset_id=?", source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE fingerprint_candidates SET asset_id=? WHERE asset_id=?", target, source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE change_events SET asset_id=? WHERE asset_id=?", target, source); err != nil {
		return err
	}
	rows2, err := tx.QueryContext(ctx, "SELECT id,advisory_id FROM findings WHERE asset_id=?", source)
	if err != nil {
		return err
	}
	for rows2.Next() {
		var id, adv string
		if err = rows2.Scan(&id, &adv); err != nil {
			rows2.Close()
			return err
		}
		var existing int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM findings WHERE asset_id=? AND advisory_id=?", target, adv).Scan(&existing); err != nil {
			rows2.Close()
			return err
		}
		if existing > 0 {
			if _, err = tx.ExecContext(ctx, "DELETE FROM finding_history WHERE finding_id=?", id); err == nil {
				_, err = tx.ExecContext(ctx, "DELETE FROM findings WHERE id=?", id)
			}
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE findings SET asset_id=? WHERE id=?", target, id)
		}
		if err != nil {
			rows2.Close()
			return err
		}
	}
	rows2.Close()
	return tx.Commit()
}
