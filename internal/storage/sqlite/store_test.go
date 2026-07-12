package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/scope"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrationPersistenceAndObservationImmutability(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	o := domain.Observation{SensorID: "test", Source: domain.SourceManual, TargetIP: netip.MustParseAddr("127.0.0.1"), Evidence: json.RawMessage(`{"fact":true}`), CollectorVersion: "test", PolicyDecisionID: "manual"}
	if err = s.AddObservation(context.Background(), &o); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB().Exec("UPDATE observations SET target_ip='127.0.0.2' WHERE id=?", o.ID); err == nil {
		t.Fatal("immutable observation updated")
	}
	s.Close()
	s, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.ListObservations(context.Background(), "", "", "", 10, 0)
	if err != nil || len(got) != 1 || got[0].ID != o.ID {
		t.Fatalf("persistence got=%v err=%v", got, err)
	}
	var v int
	if err = s.DB().QueryRow("SELECT max(version) FROM schema_migrations").Scan(&v); err != nil || v != 3 {
		t.Fatalf("version=%d err=%v", v, err)
	}
}
func TestExpiredJobLeaseRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j := domain.Job{Type: domain.JobDiscovery, Payload: json.RawMessage(`{}`)}
	if err = s.CreateJob(context.Background(), &j); err != nil {
		t.Fatal(err)
	}
	got, err := s.ClaimJob(context.Background(), "one", time.Millisecond)
	if err != nil || got.ID != j.ID {
		t.Fatal(got, err)
	}
	time.Sleep(3 * time.Millisecond)
	got, err = s.ClaimJob(context.Background(), "two", time.Minute)
	if err != nil || got.ID != j.ID || got.AttemptCount != 2 {
		t.Fatalf("recovery=%#v err=%v", got, err)
	}
	if _, err = s.ClaimJob(context.Background(), "three", time.Minute); err != sql.ErrNoRows {
		t.Fatalf("expected no job, got %v", err)
	}
}

func TestPreflightAllowsStayOutOfPrimaryAudit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := config.Default().Scope
	cfg.ActiveEnabled = true
	cfg.AllowedCIDRs = []string{"127.0.0.1/32"}
	cfg.AllowedPorts = []int{80}
	engine, err := scope.New(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = engine.ValidateJob([]string{"127.0.0.1"}, []int{80}); err != nil {
		t.Fatal(err)
	}
	var policies, audits int
	if err = s.DB().QueryRow("SELECT count(*) FROM policy_decisions WHERE phase='preflight'").Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if err = s.DB().QueryRow("SELECT count(*) FROM audit_events WHERE action='scope.decision'").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if policies != 1 || audits != 0 {
		t.Fatalf("preflight policies=%d audits=%d", policies, audits)
	}
	if decision := engine.Decide("127.0.0.1", 80); !decision.Allowed || decision.Phase != "execution" {
		t.Fatalf("execution decision %#v", decision)
	}
	if err = s.DB().QueryRow("SELECT count(*) FROM audit_events WHERE action='scope.decision'").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("execution audits=%d err=%v", audits, err)
	}
}
