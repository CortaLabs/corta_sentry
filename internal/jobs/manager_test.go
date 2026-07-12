package jobs

import (
	"context"
	"encoding/json"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"path/filepath"
	"testing"
	"time"
)

func waitState(t *testing.T, s *sqlite.Store, id, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := s.JobState(context.Background(), id)
		if err == nil && got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, _ := s.JobState(context.Background(), id)
	t.Fatalf("state=%s want=%s", got, want)
}
func TestManagerCancellationAndQueueBound(t *testing.T) {
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	started := make(chan struct{})
	h := func(ctx context.Context, j *domain.Job, progress func(int, int) error) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	m := New(s, 1, 1, 100*time.Millisecond, 10*time.Millisecond, time.Minute, h)
	j, err := m.Enqueue(context.Background(), domain.JobDiscovery, json.RawMessage(`{}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Enqueue(context.Background(), domain.JobDiscovery, json.RawMessage(`{}`), 1); err == nil {
		t.Fatal("queue bound not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job did not start")
	}
	waitState(t, s, j.ID, "running")
	if err = m.Cancel(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, j.ID, "cancelled")
}
func TestManagerRecoversExpiredLease(t *testing.T) {
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j := domain.Job{Type: domain.JobDiscovery, Payload: json.RawMessage(`{}`)}
	if err = s.CreateJob(context.Background(), &j); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimJob(context.Background(), "dead-worker", 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	m := New(s, 1, 10, 100*time.Millisecond, 10*time.Millisecond, time.Minute, func(context.Context, *domain.Job, func(int, int) error) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	waitState(t, s, j.ID, "completed")
}

func TestQueuedCancellationIsTerminalAndReleasesCapacity(t *testing.T) {
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s, 1, 1, time.Second, 10*time.Millisecond, time.Minute, func(context.Context, *domain.Job, func(int, int) error) error { return nil })
	j, err := m.Enqueue(context.Background(), domain.JobDiscovery, json.RawMessage(`{}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Cancel(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, j.ID, "cancelled")
	if _, err = m.Enqueue(context.Background(), domain.JobDiscovery, json.RawMessage(`{}`), 1); err != nil {
		t.Fatalf("cancelled queued job retained capacity: %v", err)
	}
}
