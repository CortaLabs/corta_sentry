package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/telemetry"
	"github.com/google/uuid"
	"sync"
	"time"
)

type Store interface {
	CreateJobBounded(context.Context, *domain.Job, int) error
	ClaimJob(context.Context, string, time.Duration) (*domain.Job, error)
	RenewJob(context.Context, string, string, time.Duration) error
	JobCancelled(context.Context, string) (bool, error)
	UpdateJobProgress(context.Context, string, int, int) error
	FinishJob(context.Context, string, string, string) error
	CancelJob(context.Context, string) error
}
type Handler func(context.Context, *domain.Job, func(int, int) error) error
type Manager struct {
	store                    Store
	workers, maxQueued       int
	lease, poll, maxDuration time.Duration
	handler                  Handler
	once                     sync.Once
}

func New(store Store, workers, maxQueued int, lease, poll, maxDuration time.Duration, h Handler) *Manager {
	return &Manager{store: store, workers: workers, maxQueued: maxQueued, lease: lease, poll: poll, maxDuration: maxDuration, handler: h}
}
func (m *Manager) Enqueue(ctx context.Context, t domain.JobType, payload []byte, total int) (domain.Job, error) {
	return m.EnqueueWithKey(ctx, t, payload, total, "")
}
func (m *Manager) EnqueueWithKey(ctx context.Context, t domain.JobType, payload []byte, total int, key string) (domain.Job, error) {
	j := domain.Job{Type: t, Payload: payload, ProgressTotal: total, IdempotencyKey: key}
	if err := m.store.CreateJobBounded(ctx, &j, m.maxQueued); err != nil {
		return j, err
	}
	telemetry.QueueDepth.Inc()
	return j, nil
}
func (m *Manager) Cancel(ctx context.Context, id string) error { return m.store.CancelJob(ctx, id) }
func (m *Manager) Start(ctx context.Context) {
	m.once.Do(func() {
		for i := 0; i < m.workers; i++ {
			owner := "worker-" + uuid.NewString()
			go m.loop(ctx, owner)
		}
	})
}
func (m *Manager) loop(ctx context.Context, owner string) {
	ticker := time.NewTicker(m.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j, err := m.store.ClaimJob(ctx, owner, m.lease)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				telemetry.Errors.WithLabelValues("job_claim").Inc()
				continue
			}
			m.execute(ctx, owner, j)
		}
	}
}
func (m *Manager) execute(parent context.Context, owner string, j *domain.Job) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, m.maxDuration)
	defer cancel()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(m.poll)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cancelled, err := m.store.JobCancelled(ctx, j.ID)
				if err != nil || cancelled {
					cancel()
					return
				}
				if err = m.store.RenewJob(ctx, j.ID, owner, m.lease); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	progress := func(current, total int) error { return m.store.UpdateJobProgress(ctx, j.ID, current, total) }
	err := m.handler(ctx, j, progress)
	cancel()
	<-done
	state, summary := "completed", ""
	if err != nil {
		summary = err.Error()
		state = "failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			cancelled, _ := m.store.JobCancelled(context.Background(), j.ID)
			if cancelled {
				state = "cancelled"
			} else {
				state = "failed"
			}
		}
	}
	if finishErr := m.store.FinishJob(context.Background(), j.ID, state, summary); finishErr != nil {
		telemetry.Errors.WithLabelValues("job_finish").Inc()
	}
	telemetry.QueueDepth.Dec()
	telemetry.JobDuration.WithLabelValues(string(j.Type), state).Observe(time.Since(started).Seconds())
	telemetry.Scans.WithLabelValues(state).Inc()
}
func (m *Manager) Wait(ctx context.Context, id string, state func(context.Context, string) (string, error)) error {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			s, err := state(ctx, id)
			if err != nil {
				return err
			}
			switch s {
			case "completed":
				return nil
			case "failed", "cancelled":
				return fmt.Errorf("job %s", s)
			}
		}
	}
}
