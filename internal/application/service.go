package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	jobmanager "github.com/cortalabs/cortasentry/internal/jobs"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
)

type Principal struct{ Kind, ID, RequestID string }

func (p Principal) Actor() string {
	if p.ID == "" {
		return p.Kind
	}
	return p.Kind + ":" + p.ID
}

type Service struct {
	Config       config.Config
	Store        *sqlite.Store
	Scope        *scope.Engine
	PreviewScope *scope.Engine
	Rules        *fingerprint.Engine
	Jobs         *jobmanager.Manager
}

func New(c config.Config, s *sqlite.Store, sc *scope.Engine, r *fingerprint.Engine, j *jobmanager.Manager) (*Service, error) {
	preview, err := scope.New(c.Scope, nil)
	if err != nil {
		return nil, err
	}
	return &Service{Config: c, Store: s, Scope: sc, PreviewScope: preview, Rules: r, Jobs: j}, nil
}

type ScanRequest struct {
	Targets        []string `json:"targets"`
	Ports          []int    `json:"ports"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
}
type ScanPreview struct {
	Allowed       bool     `json:"allowed"`
	Reason        string   `json:"reason,omitempty"`
	Targets       []string `json:"targets"`
	Ports         []int    `json:"ports"`
	HostCount     int      `json:"host_count"`
	ProbeCount    int      `json:"probe_count"`
	ActiveEnabled bool     `json:"active_enabled"`
}

func (s *Service) PreviewScan(req ScanRequest) ScanPreview {
	out := ScanPreview{Targets: req.Targets, Ports: req.Ports, HostCount: len(req.Targets), ProbeCount: len(req.Targets) * len(req.Ports), ActiveEnabled: s.Config.Scope.ActiveEnabled}
	aa, pp, err := s.PreviewScope.ValidateJob(req.Targets, req.Ports)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	out.Targets = make([]string, len(aa))
	for i, a := range aa {
		out.Targets[i] = a.String()
	}
	out.Ports = pp
	out.HostCount = len(aa)
	out.ProbeCount = len(aa) * len(pp)
	out.Allowed = true
	return out
}
func (s *Service) SubmitScan(ctx context.Context, p Principal, req ScanRequest) (domain.Job, error) {
	if s.Jobs == nil {
		return domain.Job{}, errors.New("job manager unavailable")
	}
	aa, pp, err := s.Scope.ValidateJob(req.Targets, req.Ports)
	if err != nil {
		s.audit(ctx, p, "scan.create", "scan", "", "denied", map[string]any{"reason": err.Error()})
		return domain.Job{}, err
	}
	normalized := ScanRequest{Ports: pp, IdempotencyKey: req.IdempotencyKey}
	for _, a := range aa {
		normalized.Targets = append(normalized.Targets, a.String())
	}
	payload, _ := json.Marshal(normalized)
	j, err := s.Jobs.EnqueueWithKey(ctx, domain.JobDiscovery, payload, len(aa)*len(pp), req.IdempotencyKey)
	outcome := "accepted"
	if err != nil {
		outcome = "failure"
	}
	_ = s.audit(ctx, p, "scan.create", "scan", j.ID, outcome, map[string]any{"targets": normalized.Targets, "ports": pp})
	return j, err
}
func (s *Service) CancelJob(ctx context.Context, p Principal, id string) error {
	if s.Jobs == nil {
		return errors.New("job manager unavailable")
	}
	err := s.Jobs.Cancel(ctx, id)
	auditErr := s.audit(ctx, p, "job.cancel", "job", id, outcome(err), nil)
	if err != nil {
		return err
	}
	return auditErr
}
func (s *Service) ReloadRules(ctx context.Context, p Principal) error {
	if err := s.Rules.Reload(s.Config.Rules.DevicePaths); err != nil {
		_ = s.audit(ctx, p, "rules.reload", "rules", "", "failure", map[string]any{"error": err.Error()})
		return err
	}
	return s.audit(ctx, p, "rules.reload", "rules", "", "success", map[string]any{"digest": s.Rules.Current().Digest})
}
func (s *Service) MergeAssets(ctx context.Context, p Principal, source, target string) error {
	err := s.Store.MergeAssets(ctx, source, target)
	auditErr := s.audit(ctx, p, "asset.merge", "asset", target, outcome(err), map[string]any{"source": source})
	if err != nil {
		return err
	}
	return auditErr
}
func (s *Service) SetFindingDisposition(ctx context.Context, p Principal, id, disposition string) error {
	err := s.Store.UpdateFindingDisposition(ctx, id, disposition)
	auditErr := s.audit(ctx, p, "finding.disposition", "finding", id, outcome(err), map[string]any{"disposition": disposition})
	if err != nil {
		return err
	}
	return auditErr
}
func (s *Service) AcknowledgeChange(ctx context.Context, p Principal, id string, ack bool) error {
	err := s.Store.AcknowledgeChange(ctx, id, ack)
	auditErr := s.audit(ctx, p, "change.acknowledge", "change", id, outcome(err), map[string]any{"acknowledged": ack})
	if err != nil {
		return err
	}
	return auditErr
}
func (s *Service) audit(ctx context.Context, p Principal, action, resourceType, resourceID, result string, details any) error {
	b := json.RawMessage(`{}`)
	if details != nil {
		b, _ = json.Marshal(details)
	}
	return s.Store.Audit(ctx, domain.AuditEvent{Actor: p.Actor(), Action: action, ResourceType: resourceType, ResourceID: resourceID, Outcome: result, RequestID: p.RequestID, Details: b})
}
func outcome(err error) string {
	if err == nil {
		return "success"
	}
	return "failure"
}
func (s *Service) RequireMCPWrite(active bool) error {
	if !s.Config.MCP.WriteEnabled {
		return errors.New("MCP write tools are disabled; set mcp.write_enabled: true explicitly")
	}
	if active && !s.Config.MCP.ActiveToolsEnabled {
		return fmt.Errorf("MCP active tools are disabled; set mcp.active_tools_enabled: true explicitly")
	}
	return nil
}
