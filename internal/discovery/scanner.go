package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/assets"
	bannercollector "github.com/cortalabs/cortasentry/internal/collectors/banner"
	httpcollector "github.com/cortalabs/cortasentry/internal/collectors/http"
	tcpcollector "github.com/cortalabs/cortasentry/internal/collectors/tcp"
	tlscollector "github.com/cortalabs/cortasentry/internal/collectors/tls"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/telemetry"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ScanStore interface {
	AddObservation(context.Context, *domain.Observation) error
	AddCandidate(context.Context, domain.FingerprintCandidate) error
	AddChange(context.Context, domain.ChangeEvent) error
	ListObservations(context.Context, string, string, string, int, int) ([]domain.Observation, error)
	UpdateClassification(context.Context, string, string, string, string, string, float64, bool) error
	AttachObservation(context.Context, string, domain.Observation, string, bool) error
	GetAsset(context.Context, string) (domain.Asset, error)
}
type ScanResult struct {
	Observations, Assets, Candidates, Changes, Errors int
	AssetIDs                                          []string `json:"asset_ids,omitempty"`
}
type Scanner struct {
	dialer                              *AuthorizedDialer
	store                               ScanStore
	resolver                            *assets.Resolver
	engine                              *fingerprint.Engine
	maxConcurrency, maxBody, maxHeaders int
	timeout                             time.Duration
}

func NewScanner(d *AuthorizedDialer, s ScanStore, r *assets.Resolver, e *fingerprint.Engine, concurrency, maxBody, maxHeaders int, timeout time.Duration) *Scanner {
	return &Scanner{dialer: d, store: s, resolver: r, engine: e, maxConcurrency: concurrency, maxBody: maxBody, maxHeaders: maxHeaders, timeout: timeout}
}

type probe struct {
	addr netip.Addr
	port int
}

func (s *Scanner) Run(ctx context.Context, jobID string, targets []netip.Addr, ports []int, strongID string) (ScanResult, error) {
	return s.RunWithProgress(ctx, jobID, targets, ports, strongID, nil)
}

// IngestObservations applies the same immutable storage, identity resolution,
// fingerprinting, and change derivation used by active scans. Importers use
// this entry point so passive evidence does not become an orphaned record.
func (s *Scanner) IngestObservations(ctx context.Context, observations []domain.Observation, strongID string) (ScanResult, error) {
	var result ScanResult
	var mu sync.Mutex
	s.ingestBatch(ctx, observations, strongID, &result, &mu)
	if result.Errors > 0 {
		return result, errors.New("observation derivation failed")
	}
	return result, nil
}
func (s *Scanner) RunWithProgress(ctx context.Context, jobID string, targets []netip.Addr, ports []int, strongID string, progress func(int, int) error) (ScanResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan probe)
	var wg sync.WaitGroup
	var mu sync.Mutex
	result := ScanResult{}
	var completed atomic.Int64
	total := len(targets) * len(ports)
	workers := s.maxConcurrency
	if workers > len(targets)*len(ports) {
		workers = len(targets) * len(ports)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ch {
				if ctx.Err() != nil {
					return
				}
				obs := tcpcollector.Collect(ctx, s.dialer, p.addr, p.port, jobID)
				batch := []domain.Observation{obs}
				telemetry.Probes.WithLabelValues("attempted").Inc()
				var tcpEv map[string]any
				_ = json.Unmarshal(obs.Evidence, &tcpEv)
				if tcpEv["state"] == "open" {
					if isTLSPort(p.port) {
						if to, err := tlscollector.Collect(ctx, s.dialer, p.addr, p.port, s.timeout, jobID); err == nil {
							batch = append(batch, to)
						}
						if ho, err := httpcollector.CollectSecure(ctx, s.dialer, p.addr, p.port, s.maxBody, s.maxHeaders, s.timeout, jobID); err == nil {
							batch = append(batch, ho)
						}
					} else if isHTTPPort(p.port) {
						if ho, err := httpcollector.Collect(ctx, s.dialer, p.addr, p.port, s.maxBody, s.maxHeaders, s.timeout, jobID); err == nil {
							batch = append(batch, ho)
						}
					} else if isBannerPort(p.port) {
						if bo, err := bannercollector.Collect(ctx, s.dialer, p.addr, p.port, s.maxBody, s.timeout, jobID); err == nil {
							batch = append(batch, bo)
						}
					}
				}
				s.ingestBatch(ctx, batch, strongID, &result, &mu)
				current := int(completed.Add(1))
				if progress != nil {
					if err := progress(current, total); err != nil {
						cancel()
						return
					}
				}
			}
		}()
	}
	for _, a := range targets {
		for _, p := range ports {
			select {
			case ch <- probe{a, p}:
			case <-ctx.Done():
				close(ch)
				wg.Wait()
				return result, ctx.Err()
			}
		}
	}
	close(ch)
	wg.Wait()
	return result, nil
}
func isTLSPort(p int) bool { return p == 443 || p == 8443 || p == 18443 }
func isHTTPPort(p int) bool {
	switch p {
	case 80, 8000, 8001, 8002, 8080, 18001, 18002, 18003, 18004:
		return true
	}
	return false
}
func isBannerPort(p int) bool { return p == 22 || p == 23 || p == 12022 }
func (s *Scanner) ingestBatch(ctx context.Context, batch []domain.Observation, strongID string, result *ScanResult, mu *sync.Mutex) {
	if len(batch) == 0 {
		return
	}
	for i := range batch {
		if err := s.store.AddObservation(ctx, &batch[i]); err != nil {
			mu.Lock()
			result.Errors++
			mu.Unlock()
			return
		}
	}
	ids := []domain.Identifier{}
	serviceSet := serviceSetFingerprint(batch)
	if serviceSet != "" {
		ids = append(ids, domain.Identifier{Type: "service_set", Value: serviceSet, Strength: "contextual", Provenance: "authorized_endpoint_batch"})
	}
	if strongID != "" {
		ids = append(ids, domain.Identifier{Type: "agent_enrollment_id", Value: strongID, Strength: "strong", Provenance: "fixture_lab"})
	}
	resolved, err := s.resolver.Resolve(ctx, batch[0], ids)
	if err != nil {
		mu.Lock()
		result.Errors++
		mu.Unlock()
		return
	}
	for i := 1; i < len(batch); i++ {
		if err = s.store.AttachObservation(ctx, resolved.AssetID, batch[i], "same authorized endpoint observation batch", false); err != nil {
			mu.Lock()
			result.Errors++
			mu.Unlock()
			return
		}
	}
	mu.Lock()
	result.Observations += len(batch)
	if resolved.Created {
		result.Assets++
	}
	found := false
	for _, id := range result.AssetIDs {
		if id == resolved.AssetID {
			found = true
			break
		}
	}
	if !found {
		result.AssetIDs = append(result.AssetIDs, resolved.AssetID)
	}
	mu.Unlock()
	if resolved.Created {
		at := time.Now().UTC()
		_ = s.store.AddChange(ctx, domain.ChangeEvent{AssetID: resolved.AssetID, Type: domain.ChangeAssetFirstSeen, Previous: []byte("null"), Current: json.RawMessage(fmt.Sprintf(`{"ip":%q}`, batch[0].TargetIP.String())), ObservationIDs: []string{batch[0].ID}, DetectedAt: at, FirstOccurrence: at, LastOccurrence: at})
		mu.Lock()
		result.Changes++
		mu.Unlock()
	}
	if !resolved.Created {
		s.detectEndpointChanges(ctx, resolved.AssetID, batch, result, mu)
	}
	recent, _ := s.store.ListObservations(ctx, resolved.AssetID, "", "", 200, 0)
	ev := make([]fingerprint.Evidence, 0, len(recent))
	for _, o := range recent {
		ev = append(ev, fingerprint.Evidence{ObservationID: o.ID, Source: o.Source, ObservedAt: o.ObservedAt, Fields: fieldsFrom(o)})
	}
	candidates := s.engine.Evaluate(resolved.AssetID, ev)
	for _, c := range candidates {
		if s.store.AddCandidate(ctx, c) == nil {
			mu.Lock()
			result.Candidates++
			mu.Unlock()
		}
	}
	if len(candidates) > 0 {
		top := candidates[0]
		amb := s.engine.IsAmbiguous(candidates)
		previous, _ := s.store.GetAsset(ctx, resolved.AssetID)
		_ = s.store.UpdateClassification(ctx, resolved.AssetID, top.DeviceClass, top.Vendor, top.ProductFamily, top.Model, top.Score, amb)
		if !resolved.Created && (previous.DeviceClass != top.DeviceClass || previous.Vendor != top.Vendor || previous.ProductFamily != top.ProductFamily || previous.Model != top.Model || previous.Ambiguous != amb) {
			at := time.Now().UTC()
			before, _ := json.Marshal(map[string]any{"device_class": previous.DeviceClass, "vendor": previous.Vendor, "product_family": previous.ProductFamily, "model": previous.Model, "ambiguous": previous.Ambiguous})
			after, _ := json.Marshal(map[string]any{"device_class": top.DeviceClass, "vendor": top.Vendor, "product_family": top.ProductFamily, "model": top.Model, "ambiguous": amb})
			if s.store.AddChange(ctx, domain.ChangeEvent{AssetID: resolved.AssetID, Type: domain.ChangeClassification, Previous: before, Current: after, ObservationIDs: top.ObservationIDs, DetectedAt: at, FirstOccurrence: at, LastOccurrence: at}) == nil {
				mu.Lock()
				result.Changes++
				mu.Unlock()
			}
		}
	}
	for _, o := range batch {
		if o.Source == domain.SourceHTTP {
			s.detectHTTPChange(ctx, resolved.AssetID, o, result, mu)
		}
	}
}

func (s *Scanner) detectEndpointChanges(ctx context.Context, assetID string, batch []domain.Observation, result *ScanResult, mu *sync.Mutex) {
	batchIDs := make(map[string]bool, len(batch))
	for _, observation := range batch {
		batchIDs[observation.ID] = true
	}
	recent, err := s.store.ListObservations(ctx, assetID, "", "", 200, 0)
	if err != nil {
		return
	}
	for _, current := range batch {
		switch current.Source {
		case domain.SourceTCPConnect:
			if observationState(current) != "open" {
				continue
			}
			seen := false
			for _, previous := range recent {
				if !batchIDs[previous.ID] && previous.Source == domain.SourceTCPConnect && previous.TargetPort == current.TargetPort && observationState(previous) == "open" {
					seen = true
					break
				}
			}
			if !seen {
				s.addEndpointChange(ctx, assetID, domain.ChangeNewService, []byte("null"), map[string]any{"port": current.TargetPort, "transport": current.Transport}, []string{current.ID}, result, mu)
			}
		case domain.SourceTLS:
			currentFingerprint := certificateFingerprint(current)
			if currentFingerprint == "" {
				continue
			}
			for _, previous := range recent {
				if batchIDs[previous.ID] || previous.Source != domain.SourceTLS || previous.TargetPort != current.TargetPort {
					continue
				}
				previousFingerprint := certificateFingerprint(previous)
				if previousFingerprint != "" && previousFingerprint != currentFingerprint {
					s.addEndpointChange(ctx, assetID, domain.ChangeCertificate, mustJSON(previousFingerprint), currentFingerprint, []string{previous.ID, current.ID}, result, mu)
				}
				break
			}
		}
	}
}

func (s *Scanner) addEndpointChange(ctx context.Context, assetID string, changeType domain.ChangeType, previous json.RawMessage, current any, observationIDs []string, result *ScanResult, mu *sync.Mutex) {
	now := time.Now().UTC()
	currentJSON, _ := json.Marshal(current)
	if s.store.AddChange(ctx, domain.ChangeEvent{AssetID: assetID, Type: changeType, Previous: previous, Current: currentJSON, ObservationIDs: observationIDs, DetectedAt: now, FirstOccurrence: now, LastOccurrence: now}) == nil {
		mu.Lock()
		result.Changes++
		mu.Unlock()
	}
}

func observationState(o domain.Observation) string {
	var evidence struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal(o.Evidence, &evidence)
	return evidence.State
}

func certificateFingerprint(o domain.Observation) string {
	var evidence struct {
		Certificates []struct {
			SHA256 string `json:"sha256"`
		} `json:"certificates"`
	}
	_ = json.Unmarshal(o.Evidence, &evidence)
	if len(evidence.Certificates) == 0 {
		return ""
	}
	return evidence.Certificates[0].SHA256
}

func mustJSON(value any) json.RawMessage {
	b, _ := json.Marshal(value)
	return b
}
func serviceSetFingerprint(batch []domain.Observation) string {
	parts := make([]string, 0, len(batch))
	for _, o := range batch {
		parts = append(parts, fmt.Sprintf("%s/%s/%d", o.Source, o.Application, o.TargetPort))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
func (s *Scanner) ingest(ctx context.Context, o *domain.Observation, strongID string, result *ScanResult, mu *sync.Mutex) {
	if err := s.store.AddObservation(ctx, o); err != nil {
		telemetry.Errors.WithLabelValues("observation_ingest").Inc()
		mu.Lock()
		result.Errors++
		mu.Unlock()
		return
	}
	ids := []domain.Identifier{}
	if strongID != "" {
		ids = append(ids, domain.Identifier{Type: "agent_enrollment_id", Value: strongID, Strength: "strong", Provenance: "fixture_lab"})
	}
	resolved, err := s.resolver.Resolve(ctx, *o, ids)
	if err != nil {
		mu.Lock()
		result.Errors++
		mu.Unlock()
		return
	}
	mu.Lock()
	result.Observations++
	if resolved.Created {
		result.Assets++
		telemetry.Assets.WithLabelValues(map[bool]string{true: "conflict", false: "created"}[resolved.Conflict]).Inc()
	}
	mu.Unlock()
	if resolved.Created {
		at := time.Now().UTC()
		_ = s.store.AddChange(ctx, domain.ChangeEvent{AssetID: resolved.AssetID, Type: domain.ChangeAssetFirstSeen, Previous: []byte("null"), Current: json.RawMessage(fmt.Sprintf(`{"ip":%q}`, o.TargetIP.String())), ObservationIDs: []string{o.ID}, DetectedAt: at, FirstOccurrence: at, LastOccurrence: at})
		mu.Lock()
		result.Changes++
		mu.Unlock()
	}
	fields := fieldsFrom(*o)
	candidates := s.engine.Evaluate(resolved.AssetID, []fingerprint.Evidence{{ObservationID: o.ID, Source: o.Source, ObservedAt: o.ObservedAt, Fields: fields}})
	telemetry.RuleEvaluations.Inc()
	for _, c := range candidates {
		_ = s.store.AddCandidate(ctx, c)
		mu.Lock()
		result.Candidates++
		mu.Unlock()
	}
	if len(candidates) > 0 {
		top := candidates[0]
		amb := s.engine.IsAmbiguous(candidates)
		_ = s.store.UpdateClassification(ctx, resolved.AssetID, top.DeviceClass, top.Vendor, top.ProductFamily, top.Model, top.Score, amb)
	}
	if o.Source == domain.SourceHTTP {
		s.detectHTTPChange(ctx, resolved.AssetID, *o, result, mu)
	}
}
func fieldsFrom(o domain.Observation) map[string]any {
	var e map[string]any
	_ = json.Unmarshal(o.Evidence, &e)
	out := map[string]any{}
	switch o.Source {
	case domain.SourceHTTP:
		out["http.status"] = e["status"]
		out["http.title"] = e["title"]
		out["http.header.server"] = e["server"]
	case domain.SourceBanner:
		out["banner.text"] = e["text"]
	case domain.SourceTCPConnect:
		out["tcp.port"] = o.TargetPort
	}
	return out
}
func (s *Scanner) detectHTTPChange(ctx context.Context, assetID string, o domain.Observation, result *ScanResult, mu *sync.Mutex) {
	obs, err := s.store.ListObservations(ctx, assetID, string(domain.SourceHTTP), "", 3, 0)
	if err != nil || len(obs) < 2 {
		return
	}
	var current, previous map[string]any
	_ = json.Unmarshal(obs[0].Evidence, &current)
	_ = json.Unmarshal(obs[1].Evidence, &previous)
	if current["title"] != previous["title"] {
		at := time.Now().UTC()
		prev, _ := json.Marshal(previous["title"])
		cur, _ := json.Marshal(current["title"])
		if s.store.AddChange(ctx, domain.ChangeEvent{AssetID: assetID, Type: domain.ChangeHTTPTitle, Previous: prev, Current: cur, ObservationIDs: []string{obs[0].ID, obs[1].ID}, DetectedAt: at, FirstOccurrence: at, LastOccurrence: at}) == nil {
			mu.Lock()
			result.Changes++
			mu.Unlock()
		}
	}
}
