package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cortalabs/cortasentry/internal/domain"
)

const ResolverVersion = "resolver/1.0.0"

type Store interface {
	FindAssetsByIdentifier(context.Context, string, string) ([]string, error)
	FindContinuityAssets(context.Context, string, string, time.Time) ([]string, error)
	CreateAsset(context.Context, *domain.Asset) error
	AttachObservation(context.Context, string, domain.Observation, string, bool) error
	AddIdentifier(context.Context, string, domain.Identifier) error
	Audit(context.Context, domain.AuditEvent) error
}
type Result struct {
	AssetID, Reason   string
	Created, Conflict bool
}
type Resolver struct{ store Store }

func New(s Store) *Resolver { return &Resolver{store: s} }

var strong = map[string]bool{"mac": true, "ssh_host_key": true, "snmp_engine_id": true, "agent_enrollment_id": true, "serial_number": true}

func (r *Resolver) Resolve(ctx context.Context, o domain.Observation, ids []domain.Identifier) (Result, error) {
	matches := map[string]bool{}
	serviceSet := ""
	strongSupplied := false
	strongUnmatched := false
	for _, id := range ids {
		if id.Type == "service_set" {
			serviceSet = id.Value
		}
		if !strong[id.Type] && id.Strength != "strong" {
			continue
		}
		strongSupplied = true
		found, err := r.store.FindAssetsByIdentifier(ctx, id.Type, id.Value)
		if err != nil {
			return Result{}, err
		}
		if len(found) == 0 {
			strongUnmatched = true
		}
		for _, a := range found {
			matches[a] = true
		}
	}
	result := Result{}
	if !strongSupplied && len(matches) == 0 && serviceSet != "" {
		continuity, err := r.store.FindContinuityAssets(ctx, o.TargetIP.String(), serviceSet, o.ObservedAt.Add(-30*time.Minute))
		if err != nil {
			return Result{}, err
		}
		for _, id := range continuity {
			matches[id] = true
		}
	}
	switch {
	case strongUnmatched && len(matches) > 0:
		a := domain.Asset{DisplayName: "Conflicting asset " + o.TargetIP.String(), FirstSeen: o.ObservedAt, LastSeen: o.ObservedAt, Status: "identity_conflict", Ambiguous: true, Criticality: "normal"}
		if err := r.store.CreateAsset(ctx, &a); err != nil {
			return result, err
		}
		result = Result{AssetID: a.ID, Reason: "strong identifiers partially contradicted an existing asset", Created: true, Conflict: true}
	case len(matches) == 0:
		a := domain.Asset{DisplayName: "Asset " + o.TargetIP.String(), FirstSeen: o.ObservedAt, LastSeen: o.ObservedAt, Status: "active", Criticality: "normal"}
		if err := r.store.CreateAsset(ctx, &a); err != nil {
			return result, err
		}
		result = Result{AssetID: a.ID, Reason: "insufficient identity evidence; created safe duplicate", Created: true}
	case len(matches) == 1:
		for id := range matches {
			result = Result{AssetID: id, Reason: "strong identifier agreement or recent address plus service-set continuity"}
		}
	default:
		a := domain.Asset{DisplayName: "Conflicting asset " + o.TargetIP.String(), FirstSeen: o.ObservedAt, LastSeen: o.ObservedAt, Status: "identity_conflict", Ambiguous: true, Criticality: "normal"}
		if err := r.store.CreateAsset(ctx, &a); err != nil {
			return result, err
		}
		result = Result{AssetID: a.ID, Reason: "multiple assets matched strong identifiers", Created: true, Conflict: true}
	}
	if err := r.store.AttachObservation(ctx, result.AssetID, o, result.Reason, result.Conflict); err != nil {
		return result, err
	}
	for _, id := range ids {
		id.ObservationID = o.ID
		if id.FirstSeen.IsZero() {
			id.FirstSeen = o.ObservedAt
		}
		id.LastSeen = o.ObservedAt
		if strong[id.Type] {
			id.Strength = "strong"
		} else if id.Strength == "" {
			id.Strength = "contextual"
		}
		if err := r.store.AddIdentifier(ctx, result.AssetID, id); err != nil {
			return result, err
		}
	}
	details, _ := json.Marshal(map[string]any{"reason": result.Reason, "resolver_version": ResolverVersion, "observation_id": o.ID, "conflict": result.Conflict})
	action := "asset.updated"
	if result.Created {
		action = "asset.created"
	}
	if result.Conflict {
		action = "asset.identity_conflict"
	}
	if err := r.store.Audit(ctx, domain.AuditEvent{At: time.Now().UTC(), Actor: "system", Action: action, ResourceType: "asset", ResourceID: result.AssetID, Outcome: "success", Details: details}); err != nil {
		return result, fmt.Errorf("audit resolver: %w", err)
	}
	return result, nil
}
