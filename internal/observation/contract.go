package observation

import (
	"encoding/json"

	"github.com/cortalabs/cortasentry/internal/domain"
)

const ContractVersion = "cortasentry.observation.v1"

type Envelope struct {
	SchemaVersion    string                   `json:"schema_version"`
	ObservationID    string                   `json:"observation_id"`
	SensorID         string                   `json:"sensor_id"`
	JobID            string                   `json:"job_id,omitempty"`
	AssetID          string                   `json:"asset_id,omitempty"`
	ObservedAt       string                   `json:"observed_at"`
	IngestedAt       string                   `json:"ingested_at"`
	Source           domain.ObservationSource `json:"source"`
	TargetIP         string                   `json:"target_ip"`
	TargetPort       int                      `json:"target_port,omitempty"`
	Transport        string                   `json:"transport,omitempty"`
	Application      string                   `json:"application,omitempty"`
	Evidence         json.RawMessage          `json:"evidence"`
	RawDigest        string                   `json:"raw_evidence_digest,omitempty"`
	CollectorVersion string                   `json:"collector_version"`
	PolicyDecisionID string                   `json:"policy_decision_id,omitempty"`
	Truncated        bool                     `json:"truncated"`
	Provenance       json.RawMessage          `json:"provenance"`
}

func Contract(o domain.Observation) Envelope {
	return Envelope{SchemaVersion: ContractVersion, ObservationID: o.ID, SensorID: o.SensorID, JobID: o.JobID, AssetID: o.AssetID, ObservedAt: o.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), IngestedAt: o.IngestedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), Source: o.Source, TargetIP: o.TargetIP.Unmap().String(), TargetPort: o.TargetPort, Transport: o.Transport, Application: o.Application, Evidence: o.Evidence, RawDigest: o.RawDigest, CollectorVersion: o.CollectorVersion, PolicyDecisionID: o.PolicyDecisionID, Truncated: o.Truncated, Provenance: o.Provenance}
}
