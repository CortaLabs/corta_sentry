package observation

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/cortalabs/cortasentry/internal/domain"
)

func TestContractUsesVersionedStructuredEvidence(t *testing.T) {
	now := time.Now().UTC()
	envelope := Contract(domain.Observation{ID: "id", SensorID: "sensor", ObservedAt: now, IngestedAt: now, Source: domain.SourceHostConnection, TargetIP: netip.MustParseAddr("::ffff:192.0.2.1"), Evidence: json.RawMessage(`{"state":"ESTAB"}`), CollectorVersion: "test", Provenance: json.RawMessage(`{"passive":true}`)})
	if envelope.SchemaVersion != ContractVersion || envelope.TargetIP != "192.0.2.1" {
		t.Fatalf("bad envelope %#v", envelope)
	}
	var evidence map[string]any
	if err := json.Unmarshal(envelope.Evidence, &evidence); err != nil || evidence["state"] != "ESTAB" {
		t.Fatalf("evidence was not structured: %v", err)
	}
}
