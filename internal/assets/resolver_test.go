package assets

import (
	"context"
	"github.com/cortalabs/cortasentry/internal/domain"
	"net/netip"
	"testing"
	"time"
)

type mem struct {
	assets     map[string]domain.Asset
	lookup     map[string][]string
	continuity []string
	n          int
}

func (m *mem) FindContinuityAssets(context.Context, string, string, time.Time) ([]string, error) {
	return m.continuity, nil
}

func TestNewStrongIdentityNeverUsesAddressContinuity(t *testing.T) {
	m := &mem{assets: map[string]domain.Asset{"old": {}}, lookup: map[string][]string{}, continuity: []string{"old"}}
	r := New(m)
	x, err := r.Resolve(context.Background(), obs("10.0.0.1"), []domain.Identifier{{Type: "mac", Value: "new-mac", Strength: "strong"}, {Type: "service_set", Value: "same", Strength: "contextual"}})
	if err != nil {
		t.Fatal(err)
	}
	if x.AssetID == "old" || !x.Created {
		t.Fatalf("new strong identity was false-merged through continuity: %#v", x)
	}
}

func TestPartialStrongAgreementCreatesConflict(t *testing.T) {
	m := &mem{assets: map[string]domain.Asset{"old": {}}, lookup: map[string][]string{"serial_number:known": {"old"}}}
	r := New(m)
	x, err := r.Resolve(context.Background(), obs("10.0.0.1"), []domain.Identifier{{Type: "serial_number", Value: "known"}, {Type: "mac", Value: "contradiction"}})
	if err != nil || !x.Created || !x.Conflict || x.AssetID == "old" {
		t.Fatalf("partial strong match did not preserve conflict: %#v err=%v", x, err)
	}
}

func (m *mem) FindAssetsByIdentifier(_ context.Context, k, v string) ([]string, error) {
	return m.lookup[k+":"+v], nil
}
func (m *mem) CreateAsset(_ context.Context, a *domain.Asset) error {
	m.n++
	a.ID = string(rune('a' + m.n))
	m.assets[a.ID] = *a
	return nil
}
func (m *mem) AttachObservation(context.Context, string, domain.Observation, string, bool) error {
	return nil
}
func (m *mem) AddIdentifier(_ context.Context, a string, id domain.Identifier) error {
	if id.Strength == "strong" {
		m.lookup[id.Type+":"+id.Value] = append(m.lookup[id.Type+":"+id.Value], a)
	}
	return nil
}
func (m *mem) Audit(context.Context, domain.AuditEvent) error { return nil }
func obs(ip string) domain.Observation {
	return domain.Observation{ID: "o", ObservedAt: time.Now(), TargetIP: netip.MustParseAddr(ip)}
}
func TestStrongAgreementNewIP(t *testing.T) {
	m := &mem{assets: map[string]domain.Asset{}, lookup: map[string][]string{}}
	r := New(m)
	x, _ := r.Resolve(context.Background(), obs("10.0.0.1"), []domain.Identifier{{Type: "mac", Value: "aa"}})
	y, _ := r.Resolve(context.Background(), obs("10.0.0.2"), []domain.Identifier{{Type: "mac", Value: "aa"}})
	if x.AssetID != y.AssetID || y.Created {
		t.Fatalf("did not preserve identity: %#v %#v", x, y)
	}
}
func TestWeakEvidenceNeverMerges(t *testing.T) {
	for _, kind := range []string{"hostname", "tls_certificate", "ip"} {
		m := &mem{assets: map[string]domain.Asset{}, lookup: map[string][]string{}}
		r := New(m)
		x, _ := r.Resolve(context.Background(), obs("10.0.0.1"), []domain.Identifier{{Type: kind, Value: "shared"}})
		y, _ := r.Resolve(context.Background(), obs("10.0.0.1"), []domain.Identifier{{Type: kind, Value: "shared"}})
		if x.AssetID == y.AssetID {
			t.Fatalf("%s caused merge", kind)
		}
	}
}
func TestConflictingStrongIdentifiers(t *testing.T) {
	m := &mem{assets: map[string]domain.Asset{}, lookup: map[string][]string{"mac:aa": {"one"}, "serial_number:s": {"two"}}}
	r := New(m)
	x, err := r.Resolve(context.Background(), obs("10.0.0.1"), []domain.Identifier{{Type: "mac", Value: "aa"}, {Type: "serial_number", Value: "s"}})
	if err != nil || !x.Conflict || !x.Created {
		t.Fatalf("expected safe conflict: %#v %v", x, err)
	}
}
