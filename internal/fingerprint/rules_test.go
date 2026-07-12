package fingerprint

import (
	"github.com/cortalabs/cortasentry/internal/domain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pred(path, op string, value any, w float64) Predicate {
	return Predicate{FieldPath: path, Operator: op, Value: value, Weight: w, Explanation: path}
}

func TestInvalidReloadKeepsActiveSet(t *testing.T) {
	d := t.TempDir()
	good := `schema_version: 1
id: good
version: 1.0.0
status: active
device_class: unknown
vendor: ""
product_family: test
required: []
positive: [{source_type: http, field_path: http.title, operator: exists, value: true, weight: 0.2, explanation: title}]
negative: []
explanation: test
author: test
source: test
created_at: 2026-01-01
updated_at: 2026-01-01
`
	p := filepath.Join(d, "rule.yaml")
	if err := os.WriteFile(p, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	e := New(.1)
	if err := e.Reload([]string{d}); err != nil {
		t.Fatal(err)
	}
	digest := e.Current().Digest
	if err := os.WriteFile(p, []byte("schema_version: 1\nid: bad\nunknown: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload([]string{d}); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if e.Current().Digest != digest {
		t.Fatal("invalid reload corrupted active rules")
	}
}
func TestNegativeDiversityAndAmbiguity(t *testing.T) {
	r := Rule{SchemaVersion: 1, ID: "x", Version: "1", Status: "active", DeviceClass: "tv", Positive: []Predicate{pred("http.title", "contains", "Samsung", .5), pred("mdns.service", "equals", "_samsungmsf._tcp", .3)}, Negative: []Predicate{pred("http.title", "contains", "emulator", .4)}}
	if err := validate(&r); err != nil {
		t.Fatal(err)
	}
	e := New(.1)
	e.current.Store(&Compiled{Rules: []Rule{r}})
	ev := []Evidence{{ObservationID: "1", Source: domain.SourceHTTP, ObservedAt: time.Now(), Fields: map[string]any{"http.title": "Samsung SmartTV emulator"}}, {ObservationID: "2", Source: domain.SourceMDNS, ObservedAt: time.Now(), Fields: map[string]any{"mdns.service": "_samsungmsf._tcp"}}}
	got := e.Evaluate("a", ev)
	if len(got) != 1 || got[0].SourceDiversity != 2 || got[0].Score >= .6 {
		t.Fatalf("unexpected %#v", got)
	}
}
