package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/domain"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const EngineVersion = "fingerprint/1.0.0"

type Rule struct {
	SchemaVersion int         `yaml:"schema_version"`
	ID            string      `yaml:"id"`
	Version       string      `yaml:"version"`
	Status        string      `yaml:"status"`
	DeviceClass   string      `yaml:"device_class"`
	Vendor        string      `yaml:"vendor"`
	ProductFamily string      `yaml:"product_family"`
	Model         string      `yaml:"model"`
	Required      []Predicate `yaml:"required"`
	Positive      []Predicate `yaml:"positive"`
	Negative      []Predicate `yaml:"negative"`
	Explanation   string      `yaml:"explanation"`
	Author        string      `yaml:"author"`
	Source        string      `yaml:"source"`
	CreatedAt     string      `yaml:"created_at"`
	UpdatedAt     string      `yaml:"updated_at"`
	Tests         []Fixture   `yaml:"tests"`
}
type Fixture struct {
	Name        string         `yaml:"name"`
	ShouldMatch bool           `yaml:"should_match"`
	SourceType  string         `yaml:"source_type"`
	Fields      map[string]any `yaml:"fields"`
}
type Predicate struct {
	SourceType  string  `yaml:"source_type"`
	FieldPath   string  `yaml:"field_path"`
	Operator    string  `yaml:"operator"`
	Value       any     `yaml:"value"`
	Weight      float64 `yaml:"weight"`
	Explanation string  `yaml:"explanation"`
	re          *regexp.Regexp
}
type Compiled struct {
	Rules    []Rule
	Digest   string
	LoadedAt time.Time
}
type Engine struct {
	current        atomic.Pointer[Compiled]
	ambiguityDelta float64
}

func New(delta float64) *Engine { return &Engine{ambiguityDelta: delta} }

var allowedOps = map[string]bool{"equals": true, "contains": true, "prefix": true, "suffix": true, "regex": true, "exists": true, "in": true, "gt": true, "gte": true, "lt": true, "lte": true, "port_present": true, "service_present": true}
var allowedFields = map[string]bool{"tcp.port": true, "banner.text": true, "http.status": true, "http.title": true, "http.header.server": true, "http.header.www_authenticate": true, "tls.subject": true, "tls.issuer": true, "tls.san": true, "tls.fingerprint": true, "mdns.service": true, "mdns.instance": true, "ssdp.server": true, "ssdp.st": true, "neighbor.mac": true, "neighbor.oui": true, "imported_nmap.service": true, "imported_nmap.product": true, "imported_nmap.version": true}

func LoadPaths(paths []string) (*Compiled, error) {
	var files []string
	for _, p := range paths {
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				files = append(files, filepath.Join(p, e.Name()))
			}
		}
	}
	sort.Strings(files)
	if len(files) > 10000 {
		return nil, errors.New("too many rules")
	}
	h := sha256.New()
	c := &Compiled{LoadedAt: time.Now().UTC()}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if len(b) > 1<<20 {
			return nil, fmt.Errorf("rule %s exceeds 1 MiB", f)
		}
		h.Write(b)
		var r Rule
		d := yaml.NewDecoder(strings.NewReader(string(b)))
		d.KnownFields(true)
		if err = d.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		var extra any
		if err = d.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("%s: exactly one YAML document required", f)
		}
		if err = validate(&r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		c.Rules = append(c.Rules, r)
	}
	c.Digest = hex.EncodeToString(h.Sum(nil))
	return c, nil
}
func validate(r *Rule) error {
	if r.SchemaVersion != 1 || r.ID == "" || r.Version == "" {
		return errors.New("schema_version 1, id, and version required")
	}
	if r.Status != "active" && r.Status != "deprecated" && r.Status != "experimental" {
		return errors.New("invalid status")
	}
	for _, list := range []*[]Predicate{&r.Required, &r.Positive, &r.Negative} {
		if len(*list) > 100 {
			return errors.New("too many predicates")
		}
		for i := range *list {
			p := &(*list)[i]
			if !allowedOps[p.Operator] || !allowedFields[p.FieldPath] {
				return fmt.Errorf("unsupported predicate %s %s", p.FieldPath, p.Operator)
			}
			if p.Operator == "regex" {
				s, ok := p.Value.(string)
				if !ok || len(s) > 1024 {
					return errors.New("regex must be bounded string")
				}
				re, err := regexp.Compile(s)
				if err != nil {
					return err
				}
				p.re = re
			}
		}
	}
	return nil
}
func (e *Engine) Reload(paths []string) error {
	c, err := LoadPaths(paths)
	if err != nil {
		return err
	}
	e.current.Store(c)
	return nil
}
func (e *Engine) Current() *Compiled { return e.current.Load() }
func (e *Engine) IsAmbiguous(c []domain.FingerprintCandidate) bool {
	return len(c) > 1 && c[0].Score-c[1].Score <= e.ambiguityDelta
}

func TestCompiled(c *Compiled) error {
	for _, r := range c.Rules {
		for _, f := range r.Tests {
			ev := []Evidence{{ObservationID: "fixture:" + f.Name, Source: domain.ObservationSource(f.SourceType), ObservedAt: time.Now().UTC(), Fields: f.Fields}}
			_, matched := evaluateRule("fixture", r, ev)
			if matched != f.ShouldMatch {
				return fmt.Errorf("rule %s fixture %s: matched=%v want=%v", r.ID, f.Name, matched, f.ShouldMatch)
			}
		}
	}
	return nil
}

type Evidence struct {
	ObservationID string
	Source        domain.ObservationSource
	ObservedAt    time.Time
	Fields        map[string]any
}

func (e *Engine) Evaluate(assetID string, ev []Evidence) []domain.FingerprintCandidate {
	c := e.current.Load()
	if c == nil {
		return nil
	}
	out := []domain.FingerprintCandidate{}
	for _, r := range c.Rules {
		if r.Status == "deprecated" {
			continue
		}
		cand, ok := evaluateRule(assetID, r, ev)
		if ok {
			out = append(out, cand)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
func evaluateRule(assetID string, r Rule, ev []Evidence) (domain.FingerprintCandidate, bool) {
	cand := domain.FingerprintCandidate{AssetID: assetID, RuleID: r.ID, RuleVersion: r.Version, DeviceClass: r.DeviceClass, Vendor: r.Vendor, ProductFamily: r.ProductFamily, Model: r.Model, Explanation: r.Explanation, EvaluatedAt: time.Now().UTC(), EngineVersion: EngineVersion}
	for _, p := range r.Required {
		m, _, _ := matchAny(p, ev)
		if !m {
			return cand, false
		}
	}
	total := 0.0
	sourceTotals := map[domain.ObservationSource]float64{}
	sources := map[domain.ObservationSource]bool{}
	for _, p := range r.Positive {
		m, id, src := matchAny(p, ev)
		if m {
			v := p.Weight
			if sourceTotals[src]+v > 0.65 {
				v = 0.65 - sourceTotals[src]
			}
			if v < 0 {
				v = 0
			}
			total += v
			sourceTotals[src] += v
			sources[src] = true
			cand.SupportingPredicates = append(cand.SupportingPredicates, p.Explanation)
			cand.ObservationIDs = appendUnique(cand.ObservationIDs, id)
			cand.Breakdown = append(cand.Breakdown, domain.ScoreContribution{Predicate: p.FieldPath + " " + p.Operator, Source: string(src), ObservationID: id, Value: v, Matched: true})
		}
	}
	for _, p := range r.Negative {
		m, id, src := matchAny(p, ev)
		if m {
			penalty := p.Weight
			if penalty < 0 {
				penalty = -penalty
			}
			total -= penalty
			cand.NegativePredicates = append(cand.NegativePredicates, p.Explanation)
			cand.Breakdown = append(cand.Breakdown, domain.ScoreContribution{Predicate: p.FieldPath + " " + p.Operator, Source: string(src), ObservationID: id, Value: -penalty, Matched: true})
		}
	}
	cand.SourceDiversity = len(sources)
	if cand.SourceDiversity >= 2 {
		total += min(.15, float64(cand.SourceDiversity-1)*.05)
	}
	if r.Model != "" {
		total += .05
	}
	freshest := time.Time{}
	for _, x := range ev {
		if x.ObservedAt.After(freshest) {
			freshest = x.ObservedAt
		}
	}
	if !freshest.IsZero() {
		age := time.Since(freshest)
		if age > 30*24*time.Hour {
			penalty := min(.25, age.Hours()/(24*365)*.25)
			total -= penalty
			cand.Breakdown = append(cand.Breakdown, domain.ScoreContribution{Predicate: "stale evidence penalty", Source: "engine", Value: -penalty, Matched: true})
		}
	}
	if total < 0 {
		total = 0
	}
	if total > 1 {
		total = 1
	}
	cand.Score = total
	return cand, total > 0
}
func matchAny(p Predicate, ev []Evidence) (bool, string, domain.ObservationSource) {
	for _, e := range ev {
		if p.SourceType != "" && p.SourceType != string(e.Source) {
			continue
		}
		v, ok := e.Fields[p.FieldPath]
		if match(p, v, ok) {
			return true, e.ObservationID, e.Source
		}
	}
	return false, "", ""
}
func match(p Predicate, v any, exists bool) bool {
	want := fmt.Sprint(p.Value)
	got := fmt.Sprint(v)
	switch p.Operator {
	case "exists":
		return exists
	case "equals":
		return exists && strings.EqualFold(got, want)
	case "contains":
		return exists && strings.Contains(strings.ToLower(got), strings.ToLower(want))
	case "prefix":
		return exists && strings.HasPrefix(strings.ToLower(got), strings.ToLower(want))
	case "suffix":
		return exists && strings.HasSuffix(strings.ToLower(got), strings.ToLower(want))
	case "regex":
		return exists && p.re.MatchString(got)
	case "in":
		b, _ := json.Marshal(p.Value)
		var values []any
		if json.Unmarshal(b, &values) != nil {
			return false
		}
		for _, x := range values {
			if strings.EqualFold(fmt.Sprint(x), got) {
				return true
			}
		}
		return false
	case "gt", "gte", "lt", "lte":
		gv, e1 := strconv.ParseFloat(got, 64)
		wv, e2 := strconv.ParseFloat(want, 64)
		if e1 != nil || e2 != nil {
			return false
		}
		switch p.Operator {
		case "gt":
			return gv > wv
		case "gte":
			return gv >= wv
		case "lt":
			return gv < wv
		default:
			return gv <= wv
		}
	case "port_present":
		return exists && got == want
	case "service_present":
		return exists && strings.EqualFold(got, want)
	}
	return false
}
func appendUnique(v []string, s string) []string {
	for _, x := range v {
		if x == s {
			return v
		}
	}
	return append(v, s)
}
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
