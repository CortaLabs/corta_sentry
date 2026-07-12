package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/cortalabs/cortasentry/internal/domain"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type Rule struct {
	SchemaVersion        int      `yaml:"schema_version"`
	ID                   string   `yaml:"id"`
	RuleVersion          string   `yaml:"rule_version"`
	FixtureOnly          bool     `yaml:"fixture_only"`
	Vendor               string   `yaml:"vendor"`
	ProductFamily        string   `yaml:"product_family"`
	Models               []string `yaml:"models"`
	AffectedVersions     []string `yaml:"affected_versions"`
	Severity             string   `yaml:"severity"`
	References           []string `yaml:"references"`
	RequiredEvidence     []string `yaml:"required_evidence"`
	SafeValidationStatus string   `yaml:"safe_validation_status"`
	Remediation          string   `yaml:"remediation"`
	Digest               string   `yaml:"-"`
	constraints          []*semver.Constraints
}
type Bundle struct {
	Rules    []Rule
	Digest   string
	LoadedAt time.Time
}
type Engine struct{ current atomic.Pointer[Bundle] }

func NewEngine() *Engine           { return &Engine{} }
func (e *Engine) Current() *Bundle { return e.current.Load() }
func (e *Engine) Reload(paths []string) error {
	b, err := LoadPaths(paths)
	if err != nil {
		return err
	}
	e.current.Store(b)
	return nil
}
func LoadPaths(paths []string) (*Bundle, error) {
	var files []string
	for _, p := range paths {
		es, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, x := range es {
			if !x.IsDir() && (strings.HasSuffix(x.Name(), ".yaml") || strings.HasSuffix(x.Name(), ".yml")) {
				files = append(files, filepath.Join(p, x.Name()))
			}
		}
	}
	sort.Strings(files)
	h := sha256.New()
	out := &Bundle{LoadedAt: time.Now().UTC()}
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if len(raw) > 1<<20 {
			return nil, fmt.Errorf("advisory %s too large", p)
		}
		h.Write(raw)
		var r Rule
		d := yaml.NewDecoder(strings.NewReader(string(raw)))
		d.KnownFields(true)
		if err = d.Decode(&r); err != nil {
			return nil, err
		}
		var extra any
		if err = d.Decode(&extra); err != io.EOF {
			return nil, errors.New("advisory must contain one YAML document")
		}
		if r.SchemaVersion != 1 || r.ID == "" || r.RuleVersion == "" || r.Vendor == "" || r.Severity == "" {
			return nil, fmt.Errorf("invalid advisory %s", p)
		}
		sum := sha256.Sum256(raw)
		r.Digest = hex.EncodeToString(sum[:])
		for _, expr := range r.AffectedVersions {
			c, err := semver.NewConstraint(expr)
			if err != nil {
				return nil, fmt.Errorf("%s version constraint: %w", r.ID, err)
			}
			r.constraints = append(r.constraints, c)
		}
		out.Rules = append(out.Rules, r)
	}
	out.Digest = hex.EncodeToString(h.Sum(nil))
	return out, nil
}
func (e *Engine) Evaluate(a domain.Asset) []domain.Finding {
	b := e.current.Load()
	if b == nil {
		return nil
	}
	var out []domain.Finding
	for _, r := range b.Rules {
		if !strings.EqualFold(r.Vendor, a.Vendor) {
			continue
		}
		ev := Evidence{Vendor: a.Vendor, ProductFamily: a.ProductFamily, Firmware: a.Firmware, ProductConfirmed: a.ProductFamily != "" && strings.EqualFold(r.ProductFamily, a.ProductFamily)}
		if ev.ProductConfirmed && a.Firmware != "" {
			if v, err := semver.NewVersion(a.Firmware); err == nil {
				for _, c := range r.constraints {
					if c.Check(v) {
						ev.VersionInRange = true
						break
					}
				}
			}
		}
		f, err := Correlate(Advisory{ID: r.ID, Vendor: r.Vendor, ProductFamily: r.ProductFamily, Severity: r.Severity, Remediation: r.Remediation, RuleDigest: r.Digest, AffectedVersions: r.AffectedVersions}, a.ID, ev)
		if err == nil {
			f.ID = ""
			f.FirstSeen = time.Now().UTC()
			f.LastEvaluated = f.FirstSeen
			out = append(out, f)
		}
	}
	return out
}
