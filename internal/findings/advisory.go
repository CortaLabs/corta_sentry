package findings

import (
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/domain"
	"strings"
)

type Advisory struct {
	ID, Vendor, ProductFamily, Severity, Remediation, RuleDigest string
	AffectedVersions                                             []string
	RequiredEvidence                                             []string
}
type Evidence struct {
	Vendor, ProductFamily, Firmware                 string
	ProductConfirmed, VersionInRange, SafeValidated bool
}

func Correlate(a Advisory, assetID string, e Evidence) (domain.Finding, error) {
	if a.ID == "" || a.Vendor == "" {
		return domain.Finding{}, errors.New("invalid advisory")
	}
	if !strings.EqualFold(a.Vendor, e.Vendor) {
		return domain.Finding{}, errors.New("vendor does not match")
	}
	state := domain.FindingPotential
	score := .25
	if e.ProductConfirmed && strings.EqualFold(a.ProductFamily, e.ProductFamily) {
		state = domain.FindingLikely
		score = .55
	}
	if e.ProductConfirmed && e.Firmware != "" && e.VersionInRange {
		state = domain.FindingVersionConfirmed
		score = .85
	}
	if e.SafeValidated {
		if state != domain.FindingVersionConfirmed {
			return domain.Finding{}, fmt.Errorf("safe validation requires confirmed affected version")
		}
		state = domain.FindingSafelyValidated
		score = 1
	}
	return domain.Finding{AssetID: assetID, AdvisoryID: a.ID, State: state, Severity: a.Severity, EvidenceScore: score, Remediation: a.Remediation, RuleDigest: a.RuleDigest, Source: "local_advisory_rule"}, nil
}
