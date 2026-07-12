package findings

import (
	"github.com/cortalabs/cortasentry/internal/domain"
	"testing"
)

func TestStateCeilings(t *testing.T) {
	a := Advisory{ID: "X", Vendor: "Acme", ProductFamily: "Cam"}
	f, _ := Correlate(a, "a", Evidence{Vendor: "Acme"})
	if f.State != domain.FindingPotential {
		t.Fatal(f.State)
	}
	f, _ = Correlate(a, "a", Evidence{Vendor: "Acme", ProductFamily: "Cam", ProductConfirmed: true})
	if f.State != domain.FindingLikely {
		t.Fatal(f.State)
	}
	f, _ = Correlate(a, "a", Evidence{Vendor: "Acme", ProductFamily: "Cam", ProductConfirmed: true, Firmware: "1", VersionInRange: true})
	if f.State != domain.FindingVersionConfirmed {
		t.Fatal(f.State)
	}
	if _, err := Correlate(a, "a", Evidence{Vendor: "Acme", SafeValidated: true}); err == nil {
		t.Fatal("unsafe state elevation")
	}
}
