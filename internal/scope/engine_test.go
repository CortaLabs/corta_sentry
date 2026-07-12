package scope

import (
	"errors"
	"github.com/cortalabs/cortasentry/internal/config"
	"testing"
)

func testEngine(t *testing.T, c config.Scope) *Engine {
	t.Helper()
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestFailClosedAndMappedIPv4(t *testing.T) {
	c := config.Default().Scope
	c.ActiveEnabled = true
	c.AllowPublicTargets = false
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	e := testEngine(t, c)
	if !e.Decide("::ffff:127.0.0.1", 80).Allowed {
		t.Fatal("mapped loopback should normalize and pass")
	}
	if e.Decide("8.8.8.8", 80).Allowed {
		t.Fatal("public out-of-scope target passed")
	}
	c.ActiveEnabled = false
	e = testEngine(t, c)
	if e.Decide("127.0.0.1", 80).Allowed {
		t.Fatal("disabled probing passed")
	}
}
func TestDenyPrecedenceAndPortBudget(t *testing.T) {
	c := config.Default().Scope
	c.ActiveEnabled = true
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	c.DeniedCIDRs = []string{"127.0.0.2/32"}
	e := testEngine(t, c)
	if e.Decide("127.0.0.2", 80).Allowed {
		t.Fatal("deny must win")
	}
	if e.Decide("127.0.0.1", 81).Allowed {
		t.Fatal("unlisted port passed")
	}
	c.MaxPortsPerHost = 1
	e = testEngine(t, c)
	if _, _, err := e.ValidateJob([]string{"127.0.0.1"}, []int{80, 443}); err == nil {
		t.Fatal("expected budget error")
	}
}
func TestNormalizeMalformed(t *testing.T) {
	for _, s := range []string{"", "127.1", "1.2.3.4/24", "[::1]"} {
		if _, err := NormalizeAddr(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestMappedPrefixTooBroad(t *testing.T) {
	if _, err := parsePrefix("::ffff:0:0/80"); err == nil {
		t.Fatal("accepted mapped prefix broader than /96")
	}
}
func TestExpandPrefix(t *testing.T) {
	v, err := ExpandPrefix("127.0.0.0/30", 4)
	if err != nil || len(v) != 2 {
		t.Fatalf("/30=%v err=%v", v, err)
	}
	v, err = ExpandPrefix("127.0.0.0/31", 2)
	if err != nil || len(v) != 2 {
		t.Fatalf("/31=%v err=%v", v, err)
	}
	if _, err = ExpandPrefix("10.0.0.0/8", 256); err == nil {
		t.Fatal("huge prefix accepted")
	}
}

type failingAudit struct{}

func (failingAudit) ScopeDecision(Decision) error { return errors.New("disk full") }
func TestAuditFailureDeniesProbe(t *testing.T) {
	c := config.Default().Scope
	c.ActiveEnabled = true
	c.AllowedCIDRs = []string{"127.0.0.1/32"}
	e, err := New(c, failingAudit{})
	if err != nil {
		t.Fatal(err)
	}
	d := e.Decide("127.0.0.1", 80)
	if d.Allowed || d.Reason != "authorization audit persistence failed" {
		t.Fatalf("decision=%#v", d)
	}
}
