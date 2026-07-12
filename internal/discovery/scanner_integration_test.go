package discovery_test

import (
	"context"
	"github.com/cortalabs/cortasentry/internal/assets"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/discovery"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/fixtures"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureCollectorsAndRepeatContinuity(t *testing.T) {
	lab, err := fixtures.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	portsMap := lab.Ports()
	ports := make([]int, 0, len(portsMap))
	for _, p := range portsMap {
		ports = append(ports, p)
	}
	cfg := config.Default()
	cfg.Scope.ActiveEnabled = true
	cfg.Scope.AllowedCIDRs = []string{"127.0.0.1/32"}
	cfg.Scope.AllowedPorts = ports
	cfg.Scope.MaxPortsPerHost = len(ports)
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sc, err := scope.New(cfg.Scope, store)
	if err != nil {
		t.Fatal(err)
	}
	rules := fingerprint.New(.1)
	if err = rules.Reload([]string{filepath.Join("..", "..", "rules", "devices")}); err != nil {
		t.Fatal(err)
	}
	dial := discovery.NewAuthorizedDialer(sc, 100*time.Millisecond, 100, 20)
	scanner := discovery.NewScanner(dial, store, assets.New(store), rules, 4, 65536, 100, 2*time.Second)
	for name, p := range portsMap {
		aa, pp, err := sc.ValidateJob([]string{"127.0.0.1"}, []int{p})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = scanner.Run(context.Background(), "fixture-"+name, aa, pp, "fixture:"+name); err != nil {
			t.Fatal(err)
		}
	}
	obs, err := store.ListObservations(context.Background(), "", "", "", 500, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, o := range obs {
		seen[string(o.Source)] = true
	}
	for _, want := range []string{"tcp_connect", "http", "banner", "tls"} {
		if !seen[want] {
			t.Fatalf("collector %s missing; seen=%v", want, seen)
		}
	}
	p := portsMap["samsung"]
	aa, pp, _ := sc.ValidateJob([]string{"127.0.0.1"}, []int{p})
	if _, err = scanner.Run(context.Background(), "normal-1", aa, pp, ""); err != nil {
		t.Fatal(err)
	}
	before, _ := store.ListAssets(context.Background(), "", "", "", 500, 0)
	if _, err = scanner.Run(context.Background(), "normal-2", aa, pp, ""); err != nil {
		t.Fatal(err)
	}
	after, _ := store.ListAssets(context.Background(), "", "", "", 500, 0)
	if len(after) != len(before) {
		t.Fatalf("repeat scan fragmented asset count %d -> %d", len(before), len(after))
	}
}
