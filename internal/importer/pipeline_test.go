package importer_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cortalabs/cortasentry/internal/assets"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/discovery"
	"github.com/cortalabs/cortasentry/internal/findings"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/importer"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
)

func TestNmapImportDerivesAndReusesAsset(t *testing.T) {
	store, err := sqlite.Open(t.TempDir() + "/import.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.Default()
	scopeEngine, err := scope.New(cfg.Scope, store)
	if err != nil {
		t.Fatal(err)
	}
	rules := fingerprint.New(.1)
	scanner := discovery.NewScanner(discovery.NewAuthorizedDialer(scopeEngine, time.Millisecond, 1, 1), store, assets.New(store), rules, 1, 1024, 10, time.Second)
	sink := importer.PipelineSink{Scanner: scanner, Store: store, Advisories: findings.NewEngine()}
	xml := `<nmaprun scanner="nmap" version="7.95"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="fixture" version="1.0"/></port></ports></host></nmaprun>`
	for i := 0; i < 2; i++ {
		if count, err := importer.Nmap(context.Background(), strings.NewReader(xml), sink, false); err != nil || count != 1 {
			t.Fatalf("pass %d count=%d err=%v", i, count, err)
		}
	}
	derived, err := store.ListAssets(context.Background(), "", "", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(derived) != 1 {
		t.Fatalf("repeat import created %d assets, want one", len(derived))
	}
	observations, err := store.ListObservations(context.Background(), derived[0].ID, "imported_nmap", "", 10, 0)
	if err != nil || len(observations) != 2 {
		t.Fatalf("derived observations=%d err=%v", len(observations), err)
	}
}
