package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
)

func TestInitCustomConfigUsesConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "cortasentry.yaml")
	if err := os.MkdirAll(filepath.Join(filepath.Dir(path), "data"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := initCommand([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), "data", "admin.token")); err != nil {
		t.Fatalf("token was not created beside custom config: %v", err)
	}
	if info, statErr := os.Stat(loaded.Server.DataDir); statErr != nil {
		t.Fatal(statErr)
	} else if info.Mode().Perm() != 0700 {
		t.Fatalf("data directory mode=%v", info.Mode().Perm())
	}
	store, err := sqlite.Open(loaded.Server.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = os.Stat(loaded.Server.Database); err != nil {
		t.Fatalf("configured database missing: %v", err)
	}
}
