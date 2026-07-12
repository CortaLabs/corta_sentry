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
	store, err := sqlite.Open(loaded.Server.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = os.Stat(loaded.Server.Database); err != nil {
		t.Fatalf("configured database missing: %v", err)
	}
}
