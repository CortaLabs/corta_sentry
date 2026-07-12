package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExampleRoundTrip(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.yaml")
	c := Default()
	c.Server.DataDir = filepath.Join(d, "data")
	c.Server.Database = filepath.Join(d, "data", "db")
	if err := Write(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope.MaxHostsPerJob != 256 || got.Limits.MaxBannerBytes != 8192 || got.Server.DataDir != c.Server.DataDir {
		t.Fatalf("roundtrip lost fields: %#v", got)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", fi.Mode().Perm())
	}
}
func TestRejectUnsafeBind(t *testing.T) {
	for _, bind := range []string{"[::]:8088", "example.com:8088", "0.0.0.0:8088"} {
		c := Default()
		c.Server.Bind = bind
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %s", bind)
		}
	}
}

func TestLoadResolvesPathsFromConfigDirectory(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "cortasentry.yaml")
	if err := os.WriteFile(p, []byte("version: 1\nserver: {bind: '127.0.0.1:8088', data_dir: ./state, database: ./state/app.db}\nrules: {device_paths: [./device-rules], advisory_paths: [./advisories]}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{c.Server.DataDir: filepath.Join(d, "state"), c.Server.Database: filepath.Join(d, "state", "app.db"), c.Rules.DevicePaths[0]: filepath.Join(d, "device-rules"), c.Rules.AdvisoryPaths[0]: filepath.Join(d, "advisories")} {
		if got != want {
			t.Fatalf("resolved path %q, want %q", got, want)
		}
	}
}
