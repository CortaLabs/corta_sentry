package auth

import (
	"context"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapVerifyRotate(t *testing.T) {
	d := t.TempDir()
	s, err := sqlite.Open(filepath.Join(d, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s.DB(), false)
	p := filepath.Join(d, "admin.token")
	tok, err := m.Bootstrap(context.Background(), p)
	if err != nil || !m.VerifyToken(context.Background(), tok) {
		t.Fatalf("bootstrap %v", err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	next, err := m.Rotate(context.Background(), p)
	if err != nil || m.VerifyToken(context.Background(), tok) || !m.VerifyToken(context.Background(), next) {
		t.Fatalf("rotation failed %v", err)
	}
}
