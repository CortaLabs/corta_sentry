package api

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/cortalabs/cortasentry/internal/assets"
	"github.com/cortalabs/cortasentry/internal/auth"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/discovery"
	"github.com/cortalabs/cortasentry/internal/findings"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a := auth.New(s.DB(), false)
	token, err := a.Bootstrap(context.Background(), filepath.Join(t.TempDir(), "token"))
	if err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Scope.ActiveEnabled = true
	c.Scope.AllowedCIDRs = []string{"127.0.0.1/32"}
	sc, _ := scope.New(c.Scope, s)
	rules := fingerprint.New(.1)
	dial := discovery.NewAuthorizedDialer(sc, c.Limits.ConnectTimeout, 50, 5)
	scan := discovery.NewScanner(dial, s, assets.New(s), rules, 1, 1024, 10, 500000000)
	return New(s, a, sc, scan, rules, findings.NewEngine(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil), token
}
func TestAPIRequiresAuthAndCSRF(t *testing.T) {
	s, token := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/assets", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	body, _ := json.Marshal(map[string]string{"token": token})
	r = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	r = httptest.NewRequest("POST", "/api/v1/rules/reload", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF got %d", w.Code)
	}
}
func TestOversizedLoginBody(t *testing.T) {
	s, _ := testServer(t)
	r := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(make([]byte, 5000)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 && w.Code != 413 {
		t.Fatal(w.Code)
	}
}
func TestSessionRefreshIssuesNewCSRF(t *testing.T) {
	s, token := testServer(t)
	body, _ := json.Marshal(map[string]string{"token": token})
	login := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	lw := httptest.NewRecorder()
	s.Handler().ServeHTTP(lw, login)
	if lw.Code != 200 {
		t.Fatal(lw.Code)
	}
	cookie := lw.Result().Cookies()[0]
	req := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("csrf_token")) {
		t.Fatalf("refresh %d %s", w.Code, w.Body.String())
	}
}

func TestEmptyJobsIsJSONArray(t *testing.T) {
	s, token := testServer(t)
	body, _ := json.Marshal(map[string]string{"token": token})
	login := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	lw := httptest.NewRecorder()
	s.Handler().ServeHTTP(lw, login)
	req := httptest.NewRequest("GET", "/api/v1/jobs", nil)
	req.AddCookie(lw.Result().Cookies()[0])
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("jobs response %d %q", w.Code, w.Body.String())
	}
}

var _ = http.MethodGet
