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
	c.Server.AllowedHosts = []string{"example.com"}
	sc, _ := scope.New(c.Scope, s)
	rules := fingerprint.New(.1)
	dial := discovery.NewAuthorizedDialer(sc, c.Limits.ConnectTimeout, 50, 5)
	scan := discovery.NewScanner(dial, s, assets.New(s), rules, 1, 1024, 10, 500000000)
	return New(s, a, sc, scan, rules, findings.NewEngine(), nil, c.HTTPAllowedHosts(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil), token
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
	req := httptest.NewRequest("POST", "/api/v1/auth/session", nil)
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

func TestHostAndCrossOriginRejected(t *testing.T) {
	s, _ := testServer(t)
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.Host = "rebound.attacker"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("host status=%d", w.Code)
	}
	r = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader([]byte(`{"token":"not-a-token"}`)))
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("origin status=%d", w.Code)
	}
}

func TestLoginLimiterIsPerRemoteSource(t *testing.T) {
	s, _ := testServer(t)
	for i := 0; i < 5; i++ {
		if !s.allowLogin("192.0.2.1:1234") {
			t.Fatalf("source denied at burst item %d", i)
		}
	}
	if s.allowLogin("192.0.2.1:9999") {
		t.Fatal("source exceeded login burst")
	}
	if !s.allowLogin("192.0.2.2:1234") {
		t.Fatal("one source exhausted another source's login budget")
	}
}

func TestSessionRefreshIsPostOnly(t *testing.T) {
	s, _ := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET session status=%d", w.Code)
	}
}

func TestFailedLoginIsAuditedWithRequestID(t *testing.T) {
	s, _ := testServer(t)
	r := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader([]byte(`{"token":"this-is-not-a-valid-administrator-token"}`)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
	events, err := s.store.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].Action != "auth.login" || events[0].Outcome != "denied" || events[0].RequestID == "" {
		t.Fatalf("audit=%#v", events)
	}
}

var _ = http.MethodGet
