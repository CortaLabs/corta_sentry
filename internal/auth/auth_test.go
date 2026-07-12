package auth

import (
	"context"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	next, err = m.Rotate(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if m.VerifyToken(context.Background(), tok) {
		t.Fatal("original token survived rotation")
	}
	fi, _ = os.Stat(p)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("rotation preserved unsafe mode %o", fi.Mode().Perm())
	}
}

func TestBrowserOriginAllowed(t *testing.T) {
	for _, tc := range []struct {
		origin, site string
		allowed      bool
	}{{"", "", true}, {"https://console.example", "same-origin", true}, {"https://evil.example", "same-site", false}, {"https://console.example", "cross-site", false}, {"null", "", false}} {
		r := httptest.NewRequest("POST", "https://console.example/api/v1/scans", nil)
		r.Host = "console.example"
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.site != "" {
			r.Header.Set("Sec-Fetch-Site", tc.site)
		}
		if got := BrowserOriginAllowed(r); got != tc.allowed {
			t.Fatalf("origin=%q site=%q got=%v", tc.origin, tc.site, got)
		}
	}
}

func TestSecureCookieSetAndClear(t *testing.T) {
	m := &Manager{secure: true}
	for _, clear := range []bool{false, true} {
		w := httptest.NewRecorder()
		if clear {
			m.ClearCookie(w)
		} else {
			m.SetCookie(w, "secret")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie=%#v", cookies)
		}
	}
}

func TestAuthenticationReturnsDurableActorIDs(t *testing.T) {
	d := t.TempDir()
	s, err := sqlite.Open(filepath.Join(d, "actors.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s.DB(), false)
	token, err := m.Bootstrap(context.Background(), filepath.Join(d, "token"))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	actor, ok := m.Authenticate(r)
	if !ok || !strings.HasPrefix(actor, "token:") {
		t.Fatalf("bearer actor=%q ok=%v", actor, ok)
	}
	session, _, err := m.Login(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: session})
	actor, ok = m.Authenticate(r)
	if !ok || !strings.HasPrefix(actor, "session:") {
		t.Fatalf("session actor=%q ok=%v", actor, ok)
	}
}
