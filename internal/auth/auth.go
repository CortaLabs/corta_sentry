package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const CookieName = "cortasentry_session"

type Manager struct {
	db     *sql.DB
	secure bool
}

func New(db *sql.DB, secure bool) *Manager { return &Manager{db: db, secure: secure} }
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hash(s string) []byte { v := sha256.Sum256([]byte(s)); return v[:] }
func writeSecret(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".admin-token-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.WriteString(token + "\n")
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
func (m *Manager) Bootstrap(ctx context.Context, secretPath string) (string, error) {
	var n int
	if err := m.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_tokens WHERE revoked_at IS NULL").Scan(&n); err != nil {
		return "", err
	}
	if n > 0 {
		return "", errors.New("administrator token already initialized")
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	if err = writeSecret(secretPath, token); err != nil {
		return "", err
	}
	_, err = m.db.ExecContext(ctx, "INSERT INTO auth_tokens(id,token_hash,created_at) VALUES(?,?,?)", uuid.Must(uuid.NewV7()).String(), hash(token), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		_ = os.Remove(secretPath)
		return "", err
	}
	return token, nil
}
func (m *Manager) VerifyToken(ctx context.Context, token string) bool {
	return m.VerifyTokenID(ctx, token) != ""
}
func (m *Manager) VerifyTokenID(ctx context.Context, token string) string {
	if len(token) < 32 || len(token) > 256 {
		return ""
	}
	rows, err := m.db.QueryContext(ctx, "SELECT id,token_hash FROM auth_tokens WHERE revoked_at IS NULL")
	if err != nil {
		return ""
	}
	defer rows.Close()
	h := hash(token)
	for rows.Next() {
		var id string
		var got []byte
		if rows.Scan(&id, &got) == nil && subtle.ConstantTimeCompare(h, got) == 1 {
			return id
		}
	}
	return ""
}
func (m *Manager) Login(ctx context.Context, token string) (session, csrf string, err error) {
	if !m.VerifyToken(ctx, token) {
		return "", "", errors.New("invalid credentials")
	}
	session, err = randomToken()
	if err != nil {
		return
	}
	csrf, err = randomToken()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	_, _ = m.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<? OR revoked_at IS NOT NULL", now.Format(time.RFC3339Nano))
	_, err = m.db.ExecContext(ctx, "INSERT INTO sessions(id,token_hash,csrf_hash,created_at,expires_at) VALUES(?,?,?,?,?)", uuid.Must(uuid.NewV7()).String(), hash(session), hash(csrf), now.Format(time.RFC3339Nano), now.Add(12*time.Hour).Format(time.RFC3339Nano))
	return
}
func (m *Manager) Authenticate(r *http.Request) (string, bool) {
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		if id := m.VerifyTokenID(r.Context(), strings.TrimPrefix(v, "Bearer ")); id != "" {
			return "token:" + id, true
		}
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", false
	}
	var id, expires string
	var revoked sql.NullString
	err = m.db.QueryRowContext(r.Context(), "SELECT id,expires_at,revoked_at FROM sessions WHERE token_hash=?", hash(c.Value)).Scan(&id, &expires, &revoked)
	if err != nil || revoked.Valid {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, expires)
	return "session:" + id, err == nil && time.Now().Before(t)
}
func (m *Manager) CheckCSRF(r *http.Request) bool {
	kind, ok := m.Authenticate(r)
	if !ok {
		return false
	}
	if strings.HasPrefix(kind, "token:") {
		return true
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		return false
	}
	var expected []byte
	if m.db.QueryRowContext(r.Context(), "SELECT csrf_hash FROM sessions WHERE token_hash=? AND revoked_at IS NULL", hash(c.Value)).Scan(&expected) != nil {
		return false
	}
	return subtle.ConstantTimeCompare(hash(provided), expected) == 1
}
func (m *Manager) RefreshCSRF(ctx context.Context, r *http.Request) (string, error) {
	kind, ok := m.Authenticate(r)
	if !ok || !strings.HasPrefix(kind, "session:") {
		return "", errors.New("valid browser session required")
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", err
	}
	res, err := m.db.ExecContext(ctx, "UPDATE sessions SET csrf_hash=? WHERE token_hash=? AND revoked_at IS NULL", hash(csrf), hash(c.Value))
	if err != nil {
		return "", err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return "", errors.New("session not found")
	}
	return csrf, nil
}
func (m *Manager) SetCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: value, Path: "/", HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 60 * 60})
}
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Path: "/", HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
func BrowserOriginAllowed(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
func (m *Manager) Logout(ctx context.Context, r *http.Request) error {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil
	}
	_, err = m.db.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE token_hash=?", time.Now().UTC().Format(time.RFC3339Nano), hash(c.Value))
	return err
}
func (m *Manager) RevokeSession(ctx context.Context, value string) error {
	_, err := m.db.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE token_hash=?", time.Now().UTC().Format(time.RFC3339Nano), hash(value))
	return err
}
func (m *Manager) Rotate(ctx context.Context, secretPath string) (string, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	id := uuid.Must(uuid.NewV7()).String()
	if _, err = m.db.ExecContext(ctx, "INSERT INTO auth_tokens(id,token_hash,created_at) VALUES(?,?,?)", id, hash(token), now); err != nil {
		return "", err
	}
	if err = writeSecret(secretPath, token); err != nil {
		_, _ = m.db.ExecContext(ctx, "DELETE FROM auth_tokens WHERE id=?", id)
		return "", err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE auth_tokens SET revoked_at=? WHERE id<>? AND revoked_at IS NULL", now, id); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL", now); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}
