package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/auth"
	"github.com/cortalabs/cortasentry/internal/discovery"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/findings"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/importer"
	jobmanager "github.com/cortalabs/cortasentry/internal/jobs"
	observationcontract "github.com/cortalabs/cortasentry/internal/observation"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	store        *sqlite.Store
	auth         *auth.Manager
	scope        *scope.Engine
	scanner      *discovery.Scanner
	rules        *fingerprint.Engine
	rulePaths    []string
	log          *slog.Logger
	mux          *http.ServeMux
	loginRates   map[string]*rate.Limiter
	loginMu      sync.Mutex
	allowedHosts map[string]bool
	scanRate     *rate.Limiter
	jobManager   *jobmanager.Manager
	importSink   importer.Sink
}

func New(store *sqlite.Store, a *auth.Manager, sc *scope.Engine, scanner *discovery.Scanner, rules *fingerprint.Engine, advisories *findings.Engine, rulePaths, allowedHosts []string, log *slog.Logger, jobs *jobmanager.Manager) *Server {
	hosts := map[string]bool{}
	for _, host := range allowedHosts {
		hosts[strings.ToLower(strings.TrimSpace(host))] = true
	}
	s := &Server{store: store, auth: a, scope: sc, scanner: scanner, rules: rules, rulePaths: rulePaths, log: log, mux: http.NewServeMux(), loginRates: map[string]*rate.Limiter{}, allowedHosts: hosts, scanRate: rate.NewLimiter(rate.Every(time.Second), 3), jobManager: jobs, importSink: importer.PipelineSink{Scanner: scanner, Store: store, Advisories: advisories}}
	s.routes()
	return s
}
func (s *Server) Handler() http.Handler { return s.requestID(s.hostGuard(s.securityHeaders(s.mux))) }
func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.DB().PingContext(r.Context()); err != nil {
			problem(w, 503, "not_ready", err.Error())
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
	})
	m.Handle("GET /metrics", promhttp.Handler())
	m.HandleFunc("POST /api/v1/auth/login", s.login)
	m.HandleFunc("POST /api/v1/auth/session", s.session)
	m.HandleFunc("POST /api/v1/auth/logout", s.protect(s.logout, true))
	m.HandleFunc("GET /api/v1/assets", s.protect(s.assets, false))
	m.HandleFunc("GET /api/v1/overview", s.protect(func(w http.ResponseWriter, r *http.Request) {
		v, err := s.store.GetOverview(r.Context())
		respond(w, v, err)
	}, false))
	m.HandleFunc("GET /api/v1/status", s.protect(func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"scope": s.scope.Summary(), "rules_loaded": s.rules.Current() != nil})
	}, false))
	m.HandleFunc("GET /api/v1/assets/{id}", s.protect(s.asset, false))
	m.HandleFunc("GET /api/v1/assets/{id}/observations", s.protect(s.assetObservations, false))
	m.HandleFunc("GET /api/v1/assets/{id}/changes", s.protect(s.assetChanges, false))
	m.HandleFunc("GET /api/v1/assets/{id}/findings", s.protect(s.assetFindings, false))
	m.HandleFunc("GET /api/v1/assets/{id}/candidates", s.protect(s.assetCandidates, false))
	m.HandleFunc("POST /api/v1/assets/merge", s.protect(s.merge, true))
	m.HandleFunc("GET /api/v1/observations", s.protect(s.observations, false))
	m.HandleFunc("GET /api/v1/observations/export", s.protect(s.exportObservations, false))
	m.HandleFunc("GET /api/v1/scans", s.protect(s.jobs, false))
	m.HandleFunc("POST /api/v1/scans", s.protect(s.scan, true))
	m.HandleFunc("POST /api/v1/scans/preview", s.protect(s.scanPreview, false))
	m.HandleFunc("POST /api/v1/scans/{id}/cancel", s.protect(s.cancel, true))
	m.HandleFunc("GET /api/v1/jobs", s.protect(s.jobs, false))
	m.HandleFunc("GET /api/v1/rules", s.protect(s.listRules, false))
	m.HandleFunc("POST /api/v1/rules/reload", s.protect(s.reloadRules, true))
	m.HandleFunc("GET /api/v1/findings", s.protect(s.findings, false))
	m.HandleFunc("PATCH /api/v1/findings/{id}", s.protect(s.patchFinding, true))
	m.HandleFunc("GET /api/v1/changes", s.protect(s.changes, false))
	m.HandleFunc("GET /api/v1/audit", s.protect(s.audit, false))
	m.HandleFunc("POST /api/v1/imports", s.protect(s.importData, true))
}
func (s *Server) protect(next http.HandlerFunc, csrf bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.auth.Authenticate(r)
		if !ok {
			problem(w, 401, "unauthorized", "authentication required")
			return
		}
		if csrf && !s.auth.CheckCSRF(r) {
			problem(w, 403, "csrf_failed", "valid CSRF token required for browser sessions")
			return
		}
		if csrf && !auth.BrowserOriginAllowed(r) {
			problem(w, 403, "cross_origin_denied", "cross-origin browser mutation denied")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), actorKey{}, actor))
		next(w, r)
	}
}

type actorKey struct{}

func actorFrom(r *http.Request) string {
	actor, _ := r.Context().Value(actorKey{}).(string)
	if actor == "" {
		return "admin"
	}
	return actor
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !auth.BrowserOriginAllowed(r) {
		problem(w, 403, "cross_origin_denied", "cross-origin browser login denied")
		return
	}
	if !s.allowLogin(r.RemoteAddr) {
		_ = s.store.Audit(r.Context(), domain.AuditEvent{Actor: "remote:" + remoteIP(r.RemoteAddr), Action: "auth.login", ResourceType: "session", Outcome: "rate_limited", RequestID: requestIDFrom(r.Context())})
		problem(w, 429, "rate_limited", "too many login attempts")
		return
	}
	var v struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &v, 4096); err != nil {
		return
	}
	session, csrf, err := s.auth.Login(r.Context(), v.Token)
	if err != nil {
		time.Sleep(100 * time.Millisecond)
		_ = s.store.Audit(r.Context(), domain.AuditEvent{Actor: "remote:" + remoteIP(r.RemoteAddr), Action: "auth.login", ResourceType: "session", Outcome: "denied", RequestID: requestIDFrom(r.Context())})
		problem(w, 401, "invalid_credentials", "invalid credentials")
		return
	}
	if err = s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "auth.login", ResourceType: "session", Outcome: "success", RequestID: requestIDFrom(r.Context())}); err != nil {
		_ = s.auth.RevokeSession(r.Context(), session)
		problem(w, 503, "audit_unavailable", "login audit persistence failed")
		return
	}
	s.auth.SetCookie(w, session)
	write(w, 200, map[string]string{"csrf_token": csrf})
}
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	if !auth.BrowserOriginAllowed(r) {
		problem(w, 403, "cross_origin_denied", "cross-origin session refresh denied")
		return
	}
	csrf, err := s.auth.RefreshCSRF(r.Context(), r)
	if err != nil {
		problem(w, 401, "unauthorized", "browser session unavailable")
		return
	}
	write(w, 200, map[string]string{"csrf_token": csrf})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Logout(r.Context(), r); err != nil {
		problem(w, 503, "logout_failed", "session revocation failed")
		return
	}
	s.auth.ClearCookie(w)
	if err := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "auth.logout", ResourceType: "session", Outcome: "success", RequestID: requestIDFrom(r.Context())}); err != nil {
		problem(w, 503, "audit_unavailable", "logout audit persistence failed")
		return
	}
	w.WriteHeader(204)
}
func remoteIP(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	return value
}
func (s *Server) allowLogin(remote string) bool {
	key := remoteIP(remote)
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if len(s.loginRates) >= 4096 {
		s.loginRates = map[string]*rate.Limiter{}
	}
	limiter := s.loginRates[key]
	if limiter == nil {
		limiter = rate.NewLimiter(rate.Every(time.Second), 5)
		s.loginRates[key] = limiter
	}
	return limiter.Allow()
}
func (s *Server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedHosts[strings.ToLower(r.Host)] {
			problem(w, 421, "host_denied", "request Host is not configured")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func page(r *http.Request) (int, int) {
	l, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if l < 1 || l > 500 {
		l = 100
	}
	if p < 1 {
		p = 1
	}
	return l, (p - 1) * l
}
func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	l, o := page(r)
	v, err := s.store.ListAssets(r.Context(), r.URL.Query().Get("status"), r.URL.Query().Get("vendor"), r.URL.Query().Get("device_class"), l, o)
	respond(w, v, err)
}
func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetAsset(r.Context(), r.PathValue("id"))
	respond(w, v, err)
}
func (s *Server) assetObservations(w http.ResponseWriter, r *http.Request) {
	l, o := page(r)
	v, err := s.store.ListObservations(r.Context(), r.PathValue("id"), r.URL.Query().Get("source"), r.URL.Query().Get("ip"), l, o)
	respond(w, v, err)
}
func (s *Server) assetChanges(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListChanges(r.Context(), r.PathValue("id"), l)
	respond(w, v, err)
}
func (s *Server) assetFindings(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListFindings(r.Context(), r.PathValue("id"), r.URL.Query().Get("severity"), l)
	respond(w, v, err)
}
func (s *Server) assetCandidates(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListCandidates(r.Context(), r.PathValue("id"), l)
	respond(w, v, err)
}
func (s *Server) observations(w http.ResponseWriter, r *http.Request) {
	l, o := page(r)
	v, err := s.store.ListObservations(r.Context(), r.URL.Query().Get("asset"), r.URL.Query().Get("source"), r.URL.Query().Get("ip"), l, o)
	respond(w, v, err)
}
func (s *Server) exportObservations(w http.ResponseWriter, r *http.Request) {
	observations, err := s.store.ListObservations(r.Context(), r.URL.Query().Get("asset"), r.URL.Query().Get("source"), r.URL.Query().Get("ip"), 500, 0)
	if err != nil {
		problem(w, 500, "storage_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="cortasentry-observations.jsonl"`)
	encoder := json.NewEncoder(w)
	for _, item := range observations {
		if err := encoder.Encode(observationcontract.Contract(item)); err != nil {
			return
		}
	}
}
func (s *Server) jobs(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListJobs(r.Context(), l)
	respond(w, v, err)
}
func (s *Server) changes(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListChanges(r.Context(), r.URL.Query().Get("asset"), l)
	respond(w, v, err)
}
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListFindings(r.Context(), r.URL.Query().Get("asset"), r.URL.Query().Get("severity"), l)
	respond(w, v, err)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	l, _ := page(r)
	v, err := s.store.ListAudit(r.Context(), l)
	respond(w, v, err)
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if !s.scanRate.Allow() {
		problem(w, 429, "rate_limited", "too many scan requests")
		return
	}
	var v struct {
		Targets []string `json:"targets"`
		Ports   []int    `json:"ports"`
	}
	if err := decode(w, r, &v, 64<<10); err != nil {
		return
	}
	targets, ports, err := s.scope.ValidateJob(v.Targets, v.Ports)
	if err != nil {
		_ = s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "scan.create", ResourceType: "scan", Outcome: "denied", RequestID: requestIDFrom(r.Context()), Details: json.RawMessage(fmt.Sprintf(`{"reason":%q}`, err.Error()))})
		problem(w, 403, "scope_denied", err.Error())
		return
	}
	payload, _ := json.Marshal(v)
	if s.jobManager == nil {
		problem(w, 503, "jobs_unavailable", "job manager unavailable")
		return
	}
	j, err := s.jobManager.Enqueue(r.Context(), domain.JobDiscovery, payload, len(targets)*len(ports))
	if err != nil {
		problem(w, 500, "storage_error", err.Error())
		return
	}
	if auditErr := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "scan.create", ResourceType: "scan", ResourceID: j.ID, Outcome: "accepted", RequestID: requestIDFrom(r.Context())}); auditErr != nil {
		_ = s.jobManager.Cancel(r.Context(), j.ID)
		problem(w, 503, "audit_unavailable", "scan creation audit failed")
		return
	}
	write(w, 202, j)
}
func (s *Server) scanPreview(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Targets []string `json:"targets"`
		Ports   []int    `json:"ports"`
	}
	if err := decode(w, r, &v, 64<<10); err != nil {
		return
	}
	aa, pp, err := s.scope.PreviewJob(v.Targets, v.Ports)
	out := map[string]any{"allowed": err == nil, "active_enabled": s.scope.Summary().ActiveEnabled, "host_count": len(aa), "port_count": len(pp), "probe_count": len(aa) * len(pp), "ports": pp}
	targets := []string{}
	for _, a := range aa {
		targets = append(targets, a.String())
	}
	out["targets"] = targets
	if err != nil {
		out["reason"] = err.Error()
	}
	write(w, 200, out)
}
func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.jobManager == nil {
		problem(w, 503, "jobs_unavailable", "job manager unavailable")
		return
	}
	err := s.jobManager.Cancel(r.Context(), id)
	auditErr := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "scan.cancel", ResourceType: "scan", ResourceID: id, Outcome: outcome(err), RequestID: requestIDFrom(r.Context())})
	if err == nil {
		err = auditErr
	}
	respond(w, map[string]string{"status": "cancellation_requested"}, err)
}
func (s *Server) merge(w http.ResponseWriter, r *http.Request) {
	var v struct{ Source, Target string }
	if err := decode(w, r, &v, 16<<10); err != nil {
		return
	}
	err := s.store.MergeAssets(r.Context(), v.Source, v.Target)
	auditErr := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "asset.merge", ResourceType: "asset", ResourceID: v.Target, Outcome: outcome(err), RequestID: requestIDFrom(r.Context())})
	if err == nil {
		err = auditErr
	}
	respond(w, map[string]string{"status": "merged"}, err)
}
func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	c := s.rules.Current()
	if c == nil {
		write(w, 200, map[string]any{"rules": []any{}})
		return
	}
	write(w, 200, c)
}
func (s *Server) reloadRules(w http.ResponseWriter, r *http.Request) {
	err := s.rules.Reload(s.rulePaths)
	auditErr := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "rules.reload", ResourceType: "rules", Outcome: outcome(err), RequestID: requestIDFrom(r.Context())})
	if err == nil {
		err = auditErr
	}
	respond(w, s.rules.Current(), err)
}
func (s *Server) patchFinding(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Disposition string `json:"disposition"`
	}
	if err := decode(w, r, &v, 4096); err != nil {
		return
	}
	err := s.store.UpdateFindingDisposition(r.Context(), r.PathValue("id"), v.Disposition)
	auditErr := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "finding.disposition", ResourceType: "finding", ResourceID: r.PathValue("id"), Outcome: outcome(err), RequestID: requestIDFrom(r.Context())})
	if err == nil {
		err = auditErr
	}
	respond(w, map[string]string{"status": "updated"}, err)
}
func (s *Server) importData(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("type")
	dry := r.URL.Query().Get("dry_run") == "true"
	var n int
	var err error
	reader := io.LimitReader(r.Body, importer.MaxImportBytes+1)
	if kind == "nmap" {
		n, err = importer.Nmap(r.Context(), reader, s.importSink, dry)
	} else {
		n, err = importer.JSONL(r.Context(), kind, reader, s.importSink, dry)
	}
	auditErr := s.store.Audit(r.Context(), domain.AuditEvent{Actor: actorFrom(r), Action: "import." + kind, ResourceType: "import", Outcome: outcome(err), RequestID: requestIDFrom(r.Context())})
	if err == nil {
		err = auditErr
	}
	respond(w, map[string]any{"records": n, "dry_run": dry}, err)
}
func decode(w http.ResponseWriter, r *http.Request, v any, max int) error {
	r.Body = http.MaxBytesReader(w, r.Body, int64(max))
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		problem(w, 400, "invalid_request", err.Error())
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		problem(w, 400, "invalid_request", "exactly one JSON object required")
		return errors.New("extra JSON")
	}
	return nil
}
func respond(w http.ResponseWriter, v any, err error) {
	if err == nil {
		write(w, 200, v)
		return
	}
	if errors.Is(err, context.Canceled) {
		problem(w, 408, "cancelled", err.Error())
		return
	}
	problem(w, 400, "request_failed", err.Error())
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, code, message string) {
	write(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func outcome(err error) string {
	if err == nil {
		return "success"
	}
	return "failure"
}

type requestIDKey struct{}

func requestIDFrom(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}
func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		w.Header().Set("X-Request-ID", id)
		started := time.Now()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
		s.log.Info("http request", "request_id", id, "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

var _ = strings.Builder{}
