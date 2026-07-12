package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/api"
	"github.com/cortalabs/cortasentry/internal/application"
	"github.com/cortalabs/cortasentry/internal/assets"
	"github.com/cortalabs/cortasentry/internal/auth"
	connectioncollector "github.com/cortalabs/cortasentry/internal/collectors/connections"
	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/cortalabs/cortasentry/internal/discovery"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/findings"
	"github.com/cortalabs/cortasentry/internal/fingerprint"
	"github.com/cortalabs/cortasentry/internal/fixtures"
	"github.com/cortalabs/cortasentry/internal/importer"
	jobmanager "github.com/cortalabs/cortasentry/internal/jobs"
	"github.com/cortalabs/cortasentry/internal/mcpserver"
	observationcontract "github.com/cortalabs/cortasentry/internal/observation"
	"github.com/cortalabs/cortasentry/internal/scope"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "cortasentry:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "init":
		return initCommand(args[1:])
	case "serve":
		return serve(args[1:])
	case "demo":
		return demo(args[1:])
	case "scan":
		return scan(args[1:])
	case "assets":
		return listCommand("assets", args[1:])
	case "observations":
		return listCommand("observations", args[1:])
	case "connections":
		return connectionsCommand(args[1:])
	case "rules":
		return rulesCommand(args[1:])
	case "import":
		return importCommand(args[1:])
	case "token":
		return tokenCommand(args[1:])
	case "config":
		return configCommand(args[1:])
	case "mcp":
		return mcpCommand(args[1:])
	case "version":
		fmt.Println("CortaSentry", version)
		return nil
	default:
		return usage()
	}
}
func connectionsCommand(args []string) error {
	if len(args) == 0 || args[0] != "snapshot" {
		return errors.New("usage: cortasentry connections snapshot")
	}
	_, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	items, err := connectioncollector.Snapshot(context.Background(), 5000)
	if err != nil {
		return err
	}
	for i := range items {
		if err = a.store.AddObservation(context.Background(), &items[i]); err != nil {
			return err
		}
	}
	_ = a.store.Audit(context.Background(), domain.AuditEvent{Actor: "admin", Action: "connections.snapshot", ResourceType: "local_node", Outcome: "success", Details: json.RawMessage(fmt.Sprintf(`{"observations":%d}`, len(items)))})
	fmt.Printf("observed %d local connection records; all remain unreviewed evidence, not maliciousness claims\n", len(items))
	return nil
}
func usage() error {
	fmt.Fprintln(os.Stderr, "usage: cortasentry {init|serve|demo|scan|assets list|observations list|rules validate|rules test|import|token rotate|config validate|mcp|version}")
	return errors.New("command required")
}
func configPath() string {
	if v := os.Getenv("CORTASENTRY_CONFIG"); v != "" {
		return v
	}
	return "./cortasentry.yaml"
}
func initCommand(args []string) error {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	path := f.String("config", configPath(), "configuration path")
	if err := f.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*path); err == nil {
		return errors.New("configuration already exists")
	}
	c := config.Default()
	if err := config.Write(*path, c); err != nil {
		return err
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Server.DataDir, 0700); err != nil {
		return err
	}
	s, err := sqlite.Open(c.Server.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	m := auth.New(s.DB(), false)
	token, err := m.Bootstrap(context.Background(), filepath.Join(c.Server.DataDir, "admin.token"))
	if err != nil {
		return err
	}
	_ = s.Audit(context.Background(), domain.AuditEvent{Actor: "system", Action: "system.init", ResourceType: "installation", Outcome: "success"})
	fmt.Printf("Initialized CortaSentry.\nConfiguration: %s\nDatabase: %s\nOne-time admin token written to: %s\nAdmin token (shown once): %s\n", *path, c.Server.Database, filepath.Join(c.Server.DataDir, "admin.token"), token)
	return nil
}

type app struct {
	cfg        config.Config
	store      *sqlite.Store
	scope      *scope.Engine
	rules      *fingerprint.Engine
	scanner    *discovery.Scanner
	auth       *auth.Manager
	jobs       *jobmanager.Manager
	service    *application.Service
	advisories *findings.Engine
}

func openApp(c config.Config) (*app, error) {
	if err := os.MkdirAll(c.Server.DataDir, 0700); err != nil {
		return nil, err
	}
	s, err := sqlite.Open(c.Server.Database)
	if err != nil {
		return nil, err
	}
	sc, err := scope.New(c.Scope, s)
	if err != nil {
		s.Close()
		return nil, err
	}
	rules := fingerprint.New(.1)
	if err = rules.Reload(c.Rules.DevicePaths); err != nil {
		s.Close()
		return nil, fmt.Errorf("load rules: %w", err)
	}
	advisories := findings.NewEngine()
	if err = advisories.Reload(c.Rules.AdvisoryPaths); err != nil {
		s.Close()
		return nil, fmt.Errorf("load advisories: %w", err)
	}
	resolver := assets.New(s)
	dial := discovery.NewAuthorizedDialer(sc, c.Limits.ConnectTimeout, c.Limits.ConnectsPerSecond, c.Limits.PerHostConnectsPerSecond)
	scanner := discovery.NewScanner(dial, s, resolver, rules, c.Limits.MaxConcurrency, c.Limits.MaxHTTPBodyBytes, c.Limits.MaxHeaders, c.Limits.ReadTimeout+2*c.Limits.ConnectTimeout)
	handler := func(ctx context.Context, j *domain.Job, progress func(int, int) error) error {
		if j.Type != domain.JobDiscovery {
			return fmt.Errorf("unsupported job type %s", j.Type)
		}
		var req struct {
			Targets []string `json:"targets"`
			Ports   []int    `json:"ports"`
		}
		if err := json.Unmarshal(j.Payload, &req); err != nil {
			return err
		}
		targets, ports, err := sc.ValidateJob(req.Targets, req.Ports)
		if err != nil {
			return err
		}
		result, err := scanner.RunWithProgress(ctx, j.ID, targets, ports, "", progress)
		if err != nil {
			return err
		}
		for _, assetID := range result.AssetIDs {
			asset, getErr := s.GetAsset(ctx, assetID)
			if getErr != nil {
				return getErr
			}
			for _, finding := range advisories.Evaluate(asset) {
				created, upErr := s.UpsertFinding(ctx, &finding)
				if upErr != nil {
					return upErr
				}
				if created {
					at := time.Now().UTC()
					cur, _ := json.Marshal(map[string]any{"advisory_id": finding.AdvisoryID, "state": finding.State})
					_ = s.AddChange(ctx, domain.ChangeEvent{AssetID: assetID, Type: domain.ChangeNewFinding, Previous: []byte("null"), Current: cur, DetectedAt: at, FirstOccurrence: at, LastOccurrence: at})
				}
			}
		}
		return nil
	}
	jm := jobmanager.New(s, c.Jobs.Workers, c.Jobs.MaxQueued, c.Jobs.LeaseDuration, c.Jobs.PollInterval, c.Limits.MaxJobDuration, handler)
	svc, err := application.New(c, s, sc, rules, jm)
	if err != nil {
		s.Close()
		return nil, err
	}
	return &app{cfg: c, store: s, scope: sc, rules: rules, scanner: scanner, auth: auth.New(s.DB(), c.Server.SecureCookies), jobs: jm, service: svc, advisories: advisories}, nil
}

func mcpCommand(args []string) error {
	_, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	ctx := context.Background()
	a.jobs.Start(ctx)
	return mcpserver.Serve(ctx, a.service, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
}
func loadApp() (config.Config, *app, error) {
	c, err := config.Load(configPath())
	if err != nil {
		return c, nil, err
	}
	a, err := openApp(c)
	return c, a, err
}
func serve(args []string) error {
	c, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	a.jobs.Start(context.Background())
	srv := api.New(a.store, a.auth, a.scope, a.scanner, a.rules, a.advisories, c.Rules.DevicePaths, log, a.jobs)
	srv.EnableWeb()
	server := &http.Server{Addr: c.Server.Bind, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	log.Info("server starting", "bind", c.Server.Bind, "version", version)
	return server.ListenAndServe()
}
func demo(args []string) error {
	c, err := config.Load(configPath())
	if err != nil {
		return err
	}
	lab, err := fixtures.Start()
	if err != nil {
		return err
	}
	defer lab.Close()
	portsMap := lab.Ports()
	ports := make([]int, 0, len(portsMap))
	for _, p := range portsMap {
		ports = append(ports, p)
	}
	c.Scope.ActiveEnabled = true
	c.Scope.AllowedCIDRs = []string{"127.0.0.1/32"}
	c.Scope.AllowedPorts = ports
	c.Scope.ExcludedPorts = nil
	c.Scope.AllowPublicTargets = false
	c.Scope.MaxHostsPerJob = 1
	c.Scope.MaxPortsPerHost = len(ports)
	a, err := openApp(c)
	if err != nil {
		return err
	}
	defer a.store.Close()
	fmt.Println("Fixture ports:", string(lab.JSON()))
	for name, p := range portsMap {
		targets, pp, err := a.scope.ValidateJob([]string{"127.0.0.1"}, []int{p})
		if err != nil {
			return err
		}
		r, err := a.scanner.Run(context.Background(), "demo-state-1-"+name, targets, pp, "fixture:"+name)
		if err != nil {
			return err
		}
		fmt.Printf("state 1 %-10s observations=%d assets=%d candidates=%d changes=%d errors=%d\n", name, r.Observations, r.Assets, r.Candidates, r.Changes, r.Errors)
	}
	lab.SetState(1)
	time.Sleep(20 * time.Millisecond)
	for name, p := range portsMap {
		targets, pp, _ := a.scope.ValidateJob([]string{"127.0.0.1"}, []int{p})
		r, err := a.scanner.Run(context.Background(), "demo-state-2-"+name, targets, pp, "fixture:"+name)
		if err != nil {
			return err
		}
		fmt.Printf("state 2 %-10s observations=%d assets=%d candidates=%d changes=%d errors=%d\n", name, r.Observations, r.Assets, r.Candidates, r.Changes, r.Errors)
	}
	_ = a.store.Audit(context.Background(), domain.AuditEvent{Actor: "admin", Action: "demo.completed", ResourceType: "fixture_lab", Outcome: "success"})
	fmt.Println("Demo data persisted. Run `cortasentry serve` and open http://" + c.Server.Bind)
	return nil
}
func scan(args []string) error {
	f := flag.NewFlagSet("scan", flag.ContinueOnError)
	cidr := f.String("cidr", "", "single authorized IP or CIDR")
	portsRaw := f.String("ports", "", "comma-separated ports")
	jsonOut := f.Bool("json", false, "JSON output")
	if err := f.Parse(args); err != nil {
		return err
	}
	c, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	targets, err := scope.ExpandPrefix(*cidr, c.Scope.MaxHostsPerJob)
	if err != nil {
		return err
	}
	ports, err := parsePorts(*portsRaw)
	if err != nil {
		return err
	}
	aa, pp, err := a.scope.ValidateJob(targets, ports)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"targets": targets, "ports": ports})
	a.jobs.Start(context.Background())
	j, err := a.jobs.Enqueue(context.Background(), domain.JobDiscovery, payload, len(aa)*len(pp))
	if err == nil {
		err = a.jobs.Wait(context.Background(), j.ID, a.store.JobState)
	}
	jobs, _ := a.store.ListJobs(context.Background(), 1)
	r := discovery.ScanResult{}
	if len(jobs) > 0 {
		r.Observations = jobs[0].ProgressCurrent
	}
	result := "success"
	if err != nil {
		result = "failure"
	}
	_ = a.store.Audit(context.Background(), domain.AuditEvent{Actor: "cli", Action: "scan.completed", ResourceType: "scan", Outcome: result})
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(r)
	} else {
		fmt.Printf("observations=%d assets=%d candidates=%d changes=%d errors=%d\n", r.Observations, r.Assets, r.Candidates, r.Changes, r.Errors)
	}
	return err
}
func parsePorts(raw string) ([]int, error) {
	if raw == "" {
		return nil, errors.New("ports required")
	}
	var out []int
	for _, x := range strings.Split(raw, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", x)
		}
		out = append(out, p)
	}
	return out, nil
}
func listCommand(kind string, args []string) error {
	if len(args) == 0 || (args[0] != "list" && !(kind == "observations" && args[0] == "export")) {
		return fmt.Errorf("usage: cortasentry %s list", kind)
	}
	_, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	if kind == "assets" {
		v, e := a.store.ListAssets(context.Background(), "", "", "", 100, 0)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	v, e := a.store.ListObservations(context.Background(), "", "", "", 100, 0)
	if e != nil {
		return e
	}
	encoder := json.NewEncoder(os.Stdout)
	if args[0] == "export" {
		for _, item := range v {
			if err := encoder.Encode(observationcontract.Contract(item)); err != nil {
				return err
			}
		}
		return nil
	}
	return encoder.Encode(v)
}
func rulesCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("rules subcommand required")
	}
	c, err := config.Load(configPath())
	if err != nil {
		return err
	}
	compiled, err := fingerprint.LoadPaths(c.Rules.DevicePaths)
	if err != nil {
		return err
	}
	switch args[0] {
	case "validate":
		fmt.Printf("validated %d rules digest=%s\n", len(compiled.Rules), compiled.Digest)
		return nil
	case "test":
		if err := fingerprint.TestCompiled(compiled); err != nil {
			return err
		}
		fmt.Printf("rule fixtures passed for %d rules\n", len(compiled.Rules))
		return nil
	}
	return errors.New("unknown rules subcommand")
}
func importCommand(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: cortasentry import <nmap|zeek|suricata|nuclei> <path> [--dry-run]")
	}
	kind, path := args[0], args[1]
	dry := len(args) > 2 && args[2] == "--dry-run"
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	var n int
	sink := importer.PipelineSink{Scanner: a.scanner, Store: a.store, Advisories: a.advisories}
	if kind == "nmap" {
		n, err = importer.Nmap(context.Background(), f, sink, dry)
	} else {
		n, err = importer.JSONL(context.Background(), kind, f, sink, dry)
	}
	if err == nil {
		_ = a.store.Audit(context.Background(), domain.AuditEvent{Actor: "admin", Action: "import." + kind, ResourceType: "file", ResourceID: filepath.Base(path), Outcome: "success"})
		fmt.Printf("validated records=%d dry_run=%v\n", n, dry)
	}
	return err
}
func tokenCommand(args []string) error {
	if len(args) == 0 || args[0] != "rotate" {
		return errors.New("usage: cortasentry token rotate")
	}
	c, a, err := loadApp()
	if err != nil {
		return err
	}
	defer a.store.Close()
	token, err := a.auth.Rotate(context.Background(), filepath.Join(c.Server.DataDir, "admin.token"))
	if err != nil {
		return err
	}
	_ = a.store.Audit(context.Background(), domain.AuditEvent{Actor: "admin", Action: "token.rotate", ResourceType: "auth_token", Outcome: "success"})
	fmt.Println("Token rotated. New token (shown once):", token)
	return nil
}
func configCommand(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("usage: cortasentry config validate")
	}
	c, err := config.Load(configPath())
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c.Redacted(), "", "  ")
	fmt.Println(string(b))
	return nil
}

var _ io.Reader
