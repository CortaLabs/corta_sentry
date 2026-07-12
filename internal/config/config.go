package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

type Config struct {
	Version int     `yaml:"version"`
	Server  Server  `yaml:"server"`
	Scope   Scope   `yaml:"scope"`
	Limits  Limits  `yaml:"limits"`
	Jobs    Jobs    `yaml:"jobs"`
	Rules   Rules   `yaml:"rules"`
	Logging Logging `yaml:"logging"`
	MCP     MCP     `yaml:"mcp"`
}
type Server struct {
	Bind                       string   `yaml:"bind"`
	DataDir                    string   `yaml:"data_dir"`
	Database                   string   `yaml:"database"`
	UnsafePublicBind           bool     `yaml:"unsafe_public_bind"`
	SecureCookies              bool     `yaml:"secure_cookies"`
	UnsafeAllowInsecureCookies bool     `yaml:"unsafe_allow_insecure_cookies"`
	AllowedHosts               []string `yaml:"allowed_hosts"`
}
type Scope struct {
	ActiveEnabled      bool     `yaml:"active_enabled"`
	AllowedCIDRs       []string `yaml:"allowed_cidrs"`
	DeniedCIDRs        []string `yaml:"denied_cidrs"`
	AllowPublicTargets bool     `yaml:"allow_public_targets"`
	AllowedPorts       []int    `yaml:"allowed_ports"`
	ExcludedPorts      []int    `yaml:"excluded_ports"`
	MaxHostsPerJob     int      `yaml:"max_hosts_per_job"`
	MaxPortsPerHost    int      `yaml:"max_ports_per_host"`
}
type Limits struct {
	MaxConcurrency           int           `yaml:"max_concurrency"`
	ConnectsPerSecond        float64       `yaml:"connects_per_second"`
	PerHostConnectsPerSecond float64       `yaml:"per_host_connects_per_second"`
	ConnectTimeout           time.Duration `yaml:"connect_timeout"`
	ReadTimeout              time.Duration `yaml:"read_timeout"`
	MaxBannerBytes           int           `yaml:"max_banner_bytes"`
	MaxHTTPBodyBytes         int           `yaml:"max_http_body_bytes"`
	MaxHeaders               int           `yaml:"max_headers"`
	MaxRedirects             int           `yaml:"max_redirects"`
	MaxJobDuration           time.Duration `yaml:"max_job_duration"`
}
type Rules struct {
	DevicePaths   []string `yaml:"device_paths"`
	AdvisoryPaths []string `yaml:"advisory_paths"`
}
type Jobs struct {
	Workers       int           `yaml:"workers"`
	MaxQueued     int           `yaml:"max_queued"`
	LeaseDuration time.Duration `yaml:"lease_duration"`
	PollInterval  time.Duration `yaml:"poll_interval"`
}
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}
type MCP struct {
	WriteEnabled       bool `yaml:"write_enabled"`
	ActiveToolsEnabled bool `yaml:"active_tools_enabled"`
}

func Default() Config {
	ruleRoot := defaultRuleRoot()
	return Config{
		Version: CurrentVersion,
		Server:  Server{Bind: "127.0.0.1:8088", DataDir: "./data", Database: "./data/cortasentry.db"},
		Scope:   Scope{AllowedPorts: []int{22, 23, 53, 80, 443, 554, 8000, 8001, 8002, 8080, 8443}, MaxHostsPerJob: 256, MaxPortsPerHost: 64},
		Limits:  Limits{MaxConcurrency: 32, ConnectsPerSecond: 50, PerHostConnectsPerSecond: 5, ConnectTimeout: 750 * time.Millisecond, ReadTimeout: time.Second, MaxBannerBytes: 8192, MaxHTTPBodyBytes: 65536, MaxHeaders: 100, MaxRedirects: 0, MaxJobDuration: 10 * time.Minute},
		Jobs:    Jobs{Workers: 2, MaxQueued: 1024, LeaseDuration: 30 * time.Second, PollInterval: 250 * time.Millisecond},
		Rules:   Rules{DevicePaths: []string{filepath.Join(ruleRoot, "devices")}, AdvisoryPaths: []string{filepath.Join(ruleRoot, "advisories")}},
		Logging: Logging{Level: "info", Format: "json"},
		MCP:     MCP{WriteEnabled: false, ActiveToolsEnabled: false},
	}
}
func defaultRuleRoot() string {
	exe, err := os.Executable()
	if err == nil {
		for _, p := range []string{filepath.Clean(filepath.Join(filepath.Dir(exe), "..", "share", "cortasentry", "rules")), filepath.Clean(filepath.Join(filepath.Dir(exe), "..", "rules"))} {
			if st, e := os.Stat(p); e == nil && st.IsDir() {
				return p
			}
		}
	}
	if p, e := filepath.Abs("./rules"); e == nil {
		if st, statErr := os.Stat(p); statErr == nil && st.IsDir() {
			return p
		}
	}
	return "./rules"
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if len(b) > 1<<20 {
		return Config{}, errors.New("configuration exceeds 1 MiB")
	}
	c := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err = dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("configuration must contain exactly one YAML document")
	}
	applyEnv(&c)
	resolveRelativePaths(&c, filepath.Dir(path))
	if err = c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func resolveRelativePaths(c *Config, base string) {
	if absolute, err := filepath.Abs(base); err == nil {
		base = absolute
	}
	resolve := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Clean(filepath.Join(base, value))
	}
	c.Server.DataDir = resolve(c.Server.DataDir)
	c.Server.Database = resolve(c.Server.Database)
	for i := range c.Rules.DevicePaths {
		c.Rules.DevicePaths[i] = resolve(c.Rules.DevicePaths[i])
	}
	for i := range c.Rules.AdvisoryPaths {
		c.Rules.AdvisoryPaths[i] = resolve(c.Rules.AdvisoryPaths[i])
	}
}
func applyEnv(c *Config) {
	if v := os.Getenv("CORTASENTRY_BIND"); v != "" {
		c.Server.Bind = v
	}
	if v := os.Getenv("CORTASENTRY_DATABASE"); v != "" {
		c.Server.Database = v
	}
	if v := os.Getenv("CORTASENTRY_UNSAFE_PUBLIC_BIND"); v == "1" || strings.EqualFold(v, "true") {
		c.Server.UnsafePublicBind = true
	}
	if v := os.Getenv("CORTASENTRY_SECURE_COOKIES"); v == "1" || strings.EqualFold(v, "true") {
		c.Server.SecureCookies = true
	}
	if v := os.Getenv("CORTASENTRY_UNSAFE_ALLOW_INSECURE_COOKIES"); v == "1" || strings.EqualFold(v, "true") {
		c.Server.UnsafeAllowInsecureCookies = true
	}
	if v := os.Getenv("CORTASENTRY_ALLOWED_HOSTS"); v != "" {
		c.Server.AllowedHosts = strings.Split(v, ",")
	}
}
func (c Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Server.Bind == "" || c.Server.Database == "" || c.Server.DataDir == "" {
		return errors.New("server bind, data_dir, and database are required")
	}
	host, port, err := net.SplitHostPort(c.Server.Bind)
	if err != nil {
		return fmt.Errorf("server.bind: %w", err)
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return errors.New("server.bind host must be an IP address")
	}
	if _, e = netip.ParseAddrPort(net.JoinHostPort(ip.String(), port)); e != nil {
		return fmt.Errorf("server.bind port: %w", e)
	}
	if !ip.Unmap().IsLoopback() && !c.Server.UnsafePublicBind {
		return errors.New("non-loopback bind requires unsafe_public_bind: true and a secured reverse proxy")
	}
	if !ip.Unmap().IsLoopback() && !c.Server.SecureCookies && !c.Server.UnsafeAllowInsecureCookies {
		return errors.New("non-loopback bind requires secure_cookies: true; loopback-published containers require explicit unsafe_allow_insecure_cookies: true")
	}
	if !ip.Unmap().IsLoopback() && len(c.Server.AllowedHosts) == 0 {
		return errors.New("non-loopback bind requires explicit allowed_hosts")
	}
	for _, host := range c.Server.AllowedHosts {
		host = strings.TrimSpace(host)
		if host == "" || len(host) > 255 || strings.ContainsAny(host, "/\\ \t\r\n") {
			return fmt.Errorf("invalid server.allowed_hosts entry %q", host)
		}
	}
	if c.Scope.MaxHostsPerJob < 1 || c.Scope.MaxPortsPerHost < 1 {
		return errors.New("scope budgets must be positive")
	}
	if c.Limits.MaxConcurrency < 1 || c.Limits.MaxConcurrency > 1024 {
		return errors.New("max_concurrency must be 1..1024")
	}
	if c.Limits.ConnectsPerSecond <= 0 || c.Limits.PerHostConnectsPerSecond <= 0 {
		return errors.New("connection rates must be positive")
	}
	if c.Limits.MaxHeaders < 1 || c.Limits.MaxHeaders > 1000 {
		return errors.New("max_headers must be 1..1000")
	}
	if c.Limits.ConnectTimeout <= 0 || c.Limits.ReadTimeout <= 0 || c.Limits.MaxJobDuration <= 0 {
		return errors.New("timeouts must be positive")
	}
	if c.Limits.MaxBannerBytes < 1 || c.Limits.MaxBannerBytes > 1<<20 || c.Limits.MaxHTTPBodyBytes < 1 || c.Limits.MaxHTTPBodyBytes > 8<<20 {
		return errors.New("response size limits invalid")
	}
	if c.Limits.MaxRedirects != 0 {
		return errors.New("max_redirects must be 0 in this release; redirects are recorded but never followed")
	}
	if c.Jobs.Workers < 1 || c.Jobs.Workers > 64 || c.Jobs.MaxQueued < 1 || c.Jobs.MaxQueued > 100000 {
		return errors.New("job workers or queue bound invalid")
	}
	if c.Jobs.LeaseDuration < 5*time.Second || c.Jobs.PollInterval < 10*time.Millisecond || c.Jobs.PollInterval >= c.Jobs.LeaseDuration {
		return errors.New("job lease/poll durations invalid")
	}
	for _, s := range append(append([]string{}, c.Scope.AllowedCIDRs...), c.Scope.DeniedCIDRs...) {
		if _, e := netip.ParsePrefix(s); e != nil {
			return fmt.Errorf("invalid CIDR %q: %w", s, e)
		}
	}
	ports := map[int]bool{}
	for _, p := range c.Scope.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid allowed port %d", p)
		}
		if ports[p] {
			return fmt.Errorf("duplicate allowed port %d", p)
		}
		ports[p] = true
	}
	if c.Scope.ActiveEnabled && len(c.Scope.AllowedCIDRs) == 0 {
		return errors.New("active scanning enabled without allowed_cidrs")
	}
	return nil
}
func (c Config) HTTPAllowedHosts() []string {
	if len(c.Server.AllowedHosts) > 0 {
		out := make([]string, 0, len(c.Server.AllowedHosts))
		for _, h := range c.Server.AllowedHosts {
			out = append(out, strings.ToLower(strings.TrimSpace(h)))
		}
		return out
	}
	host, port, _ := net.SplitHostPort(c.Server.Bind)
	return []string{strings.ToLower(net.JoinHostPort(host, port)), strings.ToLower(net.JoinHostPort("127.0.0.1", port)), strings.ToLower(net.JoinHostPort("::1", port)), strings.ToLower(net.JoinHostPort("localhost", port))}
}
func Write(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func (c Config) Redacted() Config { return c }
