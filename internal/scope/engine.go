package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/cortalabs/cortasentry/internal/config"
	"github.com/google/uuid"
)

type Decision struct {
	ID      string    `json:"id"`
	Phase   string    `json:"phase"`
	Allowed bool      `json:"allowed"`
	Reason  string    `json:"reason"`
	Target  string    `json:"target"`
	Port    int       `json:"port"`
	At      time.Time `json:"at"`
}
type Auditor interface{ ScopeDecision(Decision) error }
type Engine struct {
	cfg                    config.Scope
	allow, deny            []netip.Prefix
	allowedPorts, excluded map[int]struct{}
	audit                  Auditor
}
type Summary struct {
	ActiveEnabled      bool `json:"active_enabled"`
	AllowPublicTargets bool `json:"allow_public_targets"`
	AllowedCIDRs       int  `json:"allowed_cidrs"`
	DeniedCIDRs        int  `json:"denied_cidrs"`
	AllowedPorts       int  `json:"allowed_ports"`
	MaxHostsPerJob     int  `json:"max_hosts_per_job"`
	MaxPortsPerHost    int  `json:"max_ports_per_host"`
}

func (e *Engine) Summary() Summary {
	return Summary{ActiveEnabled: e.cfg.ActiveEnabled, AllowPublicTargets: e.cfg.AllowPublicTargets, AllowedCIDRs: len(e.allow), DeniedCIDRs: len(e.deny), AllowedPorts: len(e.allowedPorts), MaxHostsPerJob: e.cfg.MaxHostsPerJob, MaxPortsPerHost: e.cfg.MaxPortsPerHost}
}

func New(c config.Scope, a Auditor) (*Engine, error) {
	e := &Engine{cfg: c, allowedPorts: map[int]struct{}{}, excluded: map[int]struct{}{}, audit: a}
	for _, raw := range c.AllowedCIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, err
		}
		e.allow = append(e.allow, p)
	}
	for _, raw := range c.DeniedCIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, err
		}
		e.deny = append(e.deny, p)
	}
	for _, p := range c.AllowedPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d", p)
		}
		e.allowedPorts[p] = struct{}{}
	}
	for _, p := range c.ExcludedPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid excluded port %d", p)
		}
		e.excluded[p] = struct{}{}
	}
	if c.MaxHostsPerJob < 1 || c.MaxPortsPerHost < 1 {
		return nil, errors.New("invalid scope budgets")
	}
	return e, nil
}
func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %w", s, err)
	}
	a := p.Addr().Unmap()
	bits := p.Bits()
	if p.Addr().Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("mapped IPv4 prefix %q is broader than /96", s)
		}
		bits -= 96
	}
	return netip.PrefixFrom(a, bits).Masked(), nil
}
func NormalizeAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP %q: %w", s, err)
	}
	return a.Unmap(), nil
}
func (e *Engine) Decide(target string, port int) Decision {
	return e.decide(target, port, "execution")
}
func (e *Engine) decide(target string, port int, phase string) Decision {
	d := Decision{ID: uuid.Must(uuid.NewV7()).String(), Phase: phase, Target: target, Port: port, At: time.Now().UTC()}
	if !e.cfg.ActiveEnabled {
		d.Reason = "active probing disabled"
		return e.finalize(d)
	}
	a, err := NormalizeAddr(target)
	if err != nil {
		d.Reason = err.Error()
		return e.finalize(d)
	}
	d.Target = a.String()
	if a.IsUnspecified() || a.IsMulticast() {
		d.Reason = "unspecified and multicast targets are forbidden"
		return e.finalize(d)
	}
	if a.Is4() && a == netip.MustParseAddr("255.255.255.255") {
		d.Reason = "broadcast target forbidden"
		return e.finalize(d)
	}
	if !e.cfg.AllowPublicTargets && !isPrivateOrLoopback(a) {
		d.Reason = "public targets disabled"
		return e.finalize(d)
	}
	allowed := false
	for _, p := range e.allow {
		if p.Contains(a) {
			allowed = true
			break
		}
	}
	if !allowed {
		d.Reason = "target outside allowlist"
		return e.finalize(d)
	}
	for _, p := range e.deny {
		if p.Contains(a) {
			d.Reason = "target denied by denylist"
			return e.finalize(d)
		}
	}
	if port < 1 || port > 65535 {
		d.Reason = "invalid port"
		return e.finalize(d)
	}
	if _, ok := e.excluded[port]; ok {
		d.Reason = "port excluded"
		return e.finalize(d)
	}
	if len(e.allowedPorts) > 0 {
		if _, ok := e.allowedPorts[port]; !ok {
			d.Reason = "port outside allowlist"
			return e.finalize(d)
		}
	}
	d.Allowed = true
	d.Reason = "authorized"
	return e.finalize(d)
}
func (e *Engine) finalize(d Decision) Decision {
	if e.audit != nil {
		if err := e.audit.ScopeDecision(d); err != nil {
			d.Allowed = false
			d.Reason = "authorization audit persistence failed"
		}
	}
	return d
}
func isPrivateOrLoopback(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}
func (e *Engine) ValidateJob(targets []string, ports []int) ([]netip.Addr, []int, error) {
	if len(targets) == 0 || len(ports) == 0 {
		return nil, nil, errors.New("at least one target and port required")
	}
	if len(targets) > e.cfg.MaxHostsPerJob {
		return nil, nil, fmt.Errorf("host budget exceeded: %d > %d", len(targets), e.cfg.MaxHostsPerJob)
	}
	if len(ports) > e.cfg.MaxPortsPerHost {
		return nil, nil, fmt.Errorf("port budget exceeded: %d > %d", len(ports), e.cfg.MaxPortsPerHost)
	}
	seenA := map[netip.Addr]bool{}
	aa := make([]netip.Addr, 0, len(targets))
	for _, t := range targets {
		a, err := NormalizeAddr(t)
		if err != nil {
			return nil, nil, err
		}
		if !seenA[a] {
			seenA[a] = true
			aa = append(aa, a)
		}
	}
	seenP := map[int]bool{}
	pp := make([]int, 0, len(ports))
	for _, p := range ports {
		if !seenP[p] {
			seenP[p] = true
			pp = append(pp, p)
		}
	}
	if len(aa) > e.cfg.MaxHostsPerJob || len(pp) > e.cfg.MaxPortsPerHost {
		return nil, nil, errors.New("normalized job exceeds budget")
	}
	for _, a := range aa {
		for _, p := range pp {
			if d := e.decide(a.String(), p, "preflight"); !d.Allowed {
				return nil, nil, fmt.Errorf("scope denied %s:%d: %s", a, p, d.Reason)
			}
		}
	}
	sort.Slice(aa, func(i, j int) bool { return aa[i].Less(aa[j]) })
	sort.Ints(pp)
	return aa, pp, nil
}
func (e *Engine) PreviewJob(targets []string, ports []int) ([]netip.Addr, []int, error) {
	clone := *e
	clone.audit = nil
	return clone.ValidateJob(targets, ports)
}
func ExpandPrefix(raw string, max int) ([]string, error) {
	p, err := parsePrefix(raw)
	if err != nil {
		return nil, err
	}
	if max < 1 {
		return nil, errors.New("host budget must be positive")
	}
	if p.Addr().IsUnspecified() && p.Bits() == 0 {
		return nil, errors.New("default route prefix forbidden")
	}
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 63 || uint64(1)<<hostBits > uint64(max+2) {
		return nil, fmt.Errorf("CIDR exceeds host budget %d", max)
	}
	out := []string{}
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		first := a == p.Addr()
		last := !p.Contains(a.Next())
		if p.Addr().Is4() && hostBits >= 2 && (first || last) {
			continue
		}
		out = append(out, a.String())
		if len(out) > max {
			return nil, fmt.Errorf("CIDR exceeds host budget %d", max)
		}
	}
	return out, nil
}
