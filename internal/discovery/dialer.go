package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cortalabs/cortasentry/internal/scope"
	"golang.org/x/time/rate"
)

type AuthorizedDialer struct {
	scope   *scope.Engine
	timeout time.Duration
	global  *rate.Limiter
	perRate rate.Limit
	mu      sync.Mutex
	perHost map[netip.Addr]*rate.Limiter
}

func NewAuthorizedDialer(e *scope.Engine, timeout time.Duration, global, perHost float64) *AuthorizedDialer {
	return &AuthorizedDialer{scope: e, timeout: timeout, global: rate.NewLimiter(rate.Limit(global), 1), perRate: rate.Limit(perHost), perHost: map[netip.Addr]*rate.Limiter{}}
}
func (d *AuthorizedDialer) Dial(ctx context.Context, a netip.Addr, port int) (net.Conn, scope.Decision, error) {
	decision := d.scope.Decide(a.String(), port)
	if !decision.Allowed {
		return nil, decision, fmt.Errorf("scope denied: %s", decision.Reason)
	}
	if err := d.global.Wait(ctx); err != nil {
		return nil, decision, err
	}
	d.mu.Lock()
	lim := d.perHost[a]
	if lim == nil {
		lim = rate.NewLimiter(d.perRate, 1)
		d.perHost[a] = lim
	}
	d.mu.Unlock()
	if err := lim.Wait(ctx); err != nil {
		return nil, decision, err
	}
	dial := net.Dialer{Timeout: d.timeout}
	conn, err := dial.DialContext(ctx, "tcp", netip.AddrPortFrom(a, uint16(port)).String())
	return conn, decision, err
}
