package tcp

import (
	"context"
	"encoding/json"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/scope"
	"net"
	"net/netip"
	"time"
)

type Dialer interface {
	Dial(context.Context, netip.Addr, int) (net.Conn, scope.Decision, error)
}

func Collect(ctx context.Context, d Dialer, a netip.Addr, port int, jobID string) domain.Observation {
	start := time.Now().UTC()
	conn, decision, err := d.Dial(ctx, a, port)
	state := "open"
	errText := ""
	if err != nil {
		state = "closed_or_error"
		errText = err.Error()
	} else {
		conn.Close()
	}
	e, _ := json.Marshal(map[string]any{"state": state, "error": errText, "latency_ms": time.Since(start).Milliseconds()})
	return domain.Observation{SensorID: "local", JobID: jobID, ObservedAt: start, Source: domain.SourceTCPConnect, TargetIP: a, TargetPort: port, Transport: "tcp", Evidence: e, RawDigest: "", CollectorVersion: "tcp/1.0.0", PolicyDecisionID: decision.ID}
}
