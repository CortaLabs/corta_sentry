package banner

import (
	"context"
	"encoding/json"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/observation"
	"github.com/cortalabs/cortasentry/internal/scope"
	"io"
	"net"
	"net/netip"
	"time"
)

type Dialer interface {
	Dial(context.Context, netip.Addr, int) (net.Conn, scope.Decision, error)
}

func Collect(ctx context.Context, d Dialer, a netip.Addr, port, max int, timeout time.Duration, jobID string) (domain.Observation, error) {
	conn, decision, err := d.Dial(ctx, a, port)
	if err != nil {
		return domain.Observation{}, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	b, readErr := io.ReadAll(io.LimitReader(conn, int64(max)+1))
	tr := len(b) > max
	if tr {
		b = b[:max]
	}
	text, _ := observation.Printable(string(b), max)
	e, _ := json.Marshal(map[string]any{"text": text, "bytes": len(b), "read_error": errorString(readErr)})
	return domain.Observation{SensorID: "local", JobID: jobID, ObservedAt: time.Now().UTC(), Source: domain.SourceBanner, TargetIP: a, TargetPort: port, Transport: "tcp", Evidence: e, RawDigest: observation.Digest(b), CollectorVersion: "banner/1.0.0", PolicyDecisionID: decision.ID, Truncated: tr}, nil
}
func errorString(err error) string {
	if err == nil || err == io.EOF {
		return ""
	}
	return err.Error()
}
