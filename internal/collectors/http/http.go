package httpcollector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/observation"
	"github.com/cortalabs/cortasentry/internal/scope"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type Dialer interface {
	Dial(context.Context, netip.Addr, int) (net.Conn, scope.Decision, error)
}

func Collect(ctx context.Context, d Dialer, a netip.Addr, port, maxBody, maxHeaders int, timeout time.Duration, jobID string) (domain.Observation, error) {
	return collect(ctx, d, a, port, maxBody, maxHeaders, timeout, jobID, false)
}
func CollectSecure(ctx context.Context, d Dialer, a netip.Addr, port, maxBody, maxHeaders int, timeout time.Duration, jobID string) (domain.Observation, error) {
	return collect(ctx, d, a, port, maxBody, maxHeaders, timeout, jobID, true)
}
func collect(ctx context.Context, d Dialer, a netip.Addr, port, maxBody, maxHeaders int, timeout time.Duration, jobID string, secure bool) (domain.Observation, error) {
	var decisionID string
	tr := &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		conn, dec, err := d.Dial(c, a, port)
		decisionID = dec.ID
		return conn, err
	}}
	if secure {
		tr.DialTLSContext = func(c context.Context, network, address string) (net.Conn, error) {
			raw, dec, err := d.Dial(c, a, port)
			decisionID = dec.ID
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			if err = tc.HandshakeContext(c); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		}
	}
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer tr.CloseIdleConnections()
	scheme := "http"
	if secure {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s/", scheme, netip.AddrPortFrom(a, uint16(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return domain.Observation{}, err
	}
	req.Header.Set("User-Agent", "CortaSentry/0.1.0 authorized-security-inventory")
	resp, err := client.Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
	if err != nil {
		return domain.Observation{}, err
	}
	trunc := len(b) > maxBody
	if trunc {
		b = b[:maxBody]
	}
	headers, ht := observation.SanitizeHeaders(resp.Header, maxHeaders, 4096)
	trunc = trunc || ht
	title := ""
	if m := titleRE.FindSubmatch(b); len(m) > 1 {
		title, _ = observation.Printable(strings.TrimSpace(string(m[1])), 512)
	}
	excerpt, _ := observation.Printable(string(b), 2048)
	server, _ := observation.Printable(resp.Header.Get("Server"), 512)
	contentType, _ := observation.Printable(resp.Header.Get("Content-Type"), 256)
	e, _ := json.Marshal(map[string]any{"status": resp.StatusCode, "headers": headers, "title": title, "server": server, "content_type": contentType, "body_digest": observation.Digest(b), "text_excerpt": excerpt, "redirect_location": bounded(resp.Header.Get("Location"), 2048)})
	return domain.Observation{SensorID: "local", JobID: jobID, ObservedAt: time.Now().UTC(), Source: domain.SourceHTTP, TargetIP: a, TargetPort: port, Transport: "tcp", Application: "http", Evidence: e, RawDigest: observation.Digest(b), CollectorVersion: "http/1.0.0", PolicyDecisionID: decisionID, Truncated: trunc}, nil
}
func bounded(s string, n int) string { v, _ := observation.Printable(s, n); return v }
