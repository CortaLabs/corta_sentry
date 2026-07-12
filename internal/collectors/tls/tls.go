package tlscollector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/observation"
	"github.com/cortalabs/cortasentry/internal/scope"
	"net"
	"net/netip"
	"time"
)

type Dialer interface {
	Dial(context.Context, netip.Addr, int) (net.Conn, scope.Decision, error)
}

func Collect(ctx context.Context, d Dialer, a netip.Addr, port int, timeout time.Duration, jobID string) (domain.Observation, error) {
	raw, decision, err := d.Dial(ctx, a, port)
	if err != nil {
		return domain.Observation{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err = c.HandshakeContext(ctx); err != nil {
		return domain.Observation{}, err
	}
	st := c.ConnectionState()
	certs := make([]map[string]any, 0, len(st.PeerCertificates))
	for i, cert := range st.PeerCertificates {
		if i >= 5 {
			break
		}
		sum := sha256.Sum256(cert.Raw)
		sans := cert.DNSNames
		if len(sans) > 50 {
			sans = sans[:50]
		}
		subject, _ := observation.Printable(cert.Subject.String(), 2048)
		issuer, _ := observation.Printable(cert.Issuer.String(), 2048)
		for j := range sans {
			sans[j], _ = observation.Printable(sans[j], 512)
		}
		certs = append(certs, map[string]any{"subject": subject, "issuer": issuer, "sans": sans, "not_before": cert.NotBefore, "not_after": cert.NotAfter, "sha256": hex.EncodeToString(sum[:]), "public_key_algorithm": cert.PublicKeyAlgorithm.String(), "signature_algorithm": cert.SignatureAlgorithm.String()})
	}
	e, _ := json.Marshal(map[string]any{"version": tls.VersionName(st.Version), "negotiated_protocol": st.NegotiatedProtocol, "certificates": certs, "trust_established": false, "trust_note": "certificate chain collected without trust validation"})
	return domain.Observation{SensorID: "local", JobID: jobID, ObservedAt: time.Now().UTC(), Source: domain.SourceTLS, TargetIP: a, TargetPort: port, Transport: "tcp", Application: "tls", Evidence: e, CollectorVersion: "tls/1.0.0", PolicyDecisionID: decision.ID}, nil
}
