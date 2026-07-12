package ssdp

import (
	"context"
	"errors"
	"github.com/cortalabs/cortasentry/internal/observation"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Service struct {
	Source    netip.Addr `json:"source"`
	Server    string     `json:"server,omitempty"`
	ST        string     `json:"st,omitempty"`
	USN       string     `json:"usn,omitempty"`
	Location  string     `json:"location,omitempty"`
	Truncated bool       `json:"truncated"`
}

func Discover(ctx context.Context, window time.Duration, maxResponses int) ([]Service, error) {
	if maxResponses < 1 || maxResponses > 1000 {
		return nil, errors.New("invalid response budget")
	}
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(window)
	_ = c.SetDeadline(deadline)
	query := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
	if _, err = c.WriteTo([]byte(query), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
		return nil, err
	}
	var out []Service
	buf := make([]byte, 8193)
	for len(out) < maxResponses && ctx.Err() == nil {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return out, err
		}
		tr := n > 8192
		if tr {
			n = 8192
		}
		s := Parse(string(buf[:n]))
		if ua, ok := addr.(*net.UDPAddr); ok {
			if a, ok := netip.AddrFromSlice(ua.IP); ok {
				s.Source = a.Unmap()
			}
		}
		s.Truncated = tr
		out = append(out, s)
	}
	return out, ctx.Err()
}
func Parse(raw string) Service {
	s := Service{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v, _ = observation.Printable(strings.TrimSpace(v), 2048)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "server":
			s.Server = v
		case "st":
			s.ST = v
		case "usn":
			s.USN = v
		case "location":
			s.Location = v
		}
	}
	return s
}
