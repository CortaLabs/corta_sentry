package mdns

import (
	"context"
	"errors"
	"github.com/cortalabs/cortasentry/internal/observation"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Advertisement struct {
	Source         netip.Addr `json:"source"`
	ServiceMarkers []string   `json:"service_markers"`
	Digest         string     `json:"digest"`
	Truncated      bool       `json:"truncated"`
}

func Listen(ctx context.Context, window time.Duration, maxPackets int) ([]Advertisement, error) {
	if maxPackets < 1 || maxPackets > 1000 {
		return nil, errors.New("invalid packet budget")
	}
	c, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetReadBuffer(64 << 10)
	_ = c.SetDeadline(time.Now().Add(window))
	buf := make([]byte, 8193)
	var out []Advertisement
	for len(out) < maxPackets && ctx.Err() == nil {
		n, src, err := c.ReadFromUDP(buf)
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
		raw := buf[:n]
		markers := markers(raw)
		a, _ := netip.AddrFromSlice(src.IP)
		out = append(out, Advertisement{Source: a.Unmap(), ServiceMarkers: markers, Digest: observation.Digest(raw), Truncated: tr})
	}
	return out, ctx.Err()
}
func markers(b []byte) []string {
	printable, _ := observation.Printable(string(b), 8192)
	known := []string{"_http._tcp", "_https._tcp", "_ssh._tcp", "_printer._tcp", "_samsungmsf._tcp", "_airplay._tcp"}
	var out []string
	for _, k := range known {
		if strings.Contains(printable, k) {
			out = append(out, k)
		}
	}
	return out
}
