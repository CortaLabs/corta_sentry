package importer

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/observation"
	"io"
	"net/netip"
	"strings"
	"time"
)

const MaxImportBytes = 64 << 20
const MaxRecordBytes = 1 << 20

type Sink interface {
	AddObservation(context.Context, *domain.Observation) error
}
type NmapRun struct {
	Scanner string `xml:"scanner,attr"`
	Version string `xml:"version,attr"`
	Hosts   []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			Port     int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

func Nmap(ctx context.Context, r io.Reader, sink Sink, dry bool) (int, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxImportBytes+1))
	if err != nil {
		return 0, err
	}
	if len(b) > MaxImportBytes {
		return 0, errors.New("Nmap XML exceeds 64 MiB")
	}
	var run NmapRun
	if err = xml.Unmarshal(b, &run); err != nil {
		return 0, fmt.Errorf("Nmap XML: %w", err)
	}
	if run.Scanner != "" && run.Scanner != "nmap" {
		return 0, errors.New("XML is not an Nmap run")
	}
	count := 0
	for _, h := range run.Hosts {
		var addr netip.Addr
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				addr, err = netip.ParseAddr(a.Addr)
				if err == nil {
					addr = addr.Unmap()
					break
				}
			}
		}
		if !addr.IsValid() {
			continue
		}
		for _, p := range h.Ports {
			e, _ := json.Marshal(map[string]any{"state": p.State.State, "service": p.Service.Name, "product": bounded(p.Service.Product, 512), "version": bounded(p.Service.Version, 256)})
			o := domain.Observation{SensorID: "import", ObservedAt: time.Now().UTC(), Source: domain.SourceImportedNmap, TargetIP: addr, TargetPort: p.Port, Transport: p.Protocol, Application: p.Service.Name, Evidence: e, RawDigest: observation.Digest(b), CollectorVersion: "importer/nmap-1.0.0", Provenance: json.RawMessage(fmt.Sprintf(`{"tool":"nmap","version":%q}`, run.Version))}
			count++
			if !dry && sink != nil {
				if err = sink.AddObservation(ctx, &o); err != nil {
					return count, err
				}
			}
		}
	}
	return count, nil
}
func JSONL(ctx context.Context, kind string, r io.Reader, sink Sink, dry bool) (int, error) {
	sources := map[string]domain.ObservationSource{"zeek": domain.SourceImportedZeek, "suricata": domain.SourceImportedSuricata, "nuclei": domain.SourceImportedNuclei}
	source, ok := sources[kind]
	if !ok {
		return 0, errors.New("unsupported JSONL type")
	}
	cr := &countingReader{r: io.LimitReader(r, MaxImportBytes+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64<<10), MaxRecordBytes)
	count := 0
	for sc.Scan() {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		line := sc.Bytes()
		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			return count, fmt.Errorf("record %d: %w", count+1, err)
		}
		ip := firstString(raw, "id.resp_h", "dest_ip", "host", "ip")
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			if kind == "nuclei" {
				continue
			}
			return count, fmt.Errorf("record %d target IP: %w", count+1, err)
		}
		port := firstInt(raw, "id.resp_p", "dest_port", "port")
		safe := sanitizeMap(raw)
		e, err := json.Marshal(safe)
		if err != nil {
			return count, err
		}
		o := domain.Observation{SensorID: "import", ObservedAt: time.Now().UTC(), Source: source, TargetIP: addr.Unmap(), TargetPort: port, Evidence: e, RawDigest: observation.Digest(line), CollectorVersion: "importer/" + kind + "-1.0.0", Provenance: json.RawMessage(fmt.Sprintf(`{"tool":%q,"evidence_level":"unverified_import"}`, kind))}
		count++
		if !dry && sink != nil {
			if err = sink.AddObservation(ctx, &o); err != nil {
				return count, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return count, fmt.Errorf("JSONL record too large or unreadable: %w", err)
	}
	if cr.n > MaxImportBytes {
		return count, errors.New("JSONL import exceeds 64 MiB")
	}
	return count, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
func bounded(s string, n int) string { v, _ := observation.Printable(s, n); return v }
func firstString(m map[string]any, ks ...string) string {
	for _, k := range ks {
		if v, ok := m[k].(string); ok {
			return strings.TrimSpace(strings.TrimPrefix(v, "http://"))
		}
	}
	return ""
}
func firstInt(m map[string]any, ks ...string) int {
	for _, k := range ks {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case json.Number:
			n, _ := v.Int64()
			return int(n)
		}
	}
	return 0
}
func sanitizeMap(m map[string]any) map[string]any {
	out := map[string]any{}
	n := 0
	for k, v := range m {
		if n >= 200 {
			break
		}
		lk := strings.ToLower(k)
		if strings.Contains(lk, "authorization") || strings.Contains(lk, "cookie") {
			continue
		}
		switch x := v.(type) {
		case string:
			out[k] = bounded(x, 4096)
		case float64, bool, nil:
			out[k] = x
		default:
			b, _ := json.Marshal(x)
			if len(b) <= 16<<10 {
				out[k] = x
			}
		}
		n++
	}
	return out
}
