package connections

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/observation"
)

const Version = "host-connections/1.0.0"

func Snapshot(ctx context.Context, maxRecords int) ([]domain.Observation, error) {
	if maxRecords < 1 || maxRecords > 10000 {
		return nil, errors.New("connection record budget must be 1..10000")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("host connection snapshots currently support Linux; macOS and Windows adapters are pending")
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ss", "-H", "-tunap").Output()
	if err != nil {
		return nil, err
	}
	if len(out) > 4<<20 {
		return nil, errors.New("connection table output exceeds 4 MiB")
	}
	return ParseLinux(out, maxRecords), nil
}

func ParseLinux(raw []byte, maxRecords int) []domain.Observation {
	lines := strings.Split(string(raw), "\n")
	out := make([]domain.Observation, 0)
	now := time.Now().UTC()
	for _, line := range lines {
		if len(out) >= maxRecords {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		remoteIP, remotePort, ok := endpoint(fields[5])
		if !ok || remoteIP.IsUnspecified() {
			continue
		}
		localIP, localPort, _ := endpoint(fields[4])
		process := ""
		if len(fields) > 6 {
			process, _ = observation.Printable(strings.Join(fields[6:], " "), 1024)
		}
		scope := "public"
		if remoteIP.IsPrivate() || remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast() {
			scope = "local_or_private"
		}
		evidence, _ := json.Marshal(map[string]any{"state": fields[1], "direction": "locally_observed", "local_ip": localIP.String(), "local_port": localPort, "remote_ip": remoteIP.String(), "remote_port": remotePort, "remote_scope": scope, "process_excerpt": process, "classification": "unreviewed_connection"})
		out = append(out, domain.Observation{SensorID: "local-node", ObservedAt: now, Source: domain.SourceHostConnection, TargetIP: remoteIP, TargetPort: remotePort, Transport: fields[0], Application: "host_connection", Evidence: evidence, RawDigest: observation.Digest([]byte(line)), CollectorVersion: Version, Provenance: json.RawMessage(`{"method":"ss -H -tunap","passive":true,"claim":"observed_connection_not_maliciousness"}`)})
	}
	return out
}

func endpoint(value string) (netip.Addr, int, bool) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		index := strings.LastIndex(value, ":")
		if index < 1 {
			return netip.Addr{}, 0, false
		}
		host, portText = value[:index], value[index+1:]
	}
	host = strings.Trim(host, "[]")
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return netip.Addr{}, 0, false
	}
	return address.Unmap(), port, true
}
