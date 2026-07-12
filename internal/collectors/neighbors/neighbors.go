package neighbors

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Entry struct {
	IP        netip.Addr `json:"ip"`
	MAC       string     `json:"mac,omitempty"`
	Interface string     `json:"interface,omitempty"`
	State     string     `json:"state,omitempty"`
}

func Collect(ctx context.Context) ([]Entry, error) {
	var name string
	var args []string
	switch runtime.GOOS {
	case "linux":
		name = "ip"
		args = []string{"neigh", "show"}
	case "darwin":
		name = "arp"
		args = []string{"-an"}
	case "windows":
		name = "arp"
		args = []string{"-a"}
	default:
		return nil, errors.New("unsupported neighbor platform")
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	if err != nil {
		return nil, err
	}
	return Parse(string(out)), nil
}
func Parse(raw string) []Entry {
	var out []Entry
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		var ip netip.Addr
		var mac, iface, state string
		for i, v := range f {
			clean := strings.Trim(v, "()? ,")
			if a, e := netip.ParseAddr(clean); e == nil {
				ip = a.Unmap()
			}
			if v == "lladdr" && i+1 < len(f) {
				mac = strings.ToLower(f[i+1])
			}
			if v == "dev" && i+1 < len(f) {
				iface = f[i+1]
			}
			if strings.Count(clean, ":") == 5 && len(clean) >= 17 {
				mac = strings.ToLower(clean)
			}
			if v == "REACHABLE" || v == "STALE" || v == "DELAY" || v == "FAILED" {
				state = v
			}
		}
		if ip.IsValid() {
			out = append(out, Entry{IP: ip, MAC: mac, Interface: iface, State: state})
		}
	}
	return out
}
