package connections

import "testing"

func TestParseLinuxConnectionSnapshot(t *testing.T) {
	raw := []byte("tcp ESTAB 0 0 192.168.1.4:55100 93.184.216.34:443 users:((\"browser\",pid=42,fd=7))\nudp UNCONN 0 0 127.0.0.1:5353 224.0.0.251:5353\n")
	got := ParseLinux(raw, 10)
	if len(got) != 2 {
		t.Fatalf("got %d observations", len(got))
	}
	if got[0].TargetIP.String() != "93.184.216.34" || got[0].TargetPort != 443 {
		t.Fatalf("bad remote endpoint: %#v", got[0])
	}
	if got[0].Source != "host_connection" {
		t.Fatalf("bad source %s", got[0].Source)
	}
}
