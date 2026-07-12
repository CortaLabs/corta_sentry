package importer

import (
	"context"
	"strings"
	"testing"
)

func TestNmapFixture(t *testing.T) {
	x := `<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="fixture" version="1"/></port></ports></host></nmaprun>`
	n, err := Nmap(context.Background(), strings.NewReader(x), nil, true)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
func TestJSONLBoundsAndMalformed(t *testing.T) {
	if _, err := JSONL(context.Background(), "zeek", strings.NewReader("not json\n"), nil, true); err == nil {
		t.Fatal("malformed accepted")
	}
	big := "{\"id.resp_h\":\"127.0.0.1\",\"x\":\"" + strings.Repeat("x", MaxRecordBytes) + "\"}\n"
	if _, err := JSONL(context.Background(), "zeek", strings.NewReader(big), nil, true); err == nil {
		t.Fatal("oversized accepted")
	}
}
