package importer

import (
	"context"
	"strings"
	"testing"
)

func FuzzJSONL(f *testing.F) {
	f.Add("{\"id.resp_h\":\"127.0.0.1\",\"id.resp_p\":80}\n")
	f.Add("not-json\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 2<<20 {
			t.Skip()
		}
		_, _ = JSONL(context.Background(), "zeek", strings.NewReader(s), nil, true)
	})
}
func FuzzNmapXML(f *testing.F) {
	f.Add("<nmaprun scanner=\"nmap\"></nmaprun>")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 2<<20 {
			t.Skip()
		}
		_, _ = Nmap(context.Background(), strings.NewReader(s), nil, true)
	})
}
