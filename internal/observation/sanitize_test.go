package observation

import "testing"

func TestSanitizeHeaders(t *testing.T) {
	h, tr := SanitizeHeaders(map[string][]string{"Authorization": {"secret"}, "Set-Cookie": {"x=y"}, "Server": {"ok\x00bad"}}, 10, 4)
	if tr != true {
		t.Fatal("expected truncation")
	}
	if _, ok := h["Authorization"]; ok {
		t.Fatal("secret retained")
	}
	if got := h["Server"][0]; got != "okba" {
		t.Fatalf("got %q", got)
	}
}
