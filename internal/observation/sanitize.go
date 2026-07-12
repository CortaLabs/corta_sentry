package observation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

var secretHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true}

func SanitizeHeaders(in map[string][]string, maxHeaders, maxValue int) (map[string][]string, bool) {
	out := map[string][]string{}
	truncated := false
	n := 0
	for k, vv := range in {
		if secretHeaders[strings.ToLower(strings.TrimSpace(k))] {
			continue
		}
		if n >= maxHeaders {
			truncated = true
			break
		}
		vals := make([]string, 0, len(vv))
		for _, v := range vv {
			clean, t := Printable(v, maxValue)
			truncated = truncated || t
			vals = append(vals, clean)
		}
		out[k] = vals
		n++
	}
	return out, truncated
}
func Printable(s string, max int) (string, bool) {
	var b strings.Builder
	truncated := false
	for _, r := range s {
		if b.Len() >= max {
			truncated = true
			break
		}
		if unicode.IsPrint(r) && r != '\x7f' {
			b.WriteRune(r)
		} else if unicode.IsSpace(r) {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String()), truncated
}
func Digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
