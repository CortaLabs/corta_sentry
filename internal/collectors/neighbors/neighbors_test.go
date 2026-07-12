package neighbors

import "testing"

func TestParseLinux(t *testing.T) {
	v := Parse("127.0.0.2 dev lo lladdr aa:bb:cc:dd:ee:ff REACHABLE\nmalformed")
	if len(v) != 1 || v[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("%#v", v)
	}
}
