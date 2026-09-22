package enrich

import "testing"

func TestIsInternal(t *testing.T) {
	if !IsInternal("10.1.2.3", nil) || !IsInternal("192.168.1.5", nil) {
		t.Fatal("RFC1918 address was not recognized")
	}
	if !IsInternal("203.0.113.8", []string{"203.0.113.0/24"}) {
		t.Fatal("configured internal CIDR was not recognized")
	}
	if IsInternal("8.8.8.8", nil) {
		t.Fatal("public address was recognized as internal")
	}
}
