package enrich

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIOC(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ioc.yaml")
	_ = os.WriteFile(p, []byte("malicious_ips: [203.0.113.5]\nmalicious_hashes: [abc]\n"), 0600)
	i, e := LoadIOC(p)
	if e != nil || !i.MaliciousIP("203.0.113.5") || i.MaliciousIP("8.8.8.8") {
		t.Fatalf("%#v %v", i, e)
	}
}
