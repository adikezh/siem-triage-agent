package enrich

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndApply(t *testing.T) {
	p := filepath.Join(t.TempDir(), "assets.yaml")
	if e := os.WriteFile(p, []byte("assets:\n  - ip: 10.1.2.3\n    hostname: db\n    criticality: 5\n"), 0600); e != nil {
		t.Fatal(e)
	}
	m, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	a, ok := Apply(m, "10.1.2.3")
	if !ok || a.Criticality != 5 || a.Hostname != "db" {
		t.Fatalf("%#v %v", a, ok)
	}
}
