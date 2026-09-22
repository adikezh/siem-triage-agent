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

func TestLoadCSV(t *testing.T) {
	p := filepath.Join(t.TempDir(), "assets.csv")
	if e := os.WriteFile(p, []byte("ip,hostname,owner,environment,criticality\n10.1.2.4,web,soc,prod,4\n"), 0600); e != nil {
		t.Fatal(e)
	}
	m, e := LoadCSV(p)
	if e != nil || m["10.1.2.4"].Criticality != 4 {
		t.Fatalf("%#v %v", m, e)
	}
}
