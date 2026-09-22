package enrich

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type Asset struct {
	IP, Hostname, Owner, Environment string
	Criticality                      int
	Tags                             []string `yaml:"tags"`
}
type File struct {
	Assets []Asset `yaml:"assets"`
}

func Load(path string) (map[string]Asset, error) {
	out := map[string]Asset{}
	if path == "" {
		return out, nil
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var f File
	if e = yaml.Unmarshal(b, &f); e != nil {
		return nil, e
	}
	for _, a := range f.Assets {
		if a.IP == "" {
			return nil, fmt.Errorf("asset IP is required")
		}
		if a.Criticality < 1 || a.Criticality > 5 {
			return nil, fmt.Errorf("asset %s criticality must be 1..5", a.IP)
		}
		out[a.IP] = a
	}
	return out, nil
}
func Apply(a map[string]Asset, ip string) (Asset, bool) { x, ok := a[ip]; return x, ok }
