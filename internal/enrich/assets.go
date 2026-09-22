package enrich

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
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

func LoadCSV(path string) (map[string]Asset, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r := csv.NewReader(f)
	head, e := r.Read()
	if e != nil {
		return nil, e
	}
	idx := map[string]int{}
	for i, h := range head {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	out := map[string]Asset{}
	for {
		row, e := r.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		get := func(k string) string {
			if i, ok := idx[k]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		c, e := strconv.Atoi(get("criticality"))
		if e != nil {
			return nil, fmt.Errorf("asset %s criticality: %w", get("ip"), e)
		}
		a := Asset{IP: get("ip"), Hostname: get("hostname"), Owner: get("owner"), Environment: get("environment"), Criticality: c}
		if a.IP == "" || c < 1 || c > 5 {
			return nil, fmt.Errorf("invalid asset row for %s", a.IP)
		}
		out[a.IP] = a
	}
	return out, nil
}
