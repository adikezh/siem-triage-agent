package enrich

import (
	"gopkg.in/yaml.v3"
	"os"
)

type IOCFile struct {
	IPs    []string `yaml:"malicious_ips"`
	Hashes []string `yaml:"malicious_hashes"`
}
type IOC struct {
	IPs    map[string]bool
	Hashes map[string]bool
}

func LoadIOC(path string) (IOC, error) {
	out := IOC{IPs: map[string]bool{}, Hashes: map[string]bool{}}
	if path == "" {
		return out, nil
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return out, e
	}
	var f IOCFile
	if e = yaml.Unmarshal(b, &f); e != nil {
		return out, e
	}
	for _, x := range f.IPs {
		out.IPs[x] = true
	}
	for _, x := range f.Hashes {
		out.Hashes[x] = true
	}
	return out, nil
}
func (i IOC) MaliciousIP(ip string) bool { return i.IPs[ip] }
