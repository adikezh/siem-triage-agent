package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Alert struct {
	RuleID, RuleDesc, SrcIP string
	Groups                  []string
	AgentID                 string
	Internal                bool
}
type Suppression struct {
	Match     Match      `yaml:"match"`
	Action    string     `yaml:"action"`
	ExpiresAt *time.Time `yaml:"expires_at"`
	Reason    string     `yaml:"reason"`
	CreatedBy string     `yaml:"created_by"`
}
type Match struct {
	RuleID      string   `yaml:"rule_id"`
	SrcIP       string   `yaml:"src_ip"`
	Description string   `yaml:"description"`
	Groups      []string `yaml:"groups"`
	AgentID     string   `yaml:"agent_id"`
}
type File struct {
	Suppressions []Suppression `yaml:"suppressions"`
}
type Decision struct {
	Suppressed bool
	Downgrade  bool
	Tag        string
	Reason     string
}

func Load(path string) ([]Suppression, error) {
	if path == "" {
		return nil, nil
	}
	b, e := osRead(path)
	if e != nil {
		return nil, e
	}
	var f File
	if e = yaml.Unmarshal(b, &f); e != nil {
		return nil, e
	}
	return f.Suppressions, nil
}
func Evaluate(a Alert, ss []Suppression, now time.Time) Decision {
	for _, s := range ss {
		if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
			continue
		}
		if !matches(a, s.Match) {
			continue
		}
		d := Decision{Reason: s.Reason}
		switch s.Action {
		case "drop":
			d.Suppressed = true
		case "downgrade":
			d.Downgrade = true
		case "tag":
			d.Tag = s.Reason
		}
		return d
	}
	return Decision{}
}
func matches(a Alert, m Match) bool {
	if m.RuleID != "" && a.RuleID != m.RuleID {
		return false
	}
	if m.AgentID != "" && a.AgentID != m.AgentID {
		return false
	}
	if m.SrcIP != "" {
		if p, e := netip.ParsePrefix(m.SrcIP); e == nil {
			ip, e := netip.ParseAddr(a.SrcIP)
			if e != nil || !p.Contains(ip) {
				return false
			}
		} else if ok, _ := filepath.Match(m.SrcIP, a.SrcIP); !ok {
			return false
		}
	}
	if m.Description != "" {
		ok, _ := regexp.MatchString(m.Description, a.RuleDesc)
		if !ok {
			return false
		}
	}
	for _, g := range m.Groups {
		found := false
		for _, ag := range a.Groups {
			if g == ag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func osRead(path string) ([]byte, error) { return os.ReadFile(path) }
