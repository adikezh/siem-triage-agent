package rules

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

// ValidateInput rejects accidentally global rules and invalid match expressions.
func ValidateInput(m Match, action, reason string) error {
	if action != "drop" && action != "downgrade" && action != "tag" {
		return fmt.Errorf("action must be drop, downgrade or tag")
	}
	if strings.TrimSpace(reason) == "" || len(reason) > 2000 {
		return fmt.Errorf("reason must contain 1..2000 bytes")
	}
	if m.Fingerprint == "" && m.RuleID == "" && m.SrcIP == "" && m.Description == "" && m.AgentID == "" && len(m.Groups) == 0 {
		return fmt.Errorf("at least one match condition is required")
	}
	for _, value := range []string{m.Fingerprint, m.RuleID, m.SrcIP, m.Description, m.AgentID} {
		if len(value) > 1024 {
			return fmt.Errorf("match value is too long")
		}
	}
	if len(m.Groups) > 20 {
		return fmt.Errorf("at most 20 groups are allowed")
	}
	for _, group := range m.Groups {
		if strings.TrimSpace(group) == "" || len(group) > 256 {
			return fmt.Errorf("invalid group")
		}
	}
	if m.Description != "" {
		if _, err := regexp.Compile(m.Description); err != nil {
			return fmt.Errorf("invalid description expression")
		}
	}
	if strings.Contains(m.SrcIP, "/") {
		if _, err := netip.ParsePrefix(m.SrcIP); err != nil {
			return fmt.Errorf("invalid source CIDR")
		}
	} else if _, err := filepath.Match(m.SrcIP, ""); err != nil {
		return fmt.Errorf("invalid source pattern")
	}
	return nil
}
