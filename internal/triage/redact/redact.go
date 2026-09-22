package redact

import (
	"net/netip"
	"regexp"
	"strings"
)

var email = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
var user = regexp.MustCompile(`(?i)(user(name)?|login)\s*[:=]\s*([A-Za-z0-9._-]+)`)
var ip = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func Text(s string, internalCIDRs []string) string {
	s = email.ReplaceAllString(s, "email_1")
	s = user.ReplaceAllString(s, "$1=user_1")
	return ip.ReplaceAllStringFunc(s, func(v string) string {
		a, e := netip.ParseAddr(v)
		if e != nil {
			return v
		}
		for _, raw := range internalCIDRs {
			p, e := netip.ParsePrefix(raw)
			if e == nil && p.Contains(a) {
				return "10.x.x.A"
			}
		}
		return v
	})
}
func JSONSafe(fields map[string]string, cidrs []string) map[string]string {
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = Text(v, cidrs)
	}
	return out
}

var _ = strings.TrimSpace
