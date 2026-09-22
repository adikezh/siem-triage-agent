package enrich

import "net/netip"

var defaultInternalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func IsInternal(ip string, extraCIDRs []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, raw := range append(defaultInternalCIDRs, extraCIDRs...) {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}
