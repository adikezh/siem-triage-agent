package enrich

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type GeoIP struct{ db *geoip2.Reader }

func OpenGeoIP(path string) (*GeoIP, error) {
	if path == "" {
		return nil, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open GeoIP database: %w", err)
	}
	return &GeoIP{db: db}, nil
}

func (g *GeoIP) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

func (g *GeoIP) Lookup(ip string) (string, error) {
	if g == nil || g.db == nil || ip == "" {
		return "", nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	country, err := g.db.Country(parsed)
	if err != nil {
		return "", err
	}
	code := country.Country.IsoCode
	if code == "" {
		return "", nil
	}
	return code, nil
}
