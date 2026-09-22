package enrich

import "testing"

func TestGeoIPDisabledAndInvalid(t *testing.T) {
	g, err := OpenGeoIP("")
	if err != nil || g != nil {
		t.Fatalf("disabled geoip=%#v err=%v", g, err)
	}
	if got, err := g.Lookup("203.0.113.1"); err != nil || got != "" {
		t.Fatalf("disabled lookup=%q err=%v", got, err)
	}
}
