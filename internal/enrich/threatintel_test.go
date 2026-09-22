package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThreatProvidersAndCache(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/check" {
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":90}}`))
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":2}}}}`))
	}))
	defer s.Close()
	ctx := context.Background()
	a := AbuseIPDB{BaseURL: s.URL, APIKey: "x", Client: s.Client()}
	v, err := a.LookupIP(ctx, "1.2.3.4")
	if err != nil || !v.Malicious {
		t.Fatalf("abuse=%#v err=%v", v, err)
	}
	vt := VirusTotal{BaseURL: s.URL, APIKey: "x", Client: s.Client()}
	v, err = vt.LookupIP(ctx, "1.2.3.4")
	if err != nil || !v.Malicious {
		t.Fatalf("vt=%#v err=%v", v, err)
	}
	cache := NewThreatCache(time.Hour)
	_, _ = cache.Lookup(ctx, "1.2.3.4", a)
	_, _ = cache.Lookup(ctx, "1.2.3.4", a)
	if calls != 3 {
		t.Fatalf("expected provider calls=3, got %d", calls)
	}
}
