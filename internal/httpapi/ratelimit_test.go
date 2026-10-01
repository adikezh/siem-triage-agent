package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	h := RateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), 2, time.Minute)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("request %d: got %d", i, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected rate limit response, got %d", w.Code)
	}
}

func TestRateLimitBoundsClientMap(t *testing.T) {
	h := RateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), 2, time.Minute)
	for i := 0; i < 4097; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = fmt.Sprintf("[2001:db8::%x]:1234", i+1)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 204
		if i == 4096 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("client %d=%d", i, w.Code)
		}
	}
}
