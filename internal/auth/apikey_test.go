package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware(t *testing.T) {
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), "secret")
	for _, tc := range []struct {
		token string
		code  int
	}{{"", 401}, {"Bearer wrong", 401}, {"Bearer secret", 204}} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("authorization", tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%q got %d", tc.token, w.Code)
		}
	}
}

func TestHashMiddleware(t *testing.T) {
	h := MiddlewareHash(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), HashKey("secret"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("got %d", w.Code)
	}
}
