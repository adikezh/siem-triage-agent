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

func TestRoleMiddleware(t *testing.T) {
	h := MiddlewareVerifyRole(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Role(r) != "analyst" {
			t.Errorf("role=%q", Role(r))
		}
		w.WriteHeader(http.StatusNoContent)
	}), func(raw string) (string, bool) { return raw, raw == "analyst" })
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("authorization", "Bearer analyst")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("got %d", w.Code)
	}
}
