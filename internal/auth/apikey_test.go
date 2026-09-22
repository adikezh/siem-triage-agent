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
