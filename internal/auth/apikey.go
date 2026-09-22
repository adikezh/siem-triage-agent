package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

func Middleware(next http.Handler, expected string) http.Handler {
	if expected == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("authorization")
		if !strings.HasPrefix(v, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func RequireKey(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("API key must not be empty")
	}
	return strings.TrimSpace(raw), nil
}
