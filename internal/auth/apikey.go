package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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

func HashKey(key string) string { h := sha256.Sum256([]byte(key)); return hex.EncodeToString(h[:]) }
func MiddlewareHash(next http.Handler, expectedHash string) http.Handler {
	if expectedHash == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("authorization")
		if !strings.HasPrefix(v, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		h := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(expectedHash)) != 1 {
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func MiddlewareVerify(next http.Handler, verify func(string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("authorization")
		if !strings.HasPrefix(v, "Bearer ") || !verify(strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))) {
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
