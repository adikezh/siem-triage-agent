package httpapi

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func RateLimit(next http.Handler, limit int, window time.Duration) http.Handler {
	if limit <= 0 || window <= 0 {
		return next
	}
	type bucket struct {
		started time.Time
		count   int
	}
	var mu sync.Mutex
	buckets := make(map[string]bucket)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		now := time.Now()
		mu.Lock()
		b := buckets[key]
		if b.started.IsZero() || now.Sub(b.started) >= window {
			b = bucket{started: now}
		}
		b.count++
		buckets[key] = b
		allowed := b.count <= limit
		mu.Unlock()
		if !allowed {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
