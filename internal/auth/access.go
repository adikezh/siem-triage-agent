package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

type Identity struct{ Actor, Role string }
type identityKey struct{}

func WithIdentity(r *http.Request, who Identity) *http.Request {
	ctx := context.WithValue(r.Context(), identityKey{}, who)
	ctx = context.WithValue(ctx, roleKey{}, who.Role)
	return r.WithContext(ctx)
}
func Actor(r *http.Request) string {
	who, _ := r.Context().Value(identityKey{}).(Identity)
	return who.Actor
}
func Allowed(role string, roles ...string) bool {
	for _, candidate := range roles {
		if role == candidate {
			return true
		}
	}
	return false
}

// Access resolves identities on every request, including browser sessions.
// Initialized reports whether key authentication was ever configured, not just
// whether any unrevoked keys remain. Revoking the last key must not enable demo.
type Access struct {
	EnvHash, EnvRole string
	Initialized      func(context.Context) (bool, error)
	Lookup           func(context.Context, string) (Identity, bool, error)
}

func (a Access) Required(ctx context.Context) (bool, error) {
	if a.EnvHash != "" {
		return true, nil
	}
	if a.Initialized == nil {
		return false, nil
	}
	return a.Initialized(ctx)
}
func (a Access) Resolve(ctx context.Context, hash string) (Identity, bool, error) {
	if a.EnvHash != "" && subtle.ConstantTimeCompare([]byte(a.EnvHash), []byte(hash)) == 1 {
		return Identity{Actor: "environment-key", Role: a.EnvRole}, true, nil
	}
	if a.Lookup == nil {
		return Identity{}, false, nil
	}
	return a.Lookup(ctx, hash)
}
func (a Access) Protect(next http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		required, err := a.Required(r.Context())
		if err != nil {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		who := Identity{Actor: "demo", Role: "admin"}
		if required {
			v := r.Header.Get("Authorization")
			if !strings.HasPrefix(v, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			var ok bool
			who, ok, err = a.Resolve(r.Context(), HashKey(strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))))
			if err != nil {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
				return
			}
			if !ok {
				http.Error(w, "invalid API key", http.StatusUnauthorized)
				return
			}
		}
		if !Allowed(who.Role, roles...) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, WithIdentity(r, who))
	})
}
