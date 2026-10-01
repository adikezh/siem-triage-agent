package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

func TestAccessDynamicKeysRolesAndRevocation(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := StoreAccess(s, "", "")
	var actor string
	h := a.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { actor = Actor(r); w.WriteHeader(204) }), "analyst", "admin")
	request := func(token string) int {
		t.Helper()
		r := httptest.NewRequest("POST", "/write", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if status := request(""); status != 204 || actor != "demo" {
		t.Fatalf("initial demo=%d actor=%s", status, actor)
	}
	key, err := s.CreateAPIKey(context.Background(), "viewer-name", "viewer", "viewer-key")
	if err != nil {
		t.Fatal(err)
	}
	if status := request(""); status != 401 {
		t.Fatalf("new key did not protect existing handler: %d", status)
	}
	if status := request("viewer-key"); status != 403 {
		t.Fatalf("authenticated viewer=%d", status)
	}
	if err = s.RevokeAPIKey(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	if status := request(""); status != 401 {
		t.Fatalf("revoking last key enabled demo=%d", status)
	}
	if status := request("viewer-key"); status != 401 {
		t.Fatalf("revoked key=%d", status)
	}
	if _, err = s.CreateAPIKey(context.Background(), "analyst-name", "analyst", "analyst-key"); err != nil {
		t.Fatal(err)
	}
	if status := request("analyst-key"); status != 204 || actor != "analyst-name" {
		t.Fatalf("analyst=%d actor=%s", status, actor)
	}
}
func TestAccessEnvironmentRoleAndStorageFailure(t *testing.T) {
	for _, role := range []string{"viewer", "analyst", "admin"} {
		t.Run(role, func(t *testing.T) {
			a := Access{EnvHash: HashKey("synthetic-env-key"), EnvRole: role}
			h := a.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if Actor(r) != "environment-key" {
					t.Fatal("missing actor")
				}
				w.WriteHeader(204)
			}), "analyst", "admin")
			for _, token := range []string{"", "wrong", "synthetic-env-key"} {
				r := httptest.NewRequest("POST", "/", nil)
				r.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := 401
				if token == "synthetic-env-key" {
					want = 204
					if role == "viewer" {
						want = 403
					}
				}
				if w.Code != want {
					t.Fatalf("role=%s token case=%t status=%d want=%d", role, token != "", w.Code, want)
				}
			}
		})
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := StoreAccess(s, "", "")
	_ = s.Close()
	w := httptest.NewRecorder()
	a.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("database failure admitted request") }), "admin").ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
