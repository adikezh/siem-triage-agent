package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/auth"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

func TestSessionCookieExpiryAndCapacity(t *testing.T) {
	s := sessions{values: map[string]session{}}
	r := httptest.NewRequest("GET", "https://triage.example/", nil)
	w := httptest.NewRecorder()
	v, err := s.create(w, r, "hash", false)
	if err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || strings.Contains(c.Value, "hash") || c.MaxAge != int(sessionTTL.Seconds()) {
		t.Fatalf("unsafe cookie: %+v", c)
	}
	r.AddCookie(c)
	if got, ok := s.get(r); !ok || got.ID != v.ID {
		t.Fatal("session lookup failed")
	}
	v.Expires = time.Now().Add(-time.Second)
	s.values[v.ID] = v
	if _, ok := s.get(r); ok || len(s.values) != 0 {
		t.Fatal("expired session retained")
	}
	for i := range 4096 {
		s.values[str(i)] = session{Expires: time.Now().Add(time.Hour)}
	}
	if _, err = s.create(httptest.NewRecorder(), r, "", false); err == nil {
		t.Fatal("unbounded session map")
	}
}
func TestExplicitHTTPSProxyOrigin(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := NewHandler(s, Config{PublicOrigin: "https://triage.example", SecureCookies: true, Access: auth.Access{EnvHash: auth.HashKey("synthetic-proxy-key"), EnvRole: "admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://backend/login", nil))
	csrf := csrfFrom(t, w.Body.String())
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure {
		t.Fatal("proxy cookie is not secure")
	}
	for _, origin := range []string{"https://attacker.example", "http://backend", "https://triage.example"} {
		r := httptest.NewRequest("POST", "http://backend/login", strings.NewReader(url.Values{"_csrf": {csrf}, "key": {"synthetic-proxy-key"}}.Encode()))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Forwarded-Host", "triage.example")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 403
		if origin == "https://triage.example" {
			want = 303
		}
		if w.Code != want {
			t.Fatalf("origin %s=%d want %d", origin, w.Code, want)
		}
	}
}
