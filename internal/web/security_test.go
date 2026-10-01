package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`name="_csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("no CSRF field: %s", body)
	}
	return match[1]
}

type webClient struct {
	base   string
	client *http.Client
}

func (c webClient) request(t *testing.T, method, path string, data url.Values, origin string) (int, string, http.Header) {
	t.Helper()
	var body io.Reader
	if data != nil {
		body = strings.NewReader(data.Encode())
	}
	r, e := http.NewRequest(method, c.base+path, body)
	if e != nil {
		t.Fatal(e)
	}
	if data != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	response, e := c.client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	b, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	return response.StatusCode, string(b), response.Header
}
func fixture(t *testing.T) (*store.Store, webClient, string) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	id := "5710|agent|203.0.113.10/2026-10-02T00:00:00Z%2F?x#y"
	n := time.Now()
	if e = s.SaveIncident(context.Background(), map[string]any{"summary": "<script>alert(1)</script>", "src_ip": "203.0.113.10"}, id, "5710|agent|203.0.113.10", "high", 80, 3, n, n); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(Handler(s))
	t.Cleanup(server.Close)
	jar, _ := cookiejar.New(nil)
	return s, webClient{server.URL, &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, id
}
func login(t *testing.T, c webClient, key string) string {
	t.Helper()
	status, body, _ := c.request(t, "GET", "/login", nil, "")
	if status != 200 {
		t.Fatalf("login GET=%d", status)
	}
	status, _, headers := c.request(t, "POST", "/login", url.Values{"key": {key}, "_csrf": {csrfFrom(t, body)}}, c.base)
	if status != 303 {
		t.Fatalf("login POST=%d", status)
	}
	if strings.Contains(headers.Get("Set-Cookie"), key) {
		t.Fatal("raw key leaked in cookie")
	}
	_, body, _ = c.request(t, "GET", "/", nil, "")
	return csrfFrom(t, body)
}
func TestCompositeIDAndEscaping(t *testing.T) {
	_, c, id := fixture(t)
	status, body, _ := c.request(t, "GET", incidentURL(id), nil, "")
	if status != 200 {
		t.Fatalf("detail=%d %s", status, body)
	}
	if strings.Contains(body, "<script>alert(1)</script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("untrusted payload not escaped exactly once")
	}
	status, _, headers := c.request(t, "POST", incidentURL(id)+"/feedback", url.Values{"verdict": {"fp"}, "_csrf": {csrfFrom(t, body)}}, c.base)
	if status != 303 || headers.Get("Location") != incidentURL(id) {
		t.Fatalf("feedback=%d redirect=%s", status, headers.Get("Location"))
	}
}
func TestBrowserRoleMatrixAndCSRF(t *testing.T) {
	for _, role := range []string{"viewer", "analyst", "admin"} {
		t.Run(role, func(t *testing.T) {
			s, c, id := fixture(t)
			key := "synthetic-browser-" + role + "-fixture-key"
			if _, e := s.CreateAPIKey(context.Background(), "fixture-"+role, role, key); e != nil {
				t.Fatal(e)
			}
			for _, path := range []string{"/", incidentURL(id), "/suppressions", "/assets", "/stats"} {
				status, _, _ := c.request(t, "GET", path, nil, "")
				if status != 303 {
					t.Fatalf("unauth %s=%d", path, status)
				}
			}
			csrf := login(t, c, key)
			status, body, _ := c.request(t, "GET", incidentURL(id), nil, "")
			if status != 200 {
				t.Fatalf("detail=%d", status)
			}
			if role == "viewer" && strings.Contains(body, `name="verdict"`) {
				t.Fatal("viewer gets write form")
			}
			for _, origin := range []string{"https://attacker.invalid", "null"} {
				status, _, _ := c.request(t, "POST", incidentURL(id)+"/feedback", url.Values{"verdict": {"fp"}, "_csrf": {csrf}}, origin)
				if status != 403 {
					t.Fatalf("origin %s=%d", origin, status)
				}
			}
			status, _, _ = c.request(t, "POST", incidentURL(id)+"/feedback", url.Values{"verdict": {"fp"}}, c.base)
			if status != 403 {
				t.Fatalf("no CSRF=%d", status)
			}
			want := 303
			if role == "viewer" {
				want = 403
			}
			status, _, _ = c.request(t, "POST", incidentURL(id)+"/feedback", url.Values{"verdict": {"fp"}, "comment": {"fixture feedback"}, "actor": {"forged-admin"}, "_csrf": {csrf}}, c.base)
			if status != want {
				t.Fatalf("%s feedback=%d", role, status)
			}
			status, _, _ = c.request(t, "POST", "/suppressions", url.Values{"fingerprint": {"5710|agent|203.0.113.10"}, "action": {"drop"}, "reason": {"fixture noise"}, "created_by": {"forged-admin"}, "_csrf": {csrf}}, c.base)
			if status != want {
				t.Fatalf("%s create=%d", role, status)
			}
			rows, e := s.ListSuppressions(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if role != "viewer" {
				if len(rows) != 1 || rows[0].CreatedBy != "fixture-"+role {
					t.Fatalf("actor=%+v", rows)
				}
				status, _, _ = c.request(t, "POST", suppressionURL(rows[0].ID), url.Values{"_csrf": {csrf}}, c.base)
				deleteWant := 403
				if role == "admin" {
					deleteWant = 303
				}
				if status != deleteWant {
					t.Fatalf("%s delete=%d", role, status)
				}
				feedback, e := s.ListFeedback(context.Background())
				if e != nil || len(feedback) != 1 || feedback[0].Actor != "fixture-"+role {
					t.Fatalf("feedback=%+v err=%v", feedback, e)
				}
			} else if len(rows) != 0 {
				t.Fatal("viewer created suppression")
			}
		})
	}
}
func TestSessionRevocationLogoutAndBootstrap(t *testing.T) {
	s, c, id := fixture(t)
	_, body, _ := c.request(t, "GET", incidentURL(id), nil, "")
	demoCSRF := csrfFrom(t, body)
	key := "synthetic-admin-bootstrap-fixture"
	apiKey, e := s.CreateAPIKey(context.Background(), "test-admin", "admin", key)
	if e != nil {
		t.Fatal(e)
	}
	status, _, _ := c.request(t, "POST", incidentURL(id)+"/feedback", url.Values{"verdict": {"fp"}, "_csrf": {demoCSRF}}, c.base)
	if status != 401 {
		t.Fatalf("old demo session=%d", status)
	}
	csrf := login(t, c, key)
	u, _ := url.Parse(c.base)
	oldCookies := c.client.Jar.Cookies(u)
	status, _, _ = c.request(t, "POST", "/logout", url.Values{"_csrf": {csrf}}, c.base)
	if status != 303 {
		t.Fatalf("logout=%d", status)
	}
	c.client.Jar.SetCookies(u, oldCookies)
	status, _, _ = c.request(t, "GET", incidentURL(id), nil, "")
	if status != 303 {
		t.Fatalf("logged-out cookie replay=%d", status)
	}
	login(t, c, key)
	if e = s.RevokeAPIKey(context.Background(), apiKey.ID); e != nil {
		t.Fatal(e)
	}
	status, _, _ = c.request(t, "GET", incidentURL(id), nil, "")
	if status != 303 {
		t.Fatalf("revoked last key unlocked dashboard=%d", status)
	}
}
func TestSuppressionValidationAndSuggestion(t *testing.T) {
	s, c, id := fixture(t)
	_, body, _ := c.request(t, "GET", incidentURL(id), nil, "")
	csrf := csrfFrom(t, body)
	for _, data := range []url.Values{
		{"action": {"drop"}, "reason": {"match all would be dangerous"}},
		{"action": {"drop"}, "reason": {"bad regex"}, "description": {"["}},
		{"action": {"drop"}, "reason": {"bad CIDR"}, "src_ip": {"10.0.0.0/99"}},
		{"action": {"drop"}, "reason": {"expired"}, "fingerprint": {"fp"}, "expires_at": {"2000-01-01T00:00:00Z"}},
	} {
		data.Set("_csrf", csrf)
		status, _, _ := c.request(t, "POST", "/suppressions", data, c.base)
		if status != 400 {
			t.Fatalf("invalid rule=%d", status)
		}
	}
	for range 3 {
		status, _, _ := c.request(t, "POST", incidentURL(id)+"/feedback", url.Values{"verdict": {"fp"}, "_csrf": {csrf}}, c.base)
		if status != 303 {
			t.Fatal(status)
		}
	}
	_, body, _ = c.request(t, "GET", incidentURL(id), nil, "")
	if !strings.Contains(body, "Review a suppression") {
		t.Fatal("no FP suggestion")
	}
	status, body, _ := c.request(t, "GET", "/suppressions/new?incident="+url.QueryEscape(id), nil, "")
	if status != 200 || !strings.Contains(body, "5710|agent|203.0.113.10") {
		t.Fatal("fingerprint prefill missing")
	}
	rows, e := s.ListSuppressions(context.Background())
	if e != nil || len(rows) != 0 {
		t.Fatal("suggestion created rule without confirmation")
	}
}
func TestLocalesAndStaticAssets(t *testing.T) {
	_, c, _ := fixture(t)
	for _, lang := range []string{"en", "ru", "kk"} {
		status, body, _ := c.request(t, "GET", "/?lang="+lang, nil, "")
		if status != 200 || !strings.Contains(body, fmt.Sprintf(`lang="%s"`, lang)) {
			t.Fatalf("language %s=%d", lang, status)
		}
	}
	for _, path := range []string{"/static/app.css", "/static/htmx.min.js"} {
		status, body, headers := c.request(t, "GET", path, nil, "")
		if status != 200 || len(body) < 1000 || headers.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("asset %s=%d", path, status)
		}
	}
}

func TestDashboardTimeWindows(t *testing.T) {
	s, c, _ := fixture(t)
	n := time.Now()
	for i, age := range []time.Duration{3 * 24 * time.Hour, 10 * 24 * time.Hour} {
		id := fmt.Sprintf("older-%d", i)
		when := n.Add(-age)
		if err := s.SaveIncident(context.Background(), map[string]string{"src_ip": "192.0.2.1"}, id, id, "low", 10, 1, when, when); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		window string
		total  int
	}{{"24h", 1}, {"7d", 2}, {"all", 3}} {
		status, body, _ := c.request(t, "GET", "/stats?range="+tc.window, nil, "")
		if status != 200 || !strings.Contains(body, fmt.Sprintf("Total: %d", tc.total)) {
			t.Fatalf("range %s=%d %s", tc.window, status, body)
		}
	}
	for _, path := range []string{"/stats?range=bad", "/?limit=0", "/?severity=invalid", "/?since=invalid"} {
		status, _, _ := c.request(t, "GET", path, nil, "")
		if status != 400 {
			t.Fatalf("invalid query %s=%d", path, status)
		}
	}
}
