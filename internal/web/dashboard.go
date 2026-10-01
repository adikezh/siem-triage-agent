package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/adikezh/siem-triage-agent/internal/auth"
	"github.com/adikezh/siem-triage-agent/internal/enrich"
	"github.com/adikezh/siem-triage-agent/internal/httpapi"
	"github.com/adikezh/siem-triage-agent/internal/rules"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

//go:embed static/*
var static embed.FS

type Config struct {
	Assets        map[string]enrich.Asset
	Access        auth.Access
	Language      string
	SecureCookies bool
	PublicOrigin  string
}
type dashboard struct {
	store    *store.Store
	config   Config
	sessions sessions
	files    http.Handler
}
type countItem struct {
	Name  string
	Count int
}
type viewModel struct {
	Actions                                                                    []string
	SrcIP, AgentID                                                             string
	Lang, Page, CSRF, Error, Fingerprint, Raw, Summary, Severity, Since, Range string
	Who                                                                        auth.Identity
	Demo, Suggest                                                              bool
	Rows                                                                       []store.Record
	Detail                                                                     store.Record
	Feedback                                                                   []store.FeedbackRecord
	Suppressions                                                               []store.SuppressionRecord
	Assets                                                                     []enrich.Asset
	Counts, TopSrcIP, TopMITRE                                                 []countItem
	Metrics                                                                    store.MetricsSnapshot
	Total                                                                      int
	FPPercent                                                                  float64
}

func (v viewModel) CanWrite() bool   { return auth.Allowed(v.Who.Role, "analyst", "admin") }
func (v viewModel) CanDelete() bool  { return v.Who.Role == "admin" }
func incidentURL(id string) string   { return "/incidents/" + url.PathEscape(id) }
func suppressionURL(id int64) string { return fmt.Sprintf("/suppressions/%d/delete", id) }
func str(n int) string               { return strconv.Itoa(n) }
func decimal(n float64) string       { return fmt.Sprintf("%.1f", n) }
func topCounts(values map[string]int, limit int) []countItem {
	out := make([]countItem, 0, len(values))
	for name, count := range values {
		out = append(out, countItem{name, count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
func Handler(s *store.Store) http.Handler { return HandlerWithAssets(s, nil) }
func HandlerWithAssets(s *store.Store, assets map[string]enrich.Asset) http.Handler {
	return NewHandler(s, Config{Assets: assets, Access: auth.StoreAccess(s, "", "")})
}
func NewHandler(s *store.Store, cfg Config) http.Handler {
	assets, _ := fs.Sub(static, "static")
	if cfg.Access.Initialized == nil {
		cfg.Access = auth.StoreAccess(s, cfg.Access.EnvHash, cfg.Access.EnvRole)
	}
	return httpapi.RateLimit(&dashboard{store: s, config: cfg, sessions: sessions{values: make(map[string]session)}, files: http.StripPrefix("/static/", http.FileServer(http.FS(assets)))}, 120, time.Minute)
}
func (d *dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if strings.HasPrefix(r.URL.Path, "/static/") {
		d.files.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	required, err := d.config.Access.Required(r.Context())
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	v := viewModel{Lang: language(d.config.Language), Demo: !required, Range: r.URL.Query().Get("range")}
	if c, e := r.Cookie("triage_language"); e == nil {
		v.Lang = language(c.Value)
	}
	if lang := r.URL.Query().Get("lang"); lang != "" {
		v.Lang = language(lang)
		http.SetCookie(w, &http.Cookie{Name: "triage_language", Value: v.Lang, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: d.config.SecureCookies || r.TLS != nil})
	}
	sess, ok := d.sessions.get(r)
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !ok || !checkCSRF(r, sess, d.config.PublicOrigin) {
			http.Error(w, "invalid CSRF token or origin", http.StatusForbidden)
			return
		}
	}
	if r.URL.Path == "/login" {
		if !ok {
			sess, err = d.sessions.create(w, r, "", d.config.SecureCookies)
			if err != nil {
				http.Error(w, "session unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		v.CSRF = sess.CSRF
		v.Page = "login"
		if r.Method == http.MethodPost {
			key := strings.TrimSpace(r.PostForm.Get("key"))
			_, valid, e := d.config.Access.Resolve(r.Context(), auth.HashKey(key))
			if e != nil {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
				return
			}
			if valid {
				if _, e = d.sessions.create(w, r, auth.HashKey(key), d.config.SecureCookies); e != nil {
					http.Error(w, "session unavailable", http.StatusServiceUnavailable)
					return
				}
				d.sessions.remove(sess.ID)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			v.Error = v.T("Invalid API key")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
		} else if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d.render(w, r, v)
		return
	}
	who := auth.Identity{Actor: "demo", Role: "admin"}
	if required {
		var valid bool
		if ok && sess.KeyHash != "" {
			who, valid, err = d.config.Access.Resolve(r.Context(), sess.KeyHash)
		}
		if err != nil {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		if !valid {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "authentication required", http.StatusUnauthorized)
			}
			return
		}
	}
	if !ok {
		sess, err = d.sessions.create(w, r, "", d.config.SecureCookies)
		if err != nil {
			http.Error(w, "session unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	v.Who = who
	v.CSRF = sess.CSRF
	if r.Method == http.MethodPost {
		if r.URL.Path == "/logout" {
			d.sessions.remove(sess.ID)
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: d.config.SecureCookies || r.TLS != nil, MaxAge: -1})
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !v.CanWrite() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/incidents/") && strings.HasSuffix(r.URL.EscapedPath(), "/feedback") {
			id, e := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), "/incidents/"), "/feedback"))
			if e != nil {
				http.Error(w, "invalid ID", http.StatusBadRequest)
				return
			}
			verdict, comment := r.PostForm.Get("verdict"), r.PostForm.Get("comment")
			if !auth.Allowed(verdict, "tp", "fp", "ack") || len(comment) > 2000 {
				http.Error(w, "invalid verdict or comment", http.StatusBadRequest)
				return
			}
			if _, e = d.store.GetIncident(r.Context(), id); e != nil {
				http.NotFound(w, r)
				return
			}
			if e = d.store.AddFeedback(r.Context(), id, verdict, comment, who.Actor); e != nil {
				http.Error(w, "could not save feedback", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, incidentURL(id), http.StatusSeeOther)
			return
		}
		if r.URL.Path == "/suppressions" {
			d.createSuppression(w, r, v)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/suppressions/") && strings.HasSuffix(r.URL.Path, "/delete") {
			if !v.CanDelete() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			id, e := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/suppressions/"), "/delete"), 10, 64)
			if e != nil || id <= 0 {
				http.Error(w, "invalid ID", http.StatusBadRequest)
				return
			}
			if e = d.store.DeleteSuppressionBy(r.Context(), id, who.Actor); e != nil {
				http.Error(w, "could not delete suppression", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/suppressions", http.StatusSeeOther)
			return
		}
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch {
	case r.URL.Path == "/":
		v.Page = "incidents"
		v.Severity = r.URL.Query().Get("severity")
		v.Since = r.URL.Query().Get("since")
		if v.Severity != "" && !auth.Allowed(v.Severity, "low", "medium", "high", "critical") {
			http.Error(w, "invalid severity", http.StatusBadRequest)
			return
		}
		if v.Since != "" {
			if _, e := time.Parse(time.RFC3339, v.Since); e != nil {
				http.Error(w, "invalid since", http.StatusBadRequest)
				return
			}
		}
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			n, e := strconv.Atoi(raw)
			if e != nil || n < 1 || n > 1000 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
			limit = n
		}
		v.Rows, err = d.store.ListIncidentsFiltered(r.Context(), v.Severity, v.Since, limit)
	case strings.HasPrefix(r.URL.Path, "/incidents/"):
		v.Page = "detail"
		id, e := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/incidents/"))
		if e != nil {
			http.Error(w, "invalid ID", http.StatusBadRequest)
			return
		}
		v.Detail, err = d.store.GetIncident(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var pretty bytes.Buffer
		if e = json.Indent(&pretty, v.Detail.Payload, "", "  "); e == nil {
			v.Raw = pretty.String()
		} else {
			v.Raw = string(v.Detail.Payload)
		}
		var payload struct {
			Triage struct {
				Summary string `json:"Summary"`
			} `json:"triage"`
			Summary string   `json:"summary"`
			Actions []string `json:"actions"`
			SrcIP   string   `json:"src_ip"`
			AgentID string   `json:"agent_id"`
		}
		_ = json.Unmarshal(v.Detail.Payload, &payload)
		v.Actions, v.SrcIP, v.AgentID = payload.Actions, payload.SrcIP, payload.AgentID
		v.Summary = payload.Triage.Summary
		if v.Summary == "" {
			v.Summary = payload.Summary
		}
		var feedback []store.FeedbackRecord
		feedback, err = d.store.ListFeedback(r.Context())
		for _, x := range feedback {
			if x.IncidentID == id {
				v.Feedback = append(v.Feedback, x)
			}
		}
		if err == nil {
			var n int
			n, err = d.store.FalsePositiveCount(r.Context(), v.Detail.Fingerprint)
			v.Suggest = n >= 3
		}
	case r.URL.Path == "/suppressions":
		v.Page = "suppressions"
		v.Suppressions, err = d.store.ListSuppressions(r.Context())
	case r.URL.Path == "/suppressions/new":
		if !v.CanWrite() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		v.Page = "new-suppression"
		if id := r.URL.Query().Get("incident"); id != "" {
			var x store.Record
			x, err = d.store.GetIncident(r.Context(), id)
			v.Fingerprint = x.Fingerprint
		}
	case r.URL.Path == "/assets":
		v.Page = "assets"
		for _, x := range d.config.Assets {
			v.Assets = append(v.Assets, x)
		}
		sort.Slice(v.Assets, func(i, j int) bool { return v.Assets[i].IP < v.Assets[j].IP })
	case r.URL.Path == "/stats":
		if v.Range != "" && !auth.Allowed(v.Range, "all", "24h", "7d") {
			http.Error(w, "invalid range", http.StatusBadRequest)
			return
		}
		err = d.stats(r, &v)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	d.render(w, r, v)
}
func (d *dashboard) render(w http.ResponseWriter, r *http.Request, v viewModel) {
	var b bytes.Buffer
	if err := screen(v).Render(r.Context(), &b); err != nil {
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}
func (d *dashboard) createSuppression(w http.ResponseWriter, r *http.Request, v viewModel) {
	m := rules.Match{Fingerprint: strings.TrimSpace(r.PostForm.Get("fingerprint")), RuleID: strings.TrimSpace(r.PostForm.Get("rule_id")), SrcIP: strings.TrimSpace(r.PostForm.Get("src_ip")), AgentID: strings.TrimSpace(r.PostForm.Get("agent_id")), Description: strings.TrimSpace(r.PostForm.Get("description"))}
	if groups := r.PostForm.Get("groups"); strings.TrimSpace(groups) != "" {
		for _, g := range strings.Split(groups, ",") {
			m.Groups = append(m.Groups, strings.TrimSpace(g))
		}
	}
	action, reason, expires := r.PostForm.Get("action"), strings.TrimSpace(r.PostForm.Get("reason")), strings.TrimSpace(r.PostForm.Get("expires_at"))
	err := rules.ValidateInput(m, action, reason)
	if expires != "" && err == nil {
		t, e := time.Parse(time.RFC3339, expires)
		if e != nil || !t.After(time.Now()) {
			err = fmt.Errorf("expiration must be a future RFC3339 timestamp")
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(m)
	if _, err = d.store.CreateSuppressionWithMatch(r.Context(), "", string(b), action, reason, expires, v.Who.Actor); err != nil {
		http.Error(w, "could not save suppression", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/suppressions", http.StatusSeeOther)
}
func (d *dashboard) stats(r *http.Request, v *viewModel) error {
	v.Page = "stats"
	since := ""
	switch v.Range {
	case "24h":
		since = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	case "7d":
		since = time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano)
	case "", "all":
		v.Range = "all"
	default:
		return fmt.Errorf("invalid range")
	}
	rows, err := d.store.ListIncidentsFiltered(r.Context(), "", since, 0)
	if err != nil {
		return err
	}
	v.Total = len(rows)
	v.Metrics, err = d.store.Metrics(r.Context())
	if err != nil {
		return err
	}
	counts, srcIPs, tactics := map[string]int{}, map[string]int{}, map[string]int{}
	for _, row := range rows {
		counts[row.Severity]++
		var x struct {
			SrcIP        string   `json:"src_ip"`
			MITRETactics []string `json:"mitre_tactics"`
		}
		if json.Unmarshal(row.Payload, &x) == nil {
			if x.SrcIP != "" {
				srcIPs[x.SrcIP]++
			}
			for _, t := range x.MITRETactics {
				tactics[t]++
			}
		}
	}
	for _, name := range []string{"critical", "high", "medium", "low"} {
		v.Counts = append(v.Counts, countItem{name, counts[name]})
	}
	v.TopSrcIP = topCounts(srcIPs, 10)
	v.TopMITRE = topCounts(tactics, 10)
	if total := v.Metrics.FeedbackTP + v.Metrics.FeedbackFP; total > 0 {
		v.FPPercent = float64(v.Metrics.FeedbackFP) * 100 / float64(total)
	}
	return nil
}

// Safe URLs are constructed only from fixed routes and percent-encoded IDs.
func safe(path string) templ.SafeURL { return templ.SafeURL(path) }
