package web

import (
	"github.com/adikezh/siem-triage-agent/internal/store"
	"html/template"
	"net/http"
)

var page = template.Must(template.New("dashboard").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SIEM Triage</title><style>body{font:16px system-ui;margin:2rem;background:#f6f7f9;color:#18212b}main{max-width:1000px;margin:auto}table{width:100%;background:white;border-collapse:collapse}th,td{padding:.7rem;border-bottom:1px solid #ddd;text-align:left}.severity{font-weight:700}</style></head><body><main><h1>SIEM Triage</h1><p>Incidents stored locally in SQLite.</p>{{if .Rows}}<table><thead><tr><th>Fingerprint</th><th>Severity</th><th>Score</th><th>Alerts</th><th>Last seen</th></tr></thead><tbody>{{range .Rows}}<tr><td>{{.Fingerprint}}</td><td class="severity">{{.Severity}}</td><td>{{.Score}}</td><td>{{.AlertCount}}</td><td>{{.LastSeen}}</td></tr>{{end}}</tbody></table>{{else}}<p>No incidents yet.</p>{{end}}</main></body></html>`))

func Handler(s *store.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, e := s.ListIncidents(r.Context())
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_ = page.Execute(w, struct{ Rows []store.Record }{rows})
	})
}
