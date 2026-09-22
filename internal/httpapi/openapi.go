package httpapi

import (
	"encoding/json"
	"net/http"
)

func OpenAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{"openapi": "3.0.3", "info": map[string]string{"title": "SIEM Triage API", "version": "0.1.0"}, "paths": map[string]any{"/health": map[string]any{"get": map[string]string{"summary": "Health check"}}, "/metrics": map[string]any{"get": map[string]string{"summary": "Prometheus metrics"}}, "/api/incidents": map[string]any{"get": map[string]string{"summary": "List incidents"}}, "/api/incidents/{id}": map[string]any{"get": map[string]string{"summary": "Get incident"}}, "/api/stats": map[string]any{"get": map[string]string{"summary": "Incident statistics"}}, "/api/incidents/feedback": map[string]any{"post": map[string]string{"summary": "Record analyst feedback"}}, "/api/suppressions": map[string]any{"get": map[string]string{"summary": "List suppressions"}, "post": map[string]string{"summary": "Create suppression"}}, "/api/suppressions/{id}": map[string]any{"delete": map[string]string{"summary": "Delete suppression"}}, "/api/integrations/telegram/callback": map[string]any{"post": map[string]string{"summary": "Process Telegram callback"}}, "/api/integrations/slack/callback": map[string]any{"post": map[string]string{"summary": "Process Slack action"}}}}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
}
