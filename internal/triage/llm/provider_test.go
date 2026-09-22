package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAICompatibleAndValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer test" {
			t.Errorf("missing auth")
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"severity\":\"high\",\"summary\":\"review\",\"actions\":[\"collect_evidence\"],\"fp_probability\":0.1}"}}]}`))
	}))
	defer srv.Close()
	p := OpenAICompatible{BaseURL: srv.URL, APIKey: "test"}
	got, e := p.Complete(context.Background(), Request{Model: "demo", Prompt: "untrusted data"})
	if e != nil {
		t.Fatal(e)
	}
	if got.Severity != "high" {
		t.Fatalf("got %#v", got)
	}
}
func TestRejectsUnsupportedAction(t *testing.T) {
	if e := Validate(Response{Severity: "high", Actions: []string{"delete_everything"}}); e == nil || !strings.Contains(e.Error(), "unsupported action") {
		t.Fatalf("expected action rejection, got %v", e)
	}
}
