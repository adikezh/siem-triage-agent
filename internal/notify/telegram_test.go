package notify

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTelegramSender(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botTOKEN/sendMessage" {
			t.Fatal(r.URL.Path)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer srv.Close()
	e := (Telegram{BaseURL: srv.URL, Token: "TOKEN", ChatID: "123"}).Send(context.Background(), store.OutboxItem{Payload: []byte("incident")})
	if e != nil {
		t.Fatal(e)
	}
}
