package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookHMAC(t *testing.T) {
	secret := "s"
	payload := []byte(`{"incident":"i"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(payload)
		if r.Header.Get("x-triage-signature") != hex.EncodeToString(mac.Sum(nil)) {
			t.Error("bad signature")
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	e := (Webhook{URL: srv.URL, Secret: secret}).Send(context.Background(), store.OutboxItem{Channel: "webhook", Payload: payload})
	if e != nil {
		t.Fatal(e)
	}
}
