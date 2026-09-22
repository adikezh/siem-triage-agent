package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestOpenAPI(t *testing.T) {
	w := httptest.NewRecorder()
	OpenAPIHandler().ServeHTTP(w, httptest.NewRequest("GET", "/openapi.json", nil))
	var v map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	if v["openapi"] != "3.0.3" {
		t.Fatal(v)
	}
}
