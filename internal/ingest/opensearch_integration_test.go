package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This test uses a real local OpenSearch, not a mock search response. Each run
// owns a uniquely named test index and deletes only that index on completion.
func TestOpenSearchEqualTimestampPaginationAndRestart(t *testing.T) {
	base := strings.TrimRight(os.Getenv("TRIAGE_TEST_OPENSEARCH_URL"), "/")
	if base == "" {
		t.Skip("set TRIAGE_TEST_OPENSEARCH_URL to run the real OpenSearch test")
	}
	index := fmt.Sprintf("triage-integration-%d", time.Now().UnixNano())
	client := &http.Client{Timeout: 15 * time.Second}
	request := func(method, path, body string) {
		t.Helper()
		r, err := http.NewRequestWithContext(context.Background(), method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil || response.StatusCode/100 != 2 {
			t.Fatalf("%s %s: status=%d body=%s err=%v", method, path, response.StatusCode, payload, err)
		}
	}
	request(http.MethodPut, "/"+index, `{"settings":{"number_of_shards":2,"number_of_replicas":0},"mappings":{"properties":{"@timestamp":{"type":"date_nanos"},"id":{"type":"keyword"}}}}`)
	t.Cleanup(func() { request(http.MethodDelete, "/"+index, "") })
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		request(http.MethodPut, "/"+index+"/_doc/"+id+"?refresh=true", fmt.Sprintf(`{"@timestamp":"2026-10-02T08:00:00.000000001Z","id":%q}`, id))
	}
	for _, kind := range []string{"wazuh", "generic"} {
		t.Run(kind, func(t *testing.T) {
			var source interface {
				Search(context.Context, Cursor) ([]Hit, Cursor, error)
			}
			if kind == "wazuh" {
				source = WazuhClient{BaseURL: base, Index: index, PageSize: 2, HTTPClient: client}
			} else {
				source = GenericClient{BaseURL: base, Index: index, PageSize: 2, HTTPClient: client}
			}
			cursor := Cursor{}
			var ids []string
			for page := 0; page < 4; page++ {
				hits, next, err := source.Search(context.Background(), cursor)
				if err != nil {
					t.Fatal(err)
				}
				for _, hit := range hits {
					ids = append(ids, hit.ID)
				}
				sortJSON, err := json.Marshal(next.Sort)
				if err != nil {
					t.Fatal(err)
				}
				// Rehydrate between every page, as a newly started process does.
				cursor, err = RestoreCursor(next.Timestamp, sortJSON)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(ids, []string{"a", "b", "c", "d", "e"}) {
				t.Fatalf("real OpenSearch lost or replayed hits: %v", ids)
			}
		})
	}
}
