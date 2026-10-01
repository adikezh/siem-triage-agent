package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestCursorPreservesLargeIntegerSortValues(t *testing.T) {
	const raw = `[1790920000000000001,"alert"]`
	c, err := RestoreCursor(time.Now(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c.Sort)
	if err != nil || string(b) != raw {
		t.Fatalf("sort value rounded: %s %v", b, err)
	}
	for _, invalid := range []string{`{}`, `[1] [2]`, `not-json`} {
		if _, err := RestoreCursor(time.Now(), []byte(invalid)); err == nil {
			t.Fatalf("accepted invalid cursor %q", invalid)
		}
	}
}

func TestClientsKeepEqualTimestampHitsAcrossPages(t *testing.T) {
	for _, kind := range []string{"wazuh", "generic"} {
		t.Run(kind, func(t *testing.T) {
			const stamp = "2026-10-02T08:00:00Z"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					Sort  []string `json:"sort"`
					After []any    `json:"search_after"`
					Query struct {
						Range map[string]map[string]string `json:"range"`
					} `json:"query"`
				}
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if !reflect.DeepEqual(q.Sort, []string{"@timestamp", "event_id"}) {
					t.Errorf("sort=%v", q.Sort)
				}
				hits := []map[string]any{}
				// Model the source's range and search_after filtering rather than
				// returning a canned page that would hide a skipped timestamp.
				for _, id := range []string{"a", "b", "c"} {
					if q.Query.Range["@timestamp"]["gt"] >= stamp {
						continue
					}
					if len(q.After) > 0 && id <= q.After[1].(string) {
						continue
					}
					hits = append(hits, map[string]any{"_id": id, "_source": map[string]string{"@timestamp": stamp, "event_id": id}, "sort": []string{stamp, id}})
					if len(hits) == 2 {
						break
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
			}))
			defer server.Close()
			var source interface {
				Search(context.Context, Cursor) ([]Hit, Cursor, error)
			}
			if kind == "wazuh" {
				source = WazuhClient{BaseURL: server.URL, Index: "alerts", PageSize: 2, TieBreaker: "event_id"}
			} else {
				source = GenericClient{BaseURL: server.URL, Index: "alerts", PageSize: 2, TieBreaker: "event_id"}
			}
			cursor := Cursor{Timestamp: time.Unix(0, 0)}
			var ids []string
			for page := 0; page < 3; page++ {
				hits, next, err := source.Search(context.Background(), cursor)
				if err != nil {
					t.Fatal(err)
				}
				for _, hit := range hits {
					ids = append(ids, hit.ID)
				}
				b, err := json.Marshal(next.Sort)
				if err != nil {
					t.Fatal(err)
				}
				cursor, err = RestoreCursor(next.Timestamp, b)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(ids, []string{"a", "b", "c"}) {
				t.Fatalf("pagination lost or replayed hits: %v", ids)
			}
		})
	}
}

func TestClientsRejectPartialOrUnpageableResults(t *testing.T) {
	for _, kind := range []string{"wazuh", "generic"} {
		for _, body := range []string{
			`{"timed_out":true,"hits":{"hits":[]}}`,
			`{"_shards":{"failed":1},"hits":{"hits":[]}}`,
			`{"hits":{"hits":[{"_id":"a","_source":{"@timestamp":"2026-10-02T08:00:00Z"},"sort":[1790928000000,null]}]}}`,
		} {
			t.Run(kind+body, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
				defer server.Close()
				original := Cursor{Timestamp: time.Unix(0, 0)}
				var hits []Hit
				var next Cursor
				var err error
				if kind == "wazuh" {
					hits, next, err = (WazuhClient{BaseURL: server.URL, Index: "alerts"}).Search(context.Background(), original)
				} else {
					hits, next, err = (GenericClient{BaseURL: server.URL, Index: "alerts"}).Search(context.Background(), original)
				}
				if err == nil || len(hits) != 0 || !next.Timestamp.Equal(original.Timestamp) {
					t.Fatalf("partial result advanced checkpoint: hits=%v next=%#v err=%v", hits, next, err)
				}
			})
		}
	}
}
