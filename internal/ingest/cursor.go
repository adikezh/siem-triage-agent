package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// RestoreCursor preserves integer sort values, including nanosecond timestamps
// that cannot be represented exactly by a float64.
func RestoreCursor(timestamp time.Time, sortJSON []byte) (Cursor, error) {
	c := Cursor{Timestamp: timestamp}
	if len(sortJSON) == 0 {
		return c, nil
	}
	d := json.NewDecoder(bytes.NewReader(sortJSON))
	d.UseNumber()
	if err := d.Decode(&c.Sort); err != nil {
		return Cursor{}, fmt.Errorf("decode source cursor: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Cursor{}, fmt.Errorf("source cursor contains trailing data")
	}
	return c, nil
}

func timestampQuery(field string, timestamp time.Time) map[string]any {
	// date_nanos indices cannot parse year 0001 as a range bound. A new source
	// has no checkpoint, so its initial query must not invent an ancient date.
	if timestamp.IsZero() {
		return map[string]any{"match_all": map[string]any{}}
	}
	return map[string]any{"range": map[string]any{field: map[string]string{"gte": timestamp.UTC().Format(time.RFC3339Nano)}}}
}
