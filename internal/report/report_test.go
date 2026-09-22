package report

import (
	"archive/zip"
	"bytes"
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMarkdown(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n := time.Now().UTC()
	if e = s.SaveIncident(context.Background(), map[string]string{"x": "y"}, "i", "f", "high", 70, 1, n, n); e != nil {
		t.Fatal(e)
	}
	m, e := Markdown(context.Background(), s, 24*time.Hour)
	if e != nil || !strings.Contains(m, "Total incidents: **1**") || !strings.Contains(m, "| high | 1 |") {
		t.Fatalf("%s %v", m, e)
	}
}

func TestBinaryReports(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n := time.Now().UTC()
	if err = s.SaveIncident(context.Background(), map[string]string{}, "i", "f", "high", 70, 1, n, n); err != nil {
		t.Fatal(err)
	}
	pdf, err := PDF(context.Background(), s, time.Hour)
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Fatalf("pdf err=%v", err)
	}
	docx, err := DOCX(context.Background(), s, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range z.File {
		if f.Name == "word/document.xml" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing document.xml")
	}
}
