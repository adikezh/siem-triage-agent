package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"sort"
	"strings"
	"time"
)

func Markdown(ctx context.Context, s *store.Store, period time.Duration) (string, error) {
	rows, e := s.ListIncidents(ctx)
	if e != nil {
		return "", e
	}
	since := time.Now().UTC().Add(-period)
	counts := map[string]int{}
	total := 0
	for _, r := range rows {
		t, _ := time.Parse(time.RFC3339Nano, r.LastSeen)
		if t.Before(since) {
			continue
		}
		counts[r.Severity]++
		total++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "# SIEM Triage Report\n\nPeriod: last %s\n\n", period)
	fmt.Fprintf(&b, "Total incidents: **%d**\n\n| Severity | Count |\n|---|---:|\n", total)
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %d |\n", k, counts[k])
	}
	if total == 0 {
		b.WriteString("\nNo incidents in the selected period.\n")
	}
	return b.String(), nil
}

func PDF(ctx context.Context, s *store.Store, period time.Duration) ([]byte, error) {
	text, err := Markdown(ctx, s, period)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r", ""), "\n")
	var content strings.Builder
	content.WriteString("BT\n/F1 11 Tf\n50 760 Td\n")
	for _, line := range lines {
		line = strings.ReplaceAll(line, "\\", "\\\\")
		line = strings.ReplaceAll(line, "(", "\\(")
		line = strings.ReplaceAll(line, ")", "\\)")
		if len(line) > 110 {
			line = line[:110]
		}
		fmt.Fprintf(&content, "(%s) Tj\n0 -16 Td\n", line)
	}
	content.WriteString("ET")
	stream := content.String()
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	add := func(x string) { offsets = append(offsets, b.Len()); b.WriteString(x) }
	add("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
	add("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
	add("3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n")
	add("4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
	add(fmt.Sprintf("5 0 obj << /Length %d >> stream\n%s\nendstream endobj\n", len(stream), stream))
	xref := b.Len()
	b.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for _, off := range offsets[1:] {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer << /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes(), nil
}

func DOCX(ctx context.Context, s *store.Store, period time.Duration) ([]byte, error) {
	text, err := Markdown(ctx, s, period)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r", ""), "\n")
	var body strings.Builder
	for _, line := range lines {
		body.WriteString("<w:p><w:r><w:t xml:space=\"preserve\">")
		_ = xml.EscapeText(&body, []byte(line))
		body.WriteString("</w:t></w:r></w:p>")
	}
	files := map[string]string{"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`, "_rels/.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`, "word/document.xml": `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for name, data := range files {
		w, e := zw.Create(name)
		if e != nil {
			return nil, e
		}
		if _, e = w.Write([]byte(data)); e != nil {
			return nil, e
		}
	}
	if err = zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
