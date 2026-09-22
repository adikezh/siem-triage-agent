package redact

import "testing"

func TestTextRedactsPIIAndPreservesExternalIP(t *testing.T) {
	got := Text("username: alice email Alice@example.com from 10.2.3.4 to 8.8.8.8", []string{"10.0.0.0/8"})
	if got == "" || contains(got, "alice") || contains(got, "Alice@example.com") || contains(got, "10.2.3.4") {
		t.Fatalf("PII leaked: %q", got)
	}
	if !contains(got, "8.8.8.8") {
		t.Fatalf("external IP changed: %q", got)
	}
}
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
