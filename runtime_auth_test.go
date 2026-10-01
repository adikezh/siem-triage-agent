package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

func TestRuntimeAPIAndWebRoles(t *testing.T) {
	if os.Getenv("TRIAGE_RUNTIME_TEST") != "1" || runtime.GOOS == "windows" {
		t.Skip("requires Linux runtime verification")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "triage")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	path := filepath.Join(dir, "fixture.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := "rule|agent|ip/2026-10-01T00:00:00Z"
	n := time.Now()
	if err = s.SaveIncident(context.Background(), map[string]string{"src_ip": "203.0.113.10"}, id, "rule|agent|ip", "high", 80, 1, n, n); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"viewer", "analyst", "admin"} {
		if _, err = s.CreateAPIKey(context.Background(), "fixture-"+role, role, "synthetic-"+role); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	var output bytes.Buffer
	command := exec.Command(binary, "serve", "--listen", addr, "--db", path)
	command.Stdout = &output
	command.Stderr = &output
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("exit: %v %s", err, &output)
			}
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("runtime did not stop")
		}
	})
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + addr
	ready := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, e := client.Get(base + "/health")
		if e == nil {
			_ = r.Body.Close()
			ready = r.StatusCode == 200
			if ready {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server not ready")
	}
	request := func(method, path, key, body string) (int, []byte) {
		t.Helper()
		r, e := http.NewRequest(method, base+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		r.Header.Set("Content-Type", "application/json")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, b
	}
	if status, _ := request("GET", "/", "", ""); status != 303 {
		t.Fatalf("unprotected UI=%d", status)
	}
	if status, _ := request("GET", "/api/incidents", "", ""); status != 401 {
		t.Fatal(status)
	}
	for _, role := range []string{"viewer", "analyst", "admin"} {
		t.Run(role, func(t *testing.T) {
			key := "synthetic-" + role
			if status, _ := request("GET", "/api/suppressions", key, ""); status != 200 {
				t.Fatalf("read=%d", status)
			}
			feedback, _ := json.Marshal(map[string]string{"incident_id": id, "verdict": "fp", "actor": "forged-admin"})
			want := 201
			if role == "viewer" {
				want = 403
			}
			if status, _ := request("POST", "/api/incidents/feedback", key, string(feedback)); status != want {
				t.Fatalf("feedback=%d want=%d", status, want)
			}
			status, b := request("POST", "/api/suppressions", key, `{"Fingerprint":"rule|agent|ip","Action":"tag","Reason":"runtime fixture","CreatedBy":"forged-admin"}`)
			if status != want {
				t.Fatalf("create=%d want=%d body=%s", status, want, b)
			}
			if role != "viewer" {
				var rule store.SuppressionRecord
				if e := json.Unmarshal(b, &rule); e != nil {
					t.Fatal(e)
				}
				if rule.CreatedBy != "fixture-"+role {
					t.Fatalf("forged actor accepted: %+v", rule)
				}
				wantDelete := 403
				if role == "admin" {
					wantDelete = 204
				}
				if status, _ := request("DELETE", fmt.Sprintf("/api/suppressions/%d", rule.ID), key, ""); status != wantDelete {
					t.Fatalf("delete=%d want=%d", status, wantDelete)
				}
			}
		})
	}
}
