package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

func TestRuntimeServeDrainsOutboxAndShutsDown(t *testing.T) {
	if os.Getenv("TRIAGE_RUNTIME_TEST") != "1" || runtime.GOOS == "windows" {
		t.Skip("set TRIAGE_RUNTIME_TEST=1 on Linux to test the built binary and SIGTERM")
	}
	binary := filepath.Join(t.TempDir(), "triage")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, withFailedSource := range []bool{false, true} {
		t.Run(fmt.Sprintf("source_outage_%t", withFailedSource), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime.db")
			db, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Enqueue(context.Background(), "persisted-incident", "webhook", []byte(`{"alert_count":1}`)); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			delivered := make(chan struct{}, 10)
			webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { delivered <- struct{}{}; w.WriteHeader(204) }))
			defer webhook.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
			defer source.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			listener.Close()
			args := []string{"serve", "--listen", addr, "--db", path, "--webhook-url", webhook.URL}
			if withFailedSource {
				args = append(args, "--source-url", source.URL, "--source-interval", "20ms")
			}
			var output bytes.Buffer
			command := exec.Command(binary, args...)
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			stopped := false
			stop := func() {
				t.Helper()
				if stopped {
					return
				}
				started := time.Now()
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Error(err)
				}
				select {
				case err := <-done:
					stopped = true
					if err != nil {
						t.Errorf("SIGTERM exit: %v\n%s", err, &output)
					}
					if elapsed := time.Since(started); elapsed > 10*time.Second {
						t.Errorf("shutdown took %s", elapsed)
					}
				case <-time.After(10 * time.Second):
					command.Process.Kill()
					<-done
					stopped = true
					t.Error("server did not shut down within 10 seconds")
				}
			}
			t.Cleanup(stop)
			client := &http.Client{Timeout: time.Second}
			deadline := time.Now().Add(5 * time.Second)
			sent := false
			for time.Now().Before(deadline) {
				response, err := client.Get("http://" + addr + "/api/stats")
				if err == nil {
					var stats struct {
						Outbox struct{ Pending, Sent int } `json:"outbox"`
					}
					err = json.NewDecoder(response.Body).Decode(&stats)
					response.Body.Close()
					if err == nil && stats.Outbox.Sent == 1 && stats.Outbox.Pending == 0 {
						sent = true
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !sent {
				t.Fatal("built server did not durably drain the outbox")
			}
			stop()
			if len(delivered) != 1 {
				t.Fatalf("notification count=%d", len(delivered))
			}
			db, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			metrics, err := db.Metrics(context.Background())
			if err != nil || metrics.OutboxSent != 1 || metrics.OutboxPending != 0 {
				t.Fatalf("restart metrics=%#v err=%v", metrics, err)
			}
		})
	}
}
