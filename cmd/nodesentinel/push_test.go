package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestPushAgentMetricsEventsAndReconnect(t *testing.T) {
	const key = "test-agent-key-123456"
	d, _ := testDashboard(t, map[string]agentConfig{"host": {Mode: "push", Key: key}})
	server := httptest.NewTLSServer(d.handler())
	defer server.Close()
	certPath := filepath.Join(t.TempDir(), "hub.crt")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODESENTINEL_AGENT_KEY", key)
	t.Setenv("NODESENTINEL_AGENT_NAME", "host")
	t.Setenv("NODESENTINEL_HUB_URL", "ws"+strings.TrimPrefix(server.URL, "http"))
	t.Setenv("NODESENTINEL_HUB_CA_CERT", certPath)
	t.Setenv("NODESENTINEL_ENABLE_DOCKER", "")
	a, err := newAgent()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.push(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("push stopped: %v", err)
		}
	}()
	waitForMetrics := func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if data, err := d.pushedMetrics("host"); err == nil && data["cpu_percent"] != nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("agent did not push metrics")
	}
	waitForMetrics()
	d.mu.Lock()
	session := d.pushAgents["host"]
	d.mu.Unlock()
	session.mu.Lock()
	session.updated = time.Now().Add(-pushMetricsMaxAge - time.Second)
	session.mu.Unlock()
	if _, err := d.pushedMetrics("host"); err == nil {
		t.Fatal("stale agent metrics were reported as current")
	}
	session.mu.Lock()
	session.updated = time.Now()
	session.mu.Unlock()

	query := url.Values{"since": {"1"}, "until": {"2"}}
	response, err := d.requestPushEvents(ctx, "host", query)
	if err != nil {
		t.Fatalf("empty event response: %v", err)
	}
	response.Body.Close()
	query["types"] = []string{"docker"}
	if _, err := d.requestPushEvents(ctx, "host", query); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("disabled Docker event source error = %v", err)
	}

	d.mu.Lock()
	first := d.pushAgents["host"]
	d.mu.Unlock()
	first.conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		current := d.pushAgents["host"]
		d.mu.Unlock()
		if current != nil && current != first {
			waitForMetrics()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("agent did not reconnect")
}

func TestPushAuthenticationAndTransportValidation(t *testing.T) {
	const key = "test-agent-key-123456"
	d, _ := testDashboard(t, map[string]agentConfig{"host": {Mode: "push", Key: key}})
	server := httptest.NewServer(d.handler())
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/agent/connect"
	for _, test := range []struct {
		name, key, origin string
		status            int
	}{
		{"host", "wrong-agent-key-12345", "", http.StatusUnauthorized},
		{"unknown", key, "", http.StatusUnauthorized},
		{"host", key, "https://evil.example", http.StatusForbidden},
	} {
		header := http.Header{"X-Agent-Name": {test.name}, "X-Agent-Key": {test.key}}
		if test.origin != "" {
			header.Set("Origin", test.origin)
		}
		conn, response, err := websocket.DefaultDialer.Dial(target, header)
		if conn != nil {
			conn.Close()
		}
		if err == nil || response == nil || response.StatusCode != test.status {
			t.Fatalf("credentials/origin status = %v, error %v; want %d", response, err, test.status)
		}
		response.Body.Close()
	}
	t.Setenv("NODESENTINEL_HUB_URL", "ws://remote.example")
	a := &agent{key: key}
	if err := a.push(context.Background()); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("unencrypted remote hub error = %v", err)
	}
}

func TestPushAgentRejectsUntrustedDashboard(t *testing.T) {
	const key = "test-agent-key-123456"
	d, _ := testDashboard(t, map[string]agentConfig{"host": {Mode: "push", Key: key}})
	server := httptest.NewTLSServer(d.handler())
	defer server.Close()
	t.Setenv("NODESENTINEL_HUB_URL", "ws"+strings.TrimPrefix(server.URL, "http"))
	t.Setenv("NODESENTINEL_HUB_CA_CERT", "")
	t.Setenv("NODESENTINEL_AGENT_NAME", "host")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	a := &agent{key: key}
	if err := a.push(ctx); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	session := d.pushAgents["host"]
	d.mu.Unlock()
	if session != nil {
		t.Fatal("agent connected to an untrusted dashboard certificate")
	}
}

func TestPushEventRequestHonorsTimeout(t *testing.T) {
	const key = "test-agent-key-123456"
	d, _ := testDashboard(t, map[string]agentConfig{"host": {Mode: "push", Key: key}})
	server := httptest.NewServer(d.handler())
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/agent/connect"
	conn, _, err := websocket.DefaultDialer.Dial(target, http.Header{
		"X-Agent-Name": {"host"}, "X-Agent-Key": {key},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for {
		d.mu.Lock()
		connected := d.pushAgents["host"] != nil
		d.mu.Unlock()
		if connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = d.requestPushEvents(ctx, "host", url.Values{"since": {"1"}, "until": {"2"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("event request error = %v, want deadline exceeded", err)
	}
}

func TestPushConfigurationKeepsPullCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("NODESENTINEL_DASHBOARD_CONFIG", path)
	valid := `{"agents":{"new":{"mode":"push","key":"test-agent-key-123456"},"old":{"url":"http://127.0.0.1:9100"}}}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readDashboardConfig()
	if err != nil || cfg.Agents["new"].Mode != "push" || cfg.Agents["old"].URL != "http://127.0.0.1:9100" {
		t.Fatalf("mixed configuration = %#v, error %v", cfg.Agents, err)
	}
	invalid := `{"agents":{"new":{"mode":"push","key":"short"}}}`
	if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDashboardConfig(); err == nil {
		t.Fatal("push agent with a short key was accepted")
	}
	duplicate := `{"agents":{"one":{"mode":"push","key":"test-agent-key-123456"},"two":{"mode":"push","key":"test-agent-key-123456"}}}`
	if err := os.WriteFile(path, []byte(duplicate), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDashboardConfig(); err == nil {
		t.Fatal("push agents with a shared key were accepted")
	}
}

func TestDisabledAgentSourcesAreUnavailable(t *testing.T) {
	t.Setenv("NODESENTINEL_AGENT_KEY", "test-agent-key-123456")
	t.Setenv("NODESENTINEL_AGENT_CONTAINER", "1")
	for _, key := range []string{"ENABLE_DOCKER", "ENABLE_HOST_ROOT", "ENABLE_JOURNAL", "ENABLE_UFW", "ENABLE_FAIL2BAN"} {
		t.Setenv("NODESENTINEL_"+key, "")
	}
	a, err := newAgent()
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.collectMetrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data["storage_percent"] != nil || data["storage_error"] == "" || data["docker_error"] == nil {
		t.Fatalf("disabled sources were not reported unavailable: %#v", data)
	}
	for _, kind := range []string{"ssh_login", "docker"} {
		if _, err := a.collectEvents(context.Background(), 1, 2, []string{kind}, false); err == nil {
			t.Errorf("disabled %s source returned success", kind)
		}
	}
}

func TestNotificationCursorSurvivesDisconnectAndRestart(t *testing.T) {
	var since string
	fail := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since = r.URL.Query().Get("since")
		if fail {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"events":[]}`)
	}))
	defer server.Close()
	agents := map[string]agentConfig{"host": {URL: server.URL}}
	d, store := testDashboard(t, agents)
	settings := map[string]any{"events": []string{"docker"}}
	d.pollProviderEvents(context.Background(), "telegram", settings, 100)
	d.pollProviderEvents(context.Background(), "telegram", settings, 110)
	if since != "100" {
		t.Fatalf("first event query since = %s", since)
	}
	fail = false
	restarted := newDashboard(store, dashboardConfig{Agents: agents, PollSeconds: 15})
	restarted.pollProviderEvents(context.Background(), "telegram", settings, 120)
	if since != "100" {
		t.Fatalf("catch-up event query since = %s, want 100", since)
	}
	var saved int64
	if err := store.monitorDB.QueryRow(`SELECT until_time FROM notification_cursors WHERE host='host' AND provider='telegram' AND kind='docker'`).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if saved != 120 {
		t.Fatalf("saved cursor = %d, want 120", saved)
	}
}

func TestParseDockerEventPreservesNanosecondTimestamp(t *testing.T) {
	line := []byte(`{"id":"1234567890abcdef","Action":"die","Actor":{"Attributes":{"name":"web","image":"example/web:latest","exitCode":"137"}},"timeNano":1763721234567890123}`)
	event, relevant, err := parseDockerEvent(line, 1763721234, 1763721235)
	if err != nil {
		t.Fatal(err)
	}
	if !relevant {
		t.Fatal("valid Docker die event was ignored")
	}
	if event["action"] != "die" || event["name"] != "web" || event["image"] != "example/web:latest" ||
		event["exit_code"] != "137" {
		t.Fatalf("parsed Docker event = %#v", event)
	}
	timestamp := event["timestamp"].(float64)
	if timestamp < 1763721234.567 || timestamp > 1763721234.568 {
		t.Fatalf("timestamp = %.12f, want retained nanosecond value", timestamp)
	}
}
