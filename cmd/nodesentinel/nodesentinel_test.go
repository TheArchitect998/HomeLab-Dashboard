package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDashboard(t *testing.T, agents map[string]agentConfig) (*dashboard, *dashboardStore) {
	t.Helper()
	store, err := openDashboardStoreAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.close(); err != nil {
			t.Errorf("close dashboard store: %v", err)
		}
	})
	return newDashboard(store, dashboardConfig{Agents: agents, PollSeconds: 15}), store
}

func request(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var content bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&content).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &content)
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("X-Requested-With", "NodeSentinel")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func loginForTest(t *testing.T, d *dashboard, password string) *http.Cookie {
	t.Helper()
	recorder := request(t, d.handler(), http.MethodPost, "/api/auth/login",
		map[string]string{"password": password}, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	t.Fatal("login did not set a session cookie")
	return nil
}

func TestAgentAuthenticationAndEventQueryValidation(t *testing.T) {
	t.Setenv("NODESENTINEL_AGENT_KEY", "a-strong-agent-key")
	service, err := newAgent()
	if err != nil {
		t.Fatal(err)
	}
	handler := service.handler()
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/api/health", http.StatusUnauthorized},
		{"/api/events?since=-1&until=5&types=docker", http.StatusUnauthorized},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != test.status {
			t.Errorf("GET %s status = %d, want %d", test.path, recorder.Code, test.status)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("X-Agent-Key", "a-strong-agent-key")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"ok":true`) {
		t.Fatalf("authenticated health = %d %s", recorder.Code, recorder.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/events?since=5&until=5&types=docker", nil)
	req.Header.Set("X-Agent-Key", "a-strong-agent-key")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid event query status = %d, want 400", recorder.Code)
	}
}

func TestDashboardAuthenticationAndOriginProtection(t *testing.T) {
	d, store := testDashboard(t, nil)
	hash, err := passwordHash("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeSettings(map[string]any{"password": hash}); err != nil {
		t.Fatal(err)
	}
	handler := d.handler()
	if got := request(t, handler, http.MethodGet, "/api/dashboard", nil, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard status = %d, want 401", got)
	}
	invalidOrigin := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"correct-password"}`))
	invalidOrigin.Header.Set("Origin", "https://evil.example")
	invalidOrigin.Header.Set("Content-Type", "application/json")
	invalidOrigin.Header.Set("X-Requested-With", "NodeSentinel")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, invalidOrigin)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status = %d, want 403", recorder.Code)
	}
	cookie := loginForTest(t, d, "correct-password")
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie is missing security flags: %#v", cookie)
	}
	if got := request(t, handler, http.MethodGet, "/api/dashboard", nil, cookie).Code; got != http.StatusOK {
		t.Fatalf("authenticated dashboard status = %d, want 200", got)
	}
}

func TestProviderSecretsStayHiddenAndArePreserved(t *testing.T) {
	d, store := testDashboard(t, nil)
	hash, err := passwordHash("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeSettings(map[string]any{"password": hash}); err != nil {
		t.Fatal(err)
	}
	handler := d.handler()
	cookie := loginForTest(t, d, "correct-password")
	payload := map[string]any{
		"enabled": true, "events": []string{"docker"},
		"webhook_url": "https://discord.com/api/webhooks/123/secret-token",
	}
	recorder := request(t, handler, http.MethodPut, "/api/notifications/discord", payload, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save provider status = %d: %s", recorder.Code, recorder.Body.String())
	}
	get := request(t, handler, http.MethodGet, "/api/notifications/discord", nil, cookie)
	if get.Code != http.StatusOK || strings.Contains(get.Body.String(), "secret-token") {
		t.Fatalf("provider response leaked secret or failed: %d %s", get.Code, get.Body.String())
	}
	payload["webhook_url"] = ""
	recorder = request(t, handler, http.MethodPut, "/api/notifications/discord", payload, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save provider without replacement status = %d: %s", recorder.Code, recorder.Body.String())
	}
	settings, err := store.readSettings()
	if err != nil {
		t.Fatal(err)
	}
	saved := objectAt(objectAt(settings, "providers"), "discord")
	if saved["webhook_url"] != "https://discord.com/api/webhooks/123/secret-token" {
		t.Fatalf("existing secret was not preserved: %v", saved["webhook_url"])
	}
}

func TestMonitoringAndChecksKeepTheirAPIValidation(t *testing.T) {
	d, store := testDashboard(t, map[string]agentConfig{"host": {URL: "http://agent.invalid"}})
	hash, err := passwordHash("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeSettings(map[string]any{
		"password": hash,
		"telegram": map[string]any{"enabled": true, "token": "123:abc", "chat_id": "1"},
	}); err != nil {
		t.Fatal(err)
	}
	cookie := loginForTest(t, d, "correct-password")
	handler := d.handler()
	for _, invalid := range []string{"7:35", "24:00", "12:60"} {
		response := request(t, handler, http.MethodPut, "/api/monitoring",
			map[string]any{"daily_report_time": invalid}, cookie)
		if response.Code != http.StatusBadRequest {
			t.Errorf("daily report time %q status = %d, want 400", invalid, response.Code)
		}
	}
	valid := request(t, handler, http.MethodPut, "/api/monitoring",
		map[string]any{"temperature_enabled": true, "daily_report_time": "07:35", "thresholds": map[string]float64{"host": 45}},
		cookie)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid monitoring settings status = %d: %s", valid.Code, valid.Body.String())
	}
	checks := map[string]any{"checks": []map[string]any{
		{"name": "web", "type": "tcp", "target": "host.test", "port": 443},
	}}
	if response := request(t, handler, http.MethodPut, "/api/checks", checks, cookie); response.Code != http.StatusOK {
		t.Fatalf("valid checks status = %d: %s", response.Code, response.Body.String())
	}
	checks = map[string]any{"checks": []map[string]any{
		{"name": "web", "type": "ping", "target": "-c 5 hostile"},
	}}
	if response := request(t, handler, http.MethodPut, "/api/checks", checks, cookie); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid ping target status = %d, want 400", response.Code)
	}
}

func TestDashboardUsesExistingHistoryDatabase(t *testing.T) {
	state := t.TempDir()
	path := filepath.Join(state, "metrics.sqlite3")
	db, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE metrics (host TEXT NOT NULL, time INTEGER NOT NULL, cpu REAL, ram REAL, disk REAL, temperature REAL, PRIMARY KEY(host, time))`)
	if err == nil {
		_, err = db.Exec(`INSERT INTO metrics VALUES ('host', 120, 10, 20, 30, 40)`)
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	store, err := openDashboardStoreAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM metrics WHERE host='host' AND time=120`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("existing history rows = %d, want 1", count)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("metrics database permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestAgentURLNormalization(t *testing.T) {
	for input, expected := range map[string]string{
		"http://one:9100/api/metrics": "http://one:9100",
		"https://two:9100/":           "https://two:9100",
	} {
		if got := normalizeAgentURL(input); got != expected {
			t.Errorf("normalizeAgentURL(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestPBKDF2MatchesPythonCompatibleSHA256Vector(t *testing.T) {
	got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("PBKDF2-SHA256 = %s, want %s", got, want)
	}
}

func TestTrustedProxyRequiresConfiguredSource(t *testing.T) {
	t.Setenv("NODESENTINEL_TRUSTED_PROXIES", "127.0.0.1,192.0.2.0/24")
	if !trustedProxy("127.0.0.1:8080") || !trustedProxy("192.0.2.42:8080") {
		t.Fatal("configured proxy IP or subnet was not trusted")
	}
	if trustedProxy("198.51.100.8:8080") {
		t.Fatal("unconfigured client was trusted as a proxy")
	}
}

func TestAgentRequestsDoNotFollowRedirects(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/api/metrics" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	d, _ := testDashboard(t, nil)
	d.agentKey = "agent-secret-key"
	response, err := d.agentRequest(t.Context(), agentConfig{URL: server.URL}, "/api/metrics")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || requests != 1 {
		t.Fatalf("agent redirect response = %d, requests = %d; expected 302 and no follow", response.StatusCode, requests)
	}
}
