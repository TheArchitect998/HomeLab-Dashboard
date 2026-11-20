package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const (
	sessionCookieName = "nodesentinel_session"
	sessionDuration   = 12 * time.Hour
	pbkdf2Iterations  = 600_000
)

var (
	eventTypes        = map[string]bool{"ssh_login": true, "ssh_logout": true, "fail2ban": true, "docker": true}
	checkTypes        = map[string]bool{"ping": true, "http": true, "tcp": true, "dns": true}
	providers         = []string{"telegram", "discord", "ntfy", "pushover", "email", "webhook", "gotify"}
	editableProviders = map[string]bool{"discord": true, "ntfy": true, "pushover": true, "email": true, "webhook": true, "gotify": true}
	historyBuckets    = map[int]int{1: 60, 24: 300, 168: 3600, 720: 14400}
)

type agentConfig struct {
	URL    string `json:"url"`
	Key    string `json:"key"`
	CACert string `json:"ca_cert"`
	Mode   string `json:"mode"`
}

type dashboardConfig struct {
	Agents      map[string]agentConfig `json:"agents"`
	AgentKey    string                 `json:"agent_key"`
	StateDir    string                 `json:"state_dir"`
	PollSeconds int                    `json:"poll_seconds"`
	BindHost    string                 `json:"bind_host"`
	BindPort    int                    `json:"bind_port"`
}

type dashboardStore struct {
	db        *sql.DB
	monitorDB *sql.DB
	stateDir  string
	mu        sync.Mutex
}

type dashboard struct {
	store         *dashboardStore
	agents        map[string]agentConfig
	agentKey      string
	pollInterval  time.Duration
	mu            sync.Mutex
	sessions      map[string]time.Time
	loginAttempts map[string][]time.Time
	providerState map[string]providerFailure
	providerLocks map[string]*sync.Mutex
	checkStatus   map[string]map[string]any
	checkFailures map[string]int
	hardwareCheck map[string]time.Time
	pushAgents    map[string]*pushSession
	background    sync.WaitGroup
}

type providerFailure struct {
	fingerprint string
	retryAt     time.Time
}

func runDashboard() error {
	cfg, err := readDashboardConfig()
	if err != nil {
		return err
	}
	store, err := openDashboardStoreAt(cfg.StateDir)
	if err != nil {
		return err
	}
	defer store.close()
	service := newDashboard(store, cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
		service.closePushAgents()
		service.background.Wait()
	}()
	service.startBackground(ctx)
	server := &http.Server{
		Addr:              netAddress(cfg.BindHost, strconv.Itoa(cfg.BindPort)),
		Handler:           service.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return serve(server, env("DASHBOARD_TLS_CERTFILE", ""), env("DASHBOARD_TLS_KEYFILE", ""))
}

func readDashboardConfig() (dashboardConfig, error) {
	cfg := dashboardConfig{
		Agents:      map[string]agentConfig{},
		StateDir:    env("STATE_DIR", "/opt/nodesentinel/state"),
		BindHost:    env("DASHBOARD_HOST", "0.0.0.0"),
		BindPort:    8888,
		PollSeconds: 15,
	}
	if raw := env("DASHBOARD_PORT", ""); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return cfg, errors.New("NODESENTINEL_DASHBOARD_PORT must be between 1 and 65535")
		}
		cfg.BindPort = port
	}
	path := env("DASHBOARD_CONFIG", "")
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read dashboard config: %w", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("dashboard config must be JSON: %w", err)
		}
		if cfg.Agents == nil {
			cfg.Agents = map[string]agentConfig{}
		}
		if cfg.StateDir == "" {
			cfg.StateDir = env("STATE_DIR", "/opt/nodesentinel/state")
		}
		if cfg.BindHost == "" {
			cfg.BindHost = "0.0.0.0"
		}
		if cfg.BindPort == 0 {
			cfg.BindPort = 8888
		}
		if cfg.PollSeconds <= 0 {
			cfg.PollSeconds = 15
		}
		pushKeys := make(map[string]string)
		for name, item := range cfg.Agents {
			item.URL = normalizeAgentURL(item.URL)
			if item.Mode != "" && item.Mode != "pull" && item.Mode != "push" {
				return cfg, fmt.Errorf("agent %q has an invalid mode", name)
			}
			if item.Mode == "push" {
				if !validPushName(name) {
					return cfg, fmt.Errorf("push agent %q has an invalid name", name)
				}
				if !validPushKey(item.Key) {
					return cfg, fmt.Errorf("push agent %q requires its own key of at least 16 characters", name)
				}
				if other, exists := pushKeys[item.Key]; exists {
					return cfg, fmt.Errorf("push agents %q and %q must use different keys", other, name)
				}
				pushKeys[item.Key] = name
				if item.URL != "" || item.CACert != "" {
					return cfg, fmt.Errorf("push agent %q must not have a URL or CA certificate", name)
				}
			} else if item.URL == "" {
				return cfg, fmt.Errorf("agent %q has an empty URL", name)
			}
			cfg.Agents[name] = item
		}
		return cfg, nil
	}
	urlsText := env("AGENT_URLS", os.Getenv("AGENT_URLS"))
	if urlsText == "" {
		urlsText = "[]"
	}
	var urls []string
	if err := json.Unmarshal([]byte(urlsText), &urls); err != nil || urls == nil {
		return cfg, errors.New("AGENT_URLS must be a JSON array of URLs")
	}
	caCert := env("AGENT_CA_CERT", os.Getenv("AGENT_CA_CERT"))
	for i, raw := range urls {
		if strings.TrimSpace(raw) == "" {
			return cfg, errors.New("AGENT_URLS must be a JSON array of non-empty URLs")
		}
		cfg.Agents[fmt.Sprintf("agent-%d", i+1)] = agentConfig{URL: normalizeAgentURL(raw), CACert: caCert}
	}
	cfg.AgentKey = env("AGENT_KEY", os.Getenv("AGENT_KEY"))
	return cfg, nil
}

func normalizeAgentURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	return strings.TrimSuffix(raw, "/api/metrics")
}

func newDashboard(store *dashboardStore, cfg dashboardConfig) *dashboard {
	return &dashboard{
		store: store, agents: cfg.Agents, agentKey: cfg.AgentKey,
		pollInterval: time.Duration(cfg.PollSeconds) * time.Second,
		sessions:     make(map[string]time.Time), loginAttempts: make(map[string][]time.Time),
		providerState: make(map[string]providerFailure), checkStatus: make(map[string]map[string]any),
		providerLocks: make(map[string]*sync.Mutex),
		checkFailures: make(map[string]int), hardwareCheck: make(map[string]time.Time),
		pushAgents: make(map[string]*pushSession),
	}
}

func openDashboardStore() (*dashboardStore, error) {
	return openDashboardStoreAt(env("STATE_DIR", "/opt/nodesentinel/state"))
}

func openDashboardStoreAt(directory string) (*dashboardStore, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create dashboard state directory: %w", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, fmt.Errorf("protect dashboard state directory: %w", err)
	}
	db, err := openSQLite(filepath.Join(directory, "metrics.sqlite3"))
	if err != nil {
		return nil, fmt.Errorf("open metrics database: %w", err)
	}
	monitorDB, err := openSQLite(filepath.Join(directory, "monitoring.sqlite3"))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open monitoring database: %w", err)
	}
	store := &dashboardStore{db: db, monitorDB: monitorDB, stateDir: directory}
	for _, statement := range metricSchemaStatements {
		if _, err := db.Exec(statement); err != nil {
			store.close()
			return nil, fmt.Errorf("initialize dashboard database: %w", err)
		}
	}
	for _, statement := range monitoringSchemaStatements {
		if _, err := monitorDB.Exec(statement); err != nil {
			store.close()
			return nil, fmt.Errorf("initialize monitoring database: %w", err)
		}
	}
	if err := migrateNotificationProviderState(monitorDB); err != nil {
		store.close()
		return nil, fmt.Errorf("migrate notification state: %w", err)
	}
	return store, nil
}

func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

var metricSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS metrics (
		host TEXT NOT NULL, time INTEGER NOT NULL, cpu REAL, ram REAL, disk REAL, temperature REAL,
		PRIMARY KEY(host, time))`,
	`CREATE INDEX IF NOT EXISTS metrics_time ON metrics(time)`,
	`CREATE TABLE IF NOT EXISTS container_metrics (
		host TEXT NOT NULL, container TEXT NOT NULL, time INTEGER NOT NULL,
		cpu REAL, ram REAL, rx REAL, tx REAL, PRIMARY KEY(host, container, time))`,
	`CREATE INDEX IF NOT EXISTS container_metrics_time ON container_metrics(time)`,
}

var monitoringSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS samples (host TEXT, time REAL, temperature REAL)`,
	`CREATE TABLE IF NOT EXISTS events (host TEXT, kind TEXT, time REAL, event_id TEXT PRIMARY KEY)`,
	`CREATE TABLE IF NOT EXISTS cursors (host TEXT, kind TEXT, started INTEGER, until_time INTEGER, PRIMARY KEY(host, kind))`,
	`CREATE TABLE IF NOT EXISTS temperatures (host TEXT PRIMARY KEY, above INTEGER, last_sent REAL)`,
	`CREATE TABLE IF NOT EXISTS reports (host TEXT, day TEXT, PRIMARY KEY(host, day))`,
	`CREATE TABLE IF NOT EXISTS provider_temperatures (host TEXT, provider TEXT, above INTEGER, last_sent REAL, PRIMARY KEY(host, provider))`,
	`CREATE TABLE IF NOT EXISTS provider_reports (host TEXT, provider TEXT, day TEXT, PRIMARY KEY(host, provider, day))`,
	`CREATE TABLE IF NOT EXISTS provider_hardware (host TEXT, provider TEXT, issues TEXT, last_sent REAL, PRIMARY KEY(host, provider))`,
	`CREATE TABLE IF NOT EXISTS provider_checks (name TEXT, provider TEXT, down INTEGER, PRIMARY KEY(name, provider))`,
	`CREATE TABLE IF NOT EXISTS notification_cursors (host TEXT, provider TEXT, kind TEXT, until_time INTEGER NOT NULL, PRIMARY KEY(host, provider, kind))`,
	`CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY)`,
}

func migrateNotificationProviderState(db *sql.DB) error {
	var exists int
	err := db.QueryRow(`SELECT 1 FROM migrations WHERE name=?`, "notification_providers").Scan(&exists)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO provider_temperatures SELECT host, 'telegram', above, last_sent FROM temperatures`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO provider_reports SELECT host, 'telegram', day FROM reports`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO migrations VALUES (?)`, "notification_providers"); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *dashboardStore) close() error {
	err1 := s.db.Close()
	err2 := s.monitorDB.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *dashboardStore) readSettings() (map[string]any, error) {
	path := filepath.Join(s.stateDir, "settings.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	settings := map[string]any{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("invalid settings file: %w", err)
	}
	return settings, nil
}

func (s *dashboardStore) writeSettings(settings map[string]any) error {
	if err := os.MkdirAll(s.stateDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.stateDir, ".settings-")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, filepath.Join(s.stateDir, "settings.json"))
}

func (d *dashboard) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", d.index)
	mux.HandleFunc("GET /api/auth/status", d.authStatus)
	mux.HandleFunc("POST /api/auth/login", d.login)
	mux.HandleFunc("POST /api/auth/logout", d.logout)
	mux.HandleFunc("POST /api/auth/password", d.changePassword)
	mux.HandleFunc("GET /api/telegram", d.getTelegram)
	mux.HandleFunc("PUT /api/telegram", d.setTelegram)
	mux.HandleFunc("GET /api/notifications/{provider}", d.getProvider)
	mux.HandleFunc("PUT /api/notifications/{provider}", d.setProvider)
	mux.HandleFunc("POST /api/notifications/{provider}/test", d.testProvider)
	mux.HandleFunc("GET /api/monitoring", d.getMonitoring)
	mux.HandleFunc("PUT /api/monitoring", d.setMonitoring)
	mux.HandleFunc("GET /api/dashboard", d.getDashboard)
	mux.HandleFunc("GET /api/history", d.history)
	mux.HandleFunc("GET /api/history/containers", d.containerHistory)
	mux.HandleFunc("GET /api/checks", d.getChecks)
	mux.HandleFunc("PUT /api/checks", d.setChecks)
	mux.HandleFunc("GET /api/agent/connect", d.connectAgent)
	return securityHeaders(d.protectAPI(mux))
}

func (d *dashboard) protectAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				origin := r.Header.Get("Origin")
				if r.Header.Get("X-Requested-With") != "NodeSentinel" ||
					(origin != "" && !sameOrigin(origin, r.Host)) {
					writeError(w, http.StatusForbidden, "Invalid request origin")
					return
				}
			}
			if r.URL.Path != "/api/auth/status" && r.URL.Path != "/api/auth/login" &&
				r.URL.Path != "/api/agent/connect" && !d.requireSession(w, r) {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host == host
}

func (d *dashboard) requireSession(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		d.mu.Lock()
		expiry := d.sessions[cookie.Value]
		if expiry.After(time.Now()) {
			d.mu.Unlock()
			return true
		}
		delete(d.sessions, cookie.Value)
		d.mu.Unlock()
	}
	writeError(w, http.StatusUnauthorized, "Authentication required")
	return false
}

func (d *dashboard) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(filepath.Join("frontend", "index.html"))
	if err != nil {
		log.Printf("read frontend: %v", err)
		http.Error(w, "Dashboard UI unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (d *dashboard) authStatus(w http.ResponseWriter, r *http.Request) {
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	cookie, _ := r.Cookie(sessionCookieName)
	d.mu.Lock()
	authenticated := cookie != nil && d.sessions[cookie.Value].After(time.Now())
	d.mu.Unlock()
	_, configured := settings["password"]
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured, "authenticated": authenticated})
}

func (d *dashboard) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	saved, ok := settings["password"].(map[string]any)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "Password setup required on the dashboard host")
		return
	}
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		address = r.RemoteAddr
	}
	now := time.Now()
	d.mu.Lock()
	attempts := recentAttempts(d.loginAttempts[address], now.Add(-5*time.Minute))
	d.loginAttempts[address] = attempts
	if len(attempts) >= 5 {
		d.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "Too many login attempts; try again in five minutes")
		return
	}
	valid := utf8.RuneCountInString(input.Password) <= 1024 && checkPassword(input.Password, saved)
	if !valid {
		d.loginAttempts[address] = append(attempts, now)
		d.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "Invalid password")
		return
	}
	delete(d.loginAttempts, address)
	for token, expiry := range d.sessions {
		if !expiry.After(now) {
			delete(d.sessions, token)
		}
	}
	token, err := randomToken(32)
	if err != nil {
		d.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "Cannot create session")
		return
	}
	d.sessions[token] = now.Add(sessionDuration)
	d.mu.Unlock()
	secure := r.TLS != nil || trustedProxy(r.RemoteAddr) && r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", MaxAge: int(sessionDuration.Seconds()),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *dashboard) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		d.mu.Lock()
		delete(d.sessions, cookie.Value)
		d.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *dashboard) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	saved, ok := settings["password"].(map[string]any)
	if !ok || utf8.RuneCountInString(input.CurrentPassword) > 1024 || !checkPassword(input.CurrentPassword, saved) {
		writeError(w, http.StatusBadRequest, "Invalid current password")
		return
	}
	if err := validatePassword(input.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := passwordHash(input.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot secure dashboard password")
		return
	}
	settings["password"] = hash
	if err := d.store.writeSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot save dashboard settings")
		return
	}
	d.mu.Lock()
	clear(d.sessions)
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *dashboard) getTelegram(w http.ResponseWriter, r *http.Request) {
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	value := objectAt(settings, "telegram")
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": boolValue(value["enabled"]), "chat_id": stringValue(value["chat_id"]),
		"token_configured": stringValue(value["token"]) != "", "events": stringSlice(value["events"]),
		"delivery_paused": d.deliveryPaused("telegram", value),
	})
}

func (d *dashboard) setTelegram(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled bool     `json:"enabled"`
		ChatID  string   `json:"chat_id"`
		Token   string   `json:"token"`
		Events  []string `json:"events"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	events, ok := normalizeEvents(input.Events)
	if !ok {
		writeError(w, http.StatusBadRequest, "Unknown event type")
		return
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	old := objectAt(settings, "telegram")
	token := strings.TrimSpace(input.Token)
	if token == "" {
		token = stringValue(old["token"])
	}
	chatID := normalizeChatID(input.ChatID)
	if input.Enabled && (token == "" || chatID == "" || len(events) == 0) {
		writeError(w, http.StatusBadRequest, "Token, chat ID and at least one event are required")
		return
	}
	if !validBotToken(token) {
		writeError(w, http.StatusBadRequest, "Invalid bot token")
		return
	}
	if !validChatID(chatID) {
		writeError(w, http.StatusBadRequest, "Invalid chat ID")
		return
	}
	enabledAt := numberValue(old["enabled_at"])
	if !boolValue(old["enabled"]) && input.Enabled {
		enabledAt = float64(time.Now().Unix())
	}
	settings["telegram"] = map[string]any{"enabled": input.Enabled, "chat_id": chatID, "token": token,
		"events": events, "enabled_at": enabledAt}
	if err := d.store.writeSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot save dashboard settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *dashboard) getProvider(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	if !editableProviders[name] {
		writeError(w, http.StatusNotFound, "Unknown notification provider")
		return
	}
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	saved := objectAt(objectAt(settings, "providers"), name)
	server := stringValue(saved["server_url"])
	if server == "" && name == "ntfy" {
		server = "https://ntfy.sh"
	}
	result := map[string]any{"enabled": boolValue(saved["enabled"]), "events": stringSlice(saved["events"]),
		"server_url": server, "webhook_configured": stringValue(saved["webhook_url"]) != "",
		"topic_configured": stringValue(saved["topic"]) != "", "token_configured": stringValue(saved["token"]) != "",
		"user_key_configured": stringValue(saved["user_key"]) != "", "delivery_paused": d.deliveryPaused(name, saved),
		"host": stringValue(saved["host"]), "port": intValue(saved["port"], 587),
		"security": orDefault(stringValue(saved["security"]), "starttls"),
		"username": stringValue(saved["username"]), "password_configured": stringValue(saved["password"]) != "",
		"sender": stringValue(saved["sender"]), "recipient": stringValue(saved["recipient"])}
	writeJSON(w, http.StatusOK, result)
}

type providerInput struct {
	Enabled    bool     `json:"enabled"`
	Events     []string `json:"events"`
	WebhookURL string   `json:"webhook_url"`
	ServerURL  string   `json:"server_url"`
	Topic      string   `json:"topic"`
	Token      string   `json:"token"`
	UserKey    string   `json:"user_key"`
	ClearToken bool     `json:"clear_token"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Security   string   `json:"security"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Sender     string   `json:"sender"`
	Recipient  string   `json:"recipient"`
}

func (d *dashboard) setProvider(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	if !editableProviders[name] {
		writeError(w, http.StatusNotFound, "Unknown notification provider")
		return
	}
	var input providerInput
	if !decodeBody(w, r, &input) {
		return
	}
	events, ok := normalizeEvents(input.Events)
	if !ok {
		writeError(w, http.StatusBadRequest, "Unknown event type")
		return
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	providerSettings := objectAt(settings, "providers")
	old := objectAt(providerSettings, name)
	saved := map[string]any{"enabled": input.Enabled, "events": events,
		"enabled_at": numberValue(old["enabled_at"])}
	if !boolValue(old["enabled"]) && input.Enabled {
		saved["enabled_at"] = float64(time.Now().Unix())
	}
	configured := false
	switch name {
	case "discord":
		webhook := strings.TrimSpace(input.WebhookURL)
		if webhook == "" {
			webhook = stringValue(old["webhook_url"])
		}
		parsed, parseErr := url.Parse(webhook)
		valid := parseErr == nil && (parsed.Host == "discord.com" || parsed.Host == "discordapp.com") &&
			parsed.Scheme == "https" && regexp.MustCompile(`^/api/(v\d+/)?webhooks/\d+/[A-Za-z0-9_-]+$`).MatchString(parsed.Path) &&
			parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && len(webhook) <= 1000
		if webhook != "" && !valid {
			writeError(w, http.StatusBadRequest, "Invalid Discord webhook URL")
			return
		}
		saved["webhook_url"] = webhook
		configured = webhook != ""
	case "ntfy":
		server := strings.TrimRight(strings.TrimSpace(input.ServerURL), "/")
		topic := strings.TrimSpace(input.Topic)
		if topic == "" {
			topic = stringValue(old["topic"])
		}
		if input.ClearToken && strings.TrimSpace(input.Token) != "" {
			writeError(w, http.StatusBadRequest, "Cannot remove and replace the ntfy token at the same time")
			return
		}
		token := stringValue(old["token"])
		if input.ClearToken {
			token = ""
		} else if strings.TrimSpace(input.Token) != "" {
			token = strings.TrimSpace(input.Token)
		}
		if server != "" && !validHTTPURL(server, false) {
			writeError(w, http.StatusBadRequest, "Invalid ntfy server URL")
			return
		}
		if topic != "" && !regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`).MatchString(topic) {
			writeError(w, http.StatusBadRequest, "Invalid ntfy topic")
			return
		}
		if !validSecret(token, 512) {
			writeError(w, http.StatusBadRequest, "Invalid ntfy token")
			return
		}
		saved["server_url"], saved["topic"], saved["token"] = server, topic, token
		configured = server != "" && topic != ""
	case "email":
		host := strings.TrimSpace(input.Host)
		username := strings.TrimSpace(input.Username)
		password := input.Password
		if input.ClearToken && input.Password != "" {
			writeError(w, http.StatusBadRequest, "Cannot remove and replace the SMTP password at the same time")
			return
		}
		if input.ClearToken {
			password = ""
		} else if password == "" {
			password = stringValue(old["password"])
		}
		sender := strings.TrimSpace(input.Sender)
		recipients := []string{}
		for _, recipient := range strings.Split(input.Recipient, ",") {
			if recipient = strings.TrimSpace(recipient); recipient != "" {
				recipients = append(recipients, recipient)
			}
		}
		recipient := strings.Join(recipients, ", ")
		port := input.Port
		if port == 0 {
			port = intValue(old["port"], 587)
		}
		security := input.Security
		if security == "" {
			security = orDefault(stringValue(old["security"]), "starttls")
		}
		if host != "" && !regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`).MatchString(host) ||
			port < 1 || port > 65535 || (security != "starttls" && security != "ssl" && security != "none") {
			writeError(w, http.StatusBadRequest, "Invalid SMTP host, port or security mode")
			return
		}
		if len(username) > 256 || len(password) > 256 || strings.IndexFunc(username+password, func(r rune) bool { return r < 32 }) >= 0 {
			writeError(w, http.StatusBadRequest, "Invalid SMTP credentials")
			return
		}
		if (sender != "" && !validAddress.MatchString(sender)) || len(sender) > 320 || len(recipient) > 1000 {
			writeError(w, http.StatusBadRequest, "Invalid e-mail address")
			return
		}
		for _, address := range recipients {
			if !validAddress.MatchString(address) {
				writeError(w, http.StatusBadRequest, "Invalid e-mail address")
				return
			}
		}
		saved["host"], saved["port"], saved["security"] = host, port, security
		saved["username"], saved["password"], saved["sender"], saved["recipient"] = username, password, sender, recipient
		configured = host != "" && sender != "" && recipient != ""
	case "webhook":
		webhook := strings.TrimSpace(input.WebhookURL)
		if webhook == "" {
			webhook = stringValue(old["webhook_url"])
		}
		if input.ClearToken && strings.TrimSpace(input.Token) != "" {
			writeError(w, http.StatusBadRequest, "Cannot remove and replace the webhook token at the same time")
			return
		}
		token := stringValue(old["token"])
		if input.ClearToken {
			token = ""
		} else if strings.TrimSpace(input.Token) != "" {
			token = strings.TrimSpace(input.Token)
		}
		if webhook != "" && !validHTTPURL(webhook, true) {
			writeError(w, http.StatusBadRequest, "Invalid webhook URL")
			return
		}
		if !validSecret(token, 512) {
			writeError(w, http.StatusBadRequest, "Invalid webhook token")
			return
		}
		saved["webhook_url"], saved["token"] = webhook, token
		configured = webhook != ""
	case "gotify":
		server := strings.TrimRight(strings.TrimSpace(input.ServerURL), "/")
		token := strings.TrimSpace(input.Token)
		if token == "" {
			token = stringValue(old["token"])
		}
		if server != "" && !validHTTPURL(server, false) {
			writeError(w, http.StatusBadRequest, "Invalid Gotify server URL")
			return
		}
		if !validSecret(token, 512) {
			writeError(w, http.StatusBadRequest, "Invalid Gotify token")
			return
		}
		saved["server_url"], saved["token"] = server, token
		configured = server != "" && token != ""
	case "pushover":
		token, userKey := strings.TrimSpace(input.Token), strings.TrimSpace(input.UserKey)
		if token == "" {
			token = stringValue(old["token"])
		}
		if userKey == "" {
			userKey = stringValue(old["user_key"])
		}
		valid := regexp.MustCompile(`^[A-Za-z0-9]{30}$`)
		if (token != "" && !valid.MatchString(token)) || (userKey != "" && !valid.MatchString(userKey)) {
			writeError(w, http.StatusBadRequest, "Invalid Pushover token or user key")
			return
		}
		saved["token"], saved["user_key"] = token, userKey
		configured = token != "" && userKey != ""
	}
	if input.Enabled && !configured {
		writeError(w, http.StatusBadRequest, "Provider credentials are required")
		return
	}
	providerSettings[name] = saved
	settings["providers"] = providerSettings
	if err := d.store.writeSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot save dashboard settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *dashboard) getMonitoring(w http.ResponseWriter, r *http.Request) {
	all, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	saved := objectAt(all, "monitoring")
	thresholds := map[string]float64{}
	oldThresholds := objectAt(saved, "thresholds")
	for name := range d.agents {
		thresholds[name] = floatValue(oldThresholds[name], 45)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"temperature_enabled": boolValue(saved["temperature_enabled"]),
		"hardware_enabled":    boolValue(saved["hardware_enabled"]),
		"daily_report":        boolValue(saved["daily_report"]),
		"daily_report_time":   orDefault(stringValue(saved["daily_report_time"]), "12:00"),
		"thresholds":          thresholds,
	})
}

func (d *dashboard) setMonitoring(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TemperatureEnabled bool               `json:"temperature_enabled"`
		HardwareEnabled    bool               `json:"hardware_enabled"`
		DailyReport        bool               `json:"daily_report"`
		DailyReportTime    *string            `json:"daily_report_time"`
		Thresholds         map[string]float64 `json:"thresholds"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if input.DailyReportTime != nil && !regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`).MatchString(*input.DailyReportTime) {
		writeError(w, http.StatusBadRequest, "Invalid daily report time (HH:MM)")
		return
	}
	for name, threshold := range input.Thresholds {
		if _, exists := d.agents[name]; !exists || math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < -50 || threshold > 150 {
			writeError(w, http.StatusBadRequest, "Invalid host or temperature threshold (-50 to 150 °C)")
			return
		}
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	if (input.TemperatureEnabled || input.HardwareEnabled || input.DailyReport) && len(enabledProviders(settings)) == 0 {
		writeError(w, http.StatusBadRequest, "Enable a notification provider first")
		return
	}
	old := objectAt(settings, "monitoring")
	now := float64(time.Now().Unix())
	reportStarted := numberValue(old["report_started_at"])
	if !boolValue(old["daily_report"]) {
		reportStarted = now
	}
	temperatureStarted := numberValue(old["temperature_started_at"])
	if !boolValue(old["temperature_enabled"]) {
		temperatureStarted = now
	}
	hardwareStarted := numberValue(old["hardware_started_at"])
	if !boolValue(old["hardware_enabled"]) {
		hardwareStarted = now
	}
	reportTime := stringValue(old["daily_report_time"])
	if input.DailyReportTime != nil {
		reportTime = *input.DailyReportTime
	}
	if reportTime == "" {
		reportTime = "12:00"
	}
	if input.Thresholds == nil {
		input.Thresholds = map[string]float64{}
	}
	thresholds := map[string]any{}
	for name, value := range input.Thresholds {
		thresholds[name] = value
	}
	settings["monitoring"] = map[string]any{
		"temperature_enabled": input.TemperatureEnabled, "hardware_enabled": input.HardwareEnabled,
		"daily_report": input.DailyReport, "daily_report_time": reportTime, "thresholds": thresholds,
		"report_started_at": reportStarted, "temperature_started_at": temperatureStarted,
		"hardware_started_at": hardwareStarted,
	}
	if err := d.store.writeSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot save dashboard settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type checkInput struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Target string `json:"target"`
	Port   *int   `json:"port"`
	Notify *bool  `json:"notify"`
}

func (d *dashboard) getChecks(w http.ResponseWriter, r *http.Request) {
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	checks, _ := settings["checks"].([]any)
	result := make([]map[string]any, 0, len(checks))
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, raw := range checks {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		check := cloneMap(item)
		check["status"] = d.checkStatus[stringValue(item["name"])]
		result = append(result, check)
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": result})
}

func (d *dashboard) setChecks(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Checks []checkInput `json:"checks"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if len(input.Checks) > 50 {
		writeError(w, http.StatusBadRequest, "At most 50 checks are allowed")
		return
	}
	normalized := make([]map[string]any, 0, len(input.Checks))
	seen := map[string]bool{}
	for _, check := range input.Checks {
		name, target := strings.TrimSpace(check.Name), strings.TrimSpace(check.Target)
		if !regexp.MustCompile(`^[^\x00-\x1f]{1,64}$`).MatchString(name) {
			writeError(w, http.StatusBadRequest, "Invalid check name (1-64 characters)")
			return
		}
		if !checkTypes[check.Type] {
			writeError(w, http.StatusBadRequest, "Unknown check type")
			return
		}
		if check.Type == "http" {
			if !validHTTPURL(target, true) {
				writeError(w, http.StatusBadRequest, "Invalid HTTP check URL")
				return
			}
		} else if !regexp.MustCompile(`^[A-Za-z0-9:][A-Za-z0-9._:-]{0,252}$`).MatchString(target) {
			writeError(w, http.StatusBadRequest, "Invalid check host")
			return
		}
		var port any
		if check.Type == "tcp" {
			if check.Port == nil || *check.Port < 1 || *check.Port > 65535 {
				writeError(w, http.StatusBadRequest, "A TCP check needs a port (1-65535)")
				return
			}
			port = *check.Port
		}
		if seen[name] {
			writeError(w, http.StatusBadRequest, "Check names must be unique")
			return
		}
		seen[name] = true
		notify := true
		if check.Notify != nil {
			notify = *check.Notify
		}
		normalized = append(normalized, map[string]any{"name": name, "type": check.Type, "target": target,
			"port": port, "notify": notify})
	}
	d.store.mu.Lock()
	defer d.store.mu.Unlock()
	settings, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	settings["checks"] = normalized
	if err := d.store.writeSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot save dashboard settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func normalizeEvents(input []string) ([]string, bool) {
	for _, event := range input {
		if !eventTypes[event] {
			return nil, false
		}
	}
	return sortStringsUnique(input), true
}

func stringSlice(value any) []string {
	items, _ := value.([]any)
	if items == nil {
		if strings, ok := value.([]string); ok {
			return strings
		}
		return []string{}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func objectAt(value map[string]any, key string) map[string]any {
	if object, ok := value[key].(map[string]any); ok {
		return object
	}
	return map[string]any{}
}

func numberValue(value any) float64 {
	number, _ := finiteNumber(value)
	return number
}

func intValue(value any, fallback int) int {
	number, ok := value.(float64)
	if !ok {
		return fallback
	}
	return int(number)
}

func validBotToken(value string) bool {
	if value == "" {
		return true
	}
	return len(value) <= 200 && regexp.MustCompile(`^[A-Za-z0-9_:-]+$`).MatchString(value) && isASCII(value)
}

func validChatID(value string) bool {
	if value == "" {
		return true
	}
	return len(value) <= 100 && regexp.MustCompile(`^[A-Za-z0-9_@-]+$`).MatchString(value) && isASCII(value)
}

func normalizeChatID(value string) string {
	var out strings.Builder
	for _, r := range value {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			continue
		}
		switch r {
		case '‐', '‑', '‒', '–', '—', '−':
			r = '-'
		}
		out.WriteRune(r)
	}
	return out.String()
}

func validSecret(value string, limit int) bool {
	if value == "" {
		return true
	}
	if len(value) > limit {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	return true
}

func trustedProxy(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	address := net.ParseIP(host)
	if address == nil {
		return false
	}
	for _, entry := range strings.Split(env("TRUSTED_PROXIES", ""), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			if ip.Equal(address) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err == nil && network.Contains(address) {
			return true
		}
	}
	return false
}

func (d *dashboard) agentRequest(ctx context.Context, item agentConfig, path string) (*http.Response, error) {
	client := safeHTTPClient()
	if item.CACert != "" {
		pem, err := os.ReadFile(item.CACert)
		if err != nil {
			return nil, fmt.Errorf("read agent CA certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("agent CA certificate contains no valid certificates")
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	}
	key := item.Key
	if key == "" {
		key = d.agentKey
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(item.URL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	if key != "" {
		request.Header.Set("X-Agent-Key", key)
	}
	return client.Do(request)
}

func (d *dashboard) fetchAgent(ctx context.Context, name string, item agentConfig) (string, map[string]any) {
	if item.Mode == "push" {
		data, err := d.pushedMetrics(name)
		if err != nil {
			return name, map[string]any{"online": false, "error": err.Error()}
		}
		data["online"] = true
		return name, data
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	response, err := d.agentRequest(ctx, item, "/api/metrics")
	if err != nil {
		return name, map[string]any{"online": false, "error": notificationError(err)}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return name, map[string]any{"online": false, "error": fmt.Sprintf("agent returned HTTP %d", response.StatusCode)}
	}
	data := map[string]any{}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&data); err != nil {
		return name, map[string]any{"online": false, "error": "invalid agent response"}
	}
	data["online"] = true
	return name, data
}

func (d *dashboard) getDashboard(w http.ResponseWriter, r *http.Request) {
	results := make(map[string]any, len(d.agents))
	var mu sync.Mutex
	var workers sync.WaitGroup
	for name, item := range d.agents {
		workers.Add(1)
		go func(name string, item agentConfig) {
			defer workers.Done()
			key, value := d.fetchAgent(r.Context(), name, item)
			mu.Lock()
			results[key] = value
			mu.Unlock()
		}(name, item)
	}
	workers.Wait()
	writeJSON(w, http.StatusOK, results)
}

func (d *dashboard) history(w http.ResponseWriter, r *http.Request) {
	d.historyData(w, r, false)
}

func (d *dashboard) containerHistory(w http.ResponseWriter, r *http.Request) {
	d.historyData(w, r, true)
}

func (d *dashboard) historyData(w http.ResponseWriter, r *http.Request, containers bool) {
	hostName := r.URL.Query().Get("host")
	if _, ok := d.agents[hostName]; !ok {
		writeError(w, http.StatusNotFound, "Unknown host")
		return
	}
	hours, err := strconv.Atoi(orDefault(r.URL.Query().Get("hours"), "24"))
	if err != nil {
		hours = 0
	}
	bucketSize, valid := historyBuckets[hours]
	if !valid {
		writeError(w, http.StatusBadRequest, "Invalid history range")
		return
	}
	end := time.Now().Unix()/60*60 + 60
	start := end - int64(hours*3600)
	if containers {
		d.containerHistoryData(w, hostName, hours, bucketSize, start, end)
		return
	}
	rows, err := d.store.db.Query(`SELECT (time / ?) * ? AS bucket, COUNT(*),
		AVG(cpu), AVG(ram), AVG(disk), AVG(temperature),
		COUNT(cpu), COUNT(ram), COUNT(disk), COUNT(temperature)
		FROM metrics WHERE host=? AND time>=? AND time<? GROUP BY bucket ORDER BY bucket`,
		bucketSize, bucketSize, hostName, start, end)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read metric history")
		return
	}
	defer rows.Close()
	type groupedMetric struct {
		count                                           int
		cpu, ram, disk, temperature                     sql.NullFloat64
		cpuCount, ramCount, diskCount, temperatureCount int
	}
	grouped := map[int64]groupedMetric{}
	for rows.Next() {
		var bucket int64
		var values groupedMetric
		if err := rows.Scan(&bucket, &values.count, &values.cpu, &values.ram, &values.disk, &values.temperature,
			&values.cpuCount, &values.ramCount, &values.diskCount, &values.temperatureCount); err != nil {
			writeError(w, http.StatusInternalServerError, "Cannot read metric history")
			return
		}
		grouped[bucket] = values
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read metric history")
		return
	}
	first := start / int64(bucketSize) * int64(bucketSize)
	points := []map[string]any{}
	for bucket := first; bucket < end; bucket += int64(bucketSize) {
		value := grouped[bucket]
		expected := (min(bucket+int64(bucketSize), end) - max(bucket, start)) / 60
		points = append(points, map[string]any{
			"time": max(bucket, start), "cpu": nullFloat(value.cpu), "ram": nullFloat(value.ram),
			"disk": nullFloat(value.disk), "temperature": nullFloat(value.temperature),
			"complete": int64(value.count) == expected,
			"missing": map[string]bool{"cpu": int64(value.cpuCount) < expected, "ram": int64(value.ramCount) < expected,
				"disk": int64(value.diskCount) < expected, "temperature": int64(value.temperatureCount) < expected},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": hostName, "hours": hours, "bucket_seconds": bucketSize, "points": points})
}

func (d *dashboard) containerHistoryData(w http.ResponseWriter, hostName string, hours, bucketSize int, start, end int64) {
	rows, err := d.store.db.Query(`SELECT container, (time / ?) * ? AS bucket, AVG(cpu), AVG(ram), AVG(rx), AVG(tx)
		FROM container_metrics WHERE host=? AND time>=? AND time<? GROUP BY container, bucket ORDER BY container, bucket`,
		bucketSize, bucketSize, hostName, start, end)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read container history")
		return
	}
	defer rows.Close()
	containers := map[string][]map[string]any{}
	for rows.Next() {
		var name string
		var bucket int64
		var cpu, ram, rx, tx sql.NullFloat64
		if err := rows.Scan(&name, &bucket, &cpu, &ram, &rx, &tx); err != nil {
			writeError(w, http.StatusInternalServerError, "Cannot read container history")
			return
		}
		containers[name] = append(containers[name], map[string]any{
			"time": max(bucket, start), "cpu": nullFloat(cpu), "ram": nullFloat(ram),
			"rx": nullFloat(rx), "tx": nullFloat(tx),
		})
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read container history")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": hostName, "hours": hours,
		"bucket_seconds": bucketSize, "containers": containers})
}

func nullFloat(value sql.NullFloat64) any {
	if !value.Valid {
		return nil
	}
	return value.Float64
}

func (d *dashboard) collectHistory(ctx context.Context, now time.Time) error {
	type result struct {
		host string
		data map[string]any
	}
	resultCh := make(chan result, len(d.agents))
	var workers sync.WaitGroup
	for name, item := range d.agents {
		workers.Add(1)
		go func(name string, item agentConfig) {
			defer workers.Done()
			hostName, data := d.fetchAgent(ctx, name, item)
			resultCh <- result{host: hostName, data: data}
		}(name, item)
	}
	workers.Wait()
	close(resultCh)
	slot := now.Unix() / 60 * 60
	tx, err := d.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for item := range resultCh {
		if !boolValue(item.data["online"]) {
			log.Printf("History collection failed for %s: %v", item.host, item.data["error"])
			continue
		}
		cpu, ram, storage, temperature := metricValue(item.data["cpu_percent"], true),
			metricValue(item.data["ram_percent"], true), metricValue(item.data["storage_percent"], true),
			metricValue(item.data["temperature_c"], false)
		if _, err := tx.Exec(`INSERT OR REPLACE INTO metrics VALUES (?, ?, ?, ?, ?, ?)`,
			item.host, slot, cpu, ram, storage, temperature); err != nil {
			return err
		}
		stats := objectAt(item.data, "docker_stats")
		containers, ok := stats["containers"].([]any)
		if !boolValue(stats["available"]) || !ok {
			continue
		}
		for _, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := stringValue(container["name"])
			if name == "" || len(name) > 128 {
				continue
			}
			values := []any{nonnegativeMetricValue(container["cpu_percent"]), nonnegativeMetricValue(container["ram_percent"]),
				nonnegativeMetricValue(container["net_rx_bytes_per_s"]), nonnegativeMetricValue(container["net_tx_bytes_per_s"])}
			if _, err := tx.Exec(`INSERT OR REPLACE INTO container_metrics VALUES (?, ?, ?, ?, ?, ?, ?)`,
				item.host, name, slot, values[0], values[1], values[2], values[3]); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM metrics WHERE time < ?`, slot-30*24*60*60+60); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM container_metrics WHERE time < ?`, slot-30*24*60*60+60); err != nil {
		return err
	}
	return tx.Commit()
}

func metricValue(value any, percent bool) any {
	number, ok := finiteNumber(value)
	if !ok || number < 0 && percent || percent && number > 100 {
		return nil
	}
	return number
}

func nonnegativeMetricValue(value any) any {
	number, ok := finiteNumber(value)
	if !ok || number < 0 {
		return nil
	}
	return number
}

func (d *dashboard) runCheck(check map[string]any) (bool, any, any) {
	started := time.Now()
	kind, target := stringValue(check["type"]), stringValue(check["target"])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	switch kind {
	case "http":
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if requestErr != nil {
			err = requestErr
			break
		}
		response, requestErr := (&http.Client{Timeout: 10 * time.Second}).Do(request)
		if requestErr != nil {
			err = requestErr
		} else {
			response.Body.Close()
			if response.StatusCode >= 400 {
				return false, nil, fmt.Sprintf("HTTP %d", response.StatusCode)
			}
		}
	case "tcp":
		port := intValue(check["port"], 0)
		connection, connectErr := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp",
			net.JoinHostPort(target, strconv.Itoa(port)))
		if connectErr != nil {
			err = connectErr
		} else {
			connection.Close()
		}
	case "dns":
		_, err = net.DefaultResolver.LookupHost(ctx, target)
	case "ping":
		if _, lookErr := exec.LookPath("ping"); lookErr != nil {
			return false, nil, "ping is not installed"
		}
		command := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", target)
		if runErr := command.Run(); runErr != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return false, nil, "Timeout"
			}
			return false, nil, "No ping reply"
		}
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, nil, "Timeout"
		}
		return false, nil, fmt.Sprintf("%T", err)
	}
	return true, math.Round(float64(time.Since(started).Milliseconds())), nil
}

func recentAttempts(attempts []time.Time, after time.Time) []time.Time {
	valid := attempts[:0]
	for _, attempt := range attempts {
		if attempt.After(after) {
			valid = append(valid, attempt)
		}
	}
	return valid
}

func passwordHash(password string) (map[string]any, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return map[string]any{"salt": hex.EncodeToString(salt),
		"hash": hex.EncodeToString(pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, 32))}, nil
}

func checkPassword(password string, saved map[string]any) bool {
	saltHex, _ := saved["salt"].(string)
	hashHex, _ := saved["hash"].(string)
	salt, saltErr := hex.DecodeString(saltHex)
	expected, hashErr := hex.DecodeString(hashHex)
	if saltErr != nil || hashErr != nil || len(expected) != 32 {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, size int) []byte {
	var result []byte
	for block := uint32(1); len(result) < size; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		value := mac.Sum(nil)
		output := append([]byte(nil), value...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(value)
			value = mac.Sum(nil)
			for j := range output {
				output[j] ^= value[j]
			}
		}
		result = append(result, output...)
	}
	return result[:size]
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < 12 || utf8.RuneCountInString(password) > 1024 {
		return errors.New("Password must contain 12 to 1024 characters")
	}
	return nil
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func decodeBody(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON request body")
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "Invalid JSON request body")
		return false
	}
	return true
}

func validHTTPURL(value string, allowQuery bool) bool {
	if len(value) > 1000 || strings.IndexFunc(value, func(r rune) bool { return r <= 0x20 }) >= 0 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Fragment != "" || (!allowQuery && parsed.RawQuery != "") {
		return false
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var validAddress = regexp.MustCompile(`^[^@\s<>,;"]{1,64}@[A-Za-z0-9.-]{1,253}$`)

func jsonFingerprint(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func finiteNumber(value any) (float64, bool) {
	number, ok := value.(float64)
	return number, ok && !math.IsNaN(number) && !math.IsInf(number, 0)
}

func sortStringsUnique(input []string) []string {
	output := append([]string(nil), input...)
	sort.Strings(output)
	if len(output) < 2 {
		return output
	}
	result := output[:1]
	for _, value := range output[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func floatValue(value any, fallback float64) float64 {
	if number, ok := finiteNumber(value); ok {
		return number
	}
	return fallback
}
