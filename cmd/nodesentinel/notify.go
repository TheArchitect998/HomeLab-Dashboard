package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func enabledProviders(settings map[string]any) map[string]map[string]any {
	result := map[string]map[string]any{}
	telegram := objectAt(settings, "telegram")
	if boolValue(telegram["enabled"]) {
		result["telegram"] = telegram
	}
	configured := objectAt(settings, "providers")
	for _, name := range providers {
		if name == "telegram" {
			continue
		}
		entry := objectAt(configured, name)
		if boolValue(entry["enabled"]) {
			result[name] = entry
		}
	}
	return result
}

func (d *dashboard) deliveryPaused(provider string, settings map[string]any) bool {
	fingerprint := jsonFingerprint(settings)
	d.mu.Lock()
	defer d.mu.Unlock()
	failure, exists := d.providerState[provider]
	if !exists {
		return false
	}
	if failure.fingerprint != fingerprint {
		delete(d.providerState, provider)
		return false
	}
	return failure.retryAt.After(time.Now())
}

func (d *dashboard) providerMutex(provider string) *sync.Mutex {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.providerLocks == nil {
		d.providerLocks = map[string]*sync.Mutex{}
	}
	if d.providerLocks[provider] == nil {
		d.providerLocks[provider] = &sync.Mutex{}
	}
	return d.providerLocks[provider]
}

func (d *dashboard) sendNotification(ctx context.Context, provider string, settings map[string]any, message string) error {
	lock := d.providerMutex(provider)
	lock.Lock()
	defer lock.Unlock()
	fingerprint := jsonFingerprint(settings)
	d.mu.Lock()
	failure, exists := d.providerState[provider]
	if exists && failure.fingerprint != fingerprint {
		delete(d.providerState, provider)
		exists = false
	}
	if exists && failure.retryAt.After(time.Now()) {
		d.mu.Unlock()
		return errors.New("notification provider temporarily paused")
	}
	d.mu.Unlock()
	err := deliverNotification(ctx, provider, settings, message)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		delete(d.providerState, provider)
		return nil
	}
	var responseErr *httpStatusError
	if errors.As(err, &responseErr) && responseErr.status >= 400 && responseErr.status < 500 {
		retryAt := time.Now().Add(100 * 365 * 24 * time.Hour)
		if responseErr.status == http.StatusTooManyRequests && provider != "pushover" {
			delay := 60 * time.Second
			if seconds, parseErr := strconv.ParseFloat(responseErr.retryAfter, 64); parseErr == nil &&
				!math.IsNaN(seconds) && !math.IsInf(seconds, 0) {
				delay = time.Duration(math.Max(15, math.Min(seconds, 86400)) * float64(time.Second))
			}
			retryAt = time.Now().Add(delay)
		}
		d.providerState[provider] = providerFailure{fingerprint: fingerprint, retryAt: retryAt}
		log.Printf("Notification provider %s paused after HTTP %d; check its configuration", provider, responseErr.status)
	} else if provider == "pushover" && errors.Is(err, errProviderRejected) {
		d.providerState[provider] = providerFailure{fingerprint: fingerprint, retryAt: time.Now().Add(100 * 365 * 24 * time.Hour)}
		log.Printf("Notification provider %s paused after rejecting a request", provider)
	}
	return err
}

var errProviderRejected = errors.New("notification provider rejected message")

type httpStatusError struct {
	status     int
	retryAfter string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d", e.status)
}

func deliverNotification(ctx context.Context, provider string, settings map[string]any, message string) error {
	switch provider {
	case "telegram":
		endpoint := "https://api.telegram.org/bot" + stringValue(settings["token"]) + "/sendMessage"
		response, err := postJSON(ctx, endpoint, nil, map[string]any{
			"chat_id": settings["chat_id"], "text": message,
		})
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if err := ensureSuccess(response); err != nil {
			return err
		}
		var payload map[string]any
		if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload) != nil || !boolValue(payload["ok"]) {
			return errProviderRejected
		}
		return nil
	case "discord":
		webhook := stringValue(settings["webhook_url"])
		for _, part := range splitRunes(message, 1000) {
			target, err := url.Parse(webhook)
			if err != nil {
				return err
			}
			query := target.Query()
			query.Set("wait", "true")
			target.RawQuery = query.Encode()
			response, err := postJSON(ctx, target.String(), nil, map[string]any{
				"content": part, "allowed_mentions": map[string]any{"parse": []string{}},
			})
			if err != nil {
				return err
			}
			response.Body.Close()
			if err := ensureSuccess(response); err != nil {
				return err
			}
		}
		return nil
	case "ntfy":
		headers := map[string]string{"Content-Type": "text/plain; charset=utf-8", "Title": "NodeSentinel"}
		if token := stringValue(settings["token"]); token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		endpoint := strings.TrimRight(stringValue(settings["server_url"]), "/") + "/" + stringValue(settings["topic"])
		response, err := doRequest(ctx, http.MethodPost, endpoint, headers, []byte(message), nil)
		if err != nil {
			return err
		}
		response.Body.Close()
		return ensureSuccess(response)
	case "pushover":
		for _, part := range splitRunes(message, 1000) {
			form := url.Values{"token": {stringValue(settings["token"])}, "user": {stringValue(settings["user_key"])}, "message": {part}}
			response, err := doRequest(ctx, http.MethodPost, "https://api.pushover.net/1/messages.json",
				map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()), nil)
			if err != nil {
				return err
			}
			if err := ensureSuccess(response); err != nil {
				response.Body.Close()
				return err
			}
			var payload map[string]any
			err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload)
			response.Body.Close()
			if err != nil || floatValue(payload["status"], 0) != 1 {
				return errProviderRejected
			}
		}
		return nil
	case "email":
		return sendEmail(settings, message)
	case "webhook":
		headers := map[string]string{}
		if token := stringValue(settings["token"]); token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		response, err := postJSON(ctx, stringValue(settings["webhook_url"]), headers,
			map[string]any{"source": "nodesentinel", "message": message, "text": message})
		if err != nil {
			return err
		}
		response.Body.Close()
		return ensureSuccess(response)
	case "gotify":
		response, err := postJSON(ctx, strings.TrimRight(stringValue(settings["server_url"]), "/")+"/message",
			map[string]string{"X-Gotify-Key": stringValue(settings["token"])},
			map[string]any{"title": "NodeSentinel", "message": message, "priority": 5})
		if err != nil {
			return err
		}
		response.Body.Close()
		return ensureSuccess(response)
	default:
		return errors.New("unknown notification provider")
	}
}

func postJSON(ctx context.Context, endpoint string, headers map[string]string, payload any) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	return doRequest(ctx, http.MethodPost, endpoint, headers, data, nil)
}

func doRequest(ctx context.Context, method, endpoint string, headers map[string]string, body []byte, client *http.Client) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if client == nil {
		client = safeHTTPClient()
	}
	return client.Do(request)
}

func ensureSuccess(response *http.Response) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return &httpStatusError{status: response.StatusCode, retryAfter: response.Header.Get("Retry-After")}
}

func splitRunes(value string, maxRunes int) []string {
	runes := []rune(value)
	if len(runes) == 0 {
		return []string{""}
	}
	var chunks []string
	for offset := 0; offset < len(runes); offset += maxRunes {
		end := min(offset+maxRunes, len(runes))
		chunks = append(chunks, string(runes[offset:end]))
	}
	return chunks
}

func sendEmail(settings map[string]any, message string) error {
	host := stringValue(settings["host"])
	port := intValue(settings["port"], 587)
	address := net.JoinHostPort(host, strconv.Itoa(port))
	from, recipient := stringValue(settings["sender"]), stringValue(settings["recipient"])
	parsedFrom, err := mail.ParseAddress(from)
	if err != nil {
		return errors.New("invalid e-mail sender")
	}
	recipients := []string{}
	for _, raw := range strings.Split(recipient, ",") {
		entry, err := mail.ParseAddress(strings.TrimSpace(raw))
		if err != nil {
			return errors.New("invalid e-mail recipient")
		}
		recipients = append(recipients, entry.Address)
	}
	subject := "NodeSentinel"
	if strings.TrimSpace(message) != "" {
		subject = "NodeSentinel: " + truncate(strings.Split(message, "\n")[0], 80)
	}
	var body strings.Builder
	body.WriteString("From: ")
	body.WriteString(parsedFrom.Address)
	body.WriteString("\r\nTo: ")
	body.WriteString(strings.Join(recipients, ", "))
	body.WriteString("\r\nSubject: ")
	body.WriteString(mime.QEncoding.Encode("utf-8", subject))
	body.WriteString("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n")
	body.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	body.WriteString(strings.ReplaceAll(strings.ReplaceAll(message, "\r\n", "\n"), "\n", "\r\n"))
	timeout := 20 * time.Second
	dialer := net.Dialer{Timeout: timeout}
	security := orDefault(stringValue(settings["security"]), "starttls")
	if security == "ssl" {
		connection, err := tls.DialWithDialer(&dialer, "tcp", address, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return errors.New("SMTP delivery failed")
		}
		defer connection.Close()
		client, err := smtp.NewClient(connection, host)
		if err != nil {
			return errors.New("SMTP delivery failed")
		}
		defer client.Close()
		return sendSMTP(client, host, settings, parsedFrom.Address, recipients, body.String())
	}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return errors.New("SMTP delivery failed")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	client, err := smtp.NewClient(connection, host)
	if err != nil {
		return errors.New("SMTP delivery failed")
	}
	defer client.Close()
	if security == "starttls" {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return errors.New("SMTP delivery failed")
		}
	}
	return sendSMTP(client, host, settings, parsedFrom.Address, recipients, body.String())
}

func sendSMTP(client *smtp.Client, host string, settings map[string]any, sender string, recipients []string, message string) error {
	username := stringValue(settings["username"])
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, stringValue(settings["password"]), host)); err != nil {
			return errors.New("SMTP delivery failed")
		}
	}
	if err := client.Mail(sender); err != nil {
		return errors.New("SMTP delivery failed")
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return errors.New("SMTP delivery failed")
		}
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP delivery failed")
	}
	_, writeErr := io.WriteString(writer, message)
	closeErr := writer.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("SMTP delivery failed")
	}
	return nil
}

func (d *dashboard) testProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	known := false
	for _, name := range providers {
		if name == provider {
			known = true
			break
		}
	}
	if !known {
		writeError(w, http.StatusNotFound, "Unknown notification provider")
		return
	}
	all, err := d.store.readSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot read dashboard settings")
		return
	}
	settings, ok := enabledProviders(all)[provider]
	if !ok {
		writeError(w, http.StatusBadRequest, "Enable the notification provider first")
		return
	}
	d.mu.Lock()
	delete(d.providerState, provider)
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := d.sendNotification(ctx, provider, settings, "NodeSentinel: test notification"); err != nil {
		log.Printf("Test notification failed for %s: %s", provider, notificationError(err))
		writeError(w, http.StatusBadGateway, "Test notification failed; check the dashboard logs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func notificationError(err error) string {
	var response *httpStatusError
	if errors.As(err, &response) {
		return fmt.Sprintf("HTTP %d", response.status)
	}
	return fmt.Sprintf("%T", err)
}

func (d *dashboard) notificationLoop(ctx context.Context) {
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()
	for {
		settings, err := d.store.readSettings()
		if err != nil {
			log.Printf("Cannot read notification settings: %v", err)
		} else {
			enabled := enabledProviders(settings)
			d.mu.Lock()
			for provider := range d.notificationCursors {
				if _, exists := enabled[provider]; !exists {
					delete(d.notificationCursors, provider)
				}
			}
			d.mu.Unlock()
			now := time.Now().Unix()
			for provider, providerSettings := range enabled {
				d.pollProviderEvents(ctx, provider, providerSettings, now)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *dashboard) pollProviderEvents(ctx context.Context, provider string, settings map[string]any, now int64) {
	if d.deliveryPaused(provider, settings) {
		return
	}
	events := stringSlice(settings["events"])
	enabledEvents := map[string]bool{}
	for _, event := range events {
		enabledEvents[event] = true
	}
	for name, item := range d.agents {
		for _, kind := range []string{"ssh_login", "ssh_logout", "fail2ban", "docker"} {
			key := name + "\x00" + kind
			if !enabledEvents[kind] {
				d.mu.Lock()
				delete(d.notificationCursors[provider], key)
				d.mu.Unlock()
				continue
			}
			d.mu.Lock()
			if d.notificationCursors[provider] == nil {
				d.notificationCursors[provider] = map[string]int64{}
			}
			since, exists := d.notificationCursors[provider][key]
			if !exists {
				d.notificationCursors[provider][key] = now
				d.mu.Unlock()
				continue
			}
			d.mu.Unlock()
			if since >= now {
				continue
			}
			query := url.Values{"since": {strconv.FormatInt(since, 10)}, "until": {strconv.FormatInt(now, 10)}, "types": {kind}}
			ctxRequest, cancel := context.WithTimeout(ctx, 20*time.Second)
			response, err := d.agentRequestWithQuery(ctxRequest, item, "/api/events", query)
			if err == nil {
				var payload struct {
					Events []map[string]any `json:"events"`
				}
				if response.StatusCode < 200 || response.StatusCode >= 300 {
					err = fmt.Errorf("agent returned HTTP %d", response.StatusCode)
				} else if json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&payload) != nil || payload.Events == nil {
					err = errors.New("invalid event response")
				} else {
					for _, event := range payload.Events {
						if stringValue(event["type"]) != kind {
							err = errors.New("unexpected event type")
							break
						}
						if sendErr := d.sendNotification(ctxRequest, provider, settings, notificationText(name, event)); sendErr != nil {
							err = sendErr
							break
						}
					}
				}
				response.Body.Close()
			}
			cancel()
			if err != nil {
				log.Printf("Notification polling failed for %s (%s, %s): %s", name, kind, provider, notificationError(err))
				continue
			}
			d.mu.Lock()
			d.notificationCursors[provider][key] = now
			d.mu.Unlock()
		}
	}
}

func (d *dashboard) agentRequestWithQuery(ctx context.Context, item agentConfig, path string, query url.Values) (*http.Response, error) {
	target, err := url.Parse(strings.TrimRight(item.URL, "/") + path)
	if err != nil {
		return nil, err
	}
	target.RawQuery = query.Encode()
	client := safeHTTPClient()
	if item.CACert != "" {
		pem, err := os.ReadFile(item.CACert)
		if err != nil {
			return nil, err
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	if key != "" {
		request.Header.Set("X-Agent-Key", key)
	}
	return client.Do(request)
}

func notificationText(host string, event map[string]any) string {
	kind := stringValue(event["type"])
	if kind == "docker" && (stringValue(event["action"]) == "start" || stringValue(event["action"]) == "die") {
		action := stringValue(event["action"])
		code := stringValue(event["exit_code"])
		if code == "" && event["exit_code"] != nil {
			code = fmt.Sprint(event["exit_code"])
		}
		exitDescriptions := map[string]string{"0": "Successful shutdown", "143": "Graceful termination (SIGTERM)",
			"1": "Application error", "2": "Misuse of shell builtins", "126": "Command cannot execute",
			"127": "File or directory not found", "128": "Invalid argument", "130": "Container terminated by user",
			"134": "Abnormal termination (SIGABRT)", "137": "Immediate termination (SIGKILL)",
			"139": "Segmentation fault", "255": "Unknown error"}
		name := orDefault(stringValue(event["name"]), "Unknown")
		image := orDefault(stringValue(event["image"]), "Nicht verfügbar")
		symbol, status := "🟢", "started"
		if action == "die" {
			symbol, status = "❌", "stopped!"
			if code == "0" || code == "143" {
				symbol = "⛵"
			}
		}
		message := fmt.Sprintf("%s %s %s\n🖥 Host: %s\nImage: %s", symbol, name, status, host, image)
		if action == "die" {
			description := exitDescriptions[code]
			if description != "" {
				description += ": "
			}
			message += fmt.Sprintf("\n%sExit code %s", description, orDefault(code, "Nicht verfügbar"))
		}
		return message
	}
	if (kind != "ssh_login" && kind != "ssh_logout") || event["user"] == nil {
		return host + ": " + stringValue(event["message"])
	}
	action := "🔓 SSH-Login"
	if kind == "ssh_logout" {
		action = "🔐 SSH-Logout"
	}
	timestamp := time.Unix(int64(floatValue(event["timestamp"], 0)), 0).In(time.Local).Format("02.01.2006 15:04:05 -0700")
	return fmt.Sprintf("%s\n🖥 Host: %s\n👤 Benutzer: %s\n🌐 IP-Adresse: %s\n⏰ Zeit: %s",
		action, host, orDefault(fmt.Sprint(event["user"]), "Nicht verfügbar"),
		orDefault(stringValue(event["remote_ip"]), "Nicht verfügbar"), timestamp)
}
