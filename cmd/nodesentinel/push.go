package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
)

const (
	pushMaxMessage    = 4 << 20
	pushTimeout       = 90 * time.Second
	pushMetricsMaxAge = 3 * time.Minute
)

type pushMessage struct {
	Type    string           `json:"type"`
	ID      uint64           `json:"id,omitempty"`
	Query   url.Values       `json:"query,omitempty"`
	Metrics map[string]any   `json:"metrics,omitempty"`
	Events  []map[string]any `json:"events"`
	Error   string           `json:"error,omitempty"`
}

type pushSession struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[uint64]chan pushMessage
	metrics map[string]any
	updated time.Time
	closed  chan struct{}
	nextID  atomic.Uint64
}

func validPushName(name string) bool {
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validPushKey(key string) bool {
	if len(key) < 16 || strings.TrimSpace(key) != key || key == "change-me" || key == "replace-with-a-unique-agent-key" {
		return false
	}
	for _, character := range key {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (s *pushSession) write(message pushMessage) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return s.conn.WriteJSON(message)
}

func (d *dashboard) connectAgent(w http.ResponseWriter, r *http.Request) {
	name := r.Header.Get("X-Agent-Name")
	item, ok := d.agents[name]
	key := r.Header.Get("X-Agent-Key")
	if !ok || item.Mode != "push" || len(item.Key) < 16 || len(key) != len(item.Key) ||
		subtle.ConstantTimeCompare([]byte(key), []byte(item.Key)) != 1 {
		writeError(w, http.StatusUnauthorized, "Invalid agent credentials")
		return
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Agent %s WebSocket upgrade failed: %v", name, err)
		return
	}
	session := &pushSession{conn: conn, pending: make(map[uint64]chan pushMessage), closed: make(chan struct{})}
	d.mu.Lock()
	old := d.pushAgents[name]
	d.pushAgents[name] = session
	d.mu.Unlock()
	if old != nil {
		old.conn.Close()
	}
	defer func() {
		conn.Close()
		close(session.closed)
		d.mu.Lock()
		if d.pushAgents[name] == session {
			delete(d.pushAgents, name)
		}
		d.mu.Unlock()
	}()
	conn.SetReadLimit(pushMaxMessage)
	if err := conn.SetReadDeadline(time.Now().Add(pushTimeout)); err != nil {
		log.Printf("Agent %s read deadline failed: %v", name, err)
		return
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pushTimeout))
	})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-session.closed:
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					conn.Close()
					return
				}
			}
		}
	}()
	for {
		var message pushMessage
		if err := conn.ReadJSON(&message); err != nil {
			return
		}
		switch message.Type {
		case "metrics":
			if message.Metrics == nil {
				log.Printf("Agent %s sent invalid metrics", name)
				return
			}
			session.mu.Lock()
			session.metrics, session.updated = message.Metrics, time.Now()
			session.mu.Unlock()
		case "events":
			session.mu.Lock()
			waiter := session.pending[message.ID]
			session.mu.Unlock()
			if waiter != nil {
				select {
				case waiter <- message:
				default:
				}
			}
		default:
			log.Printf("Agent %s sent an unknown message", name)
			return
		}
	}
}

func (d *dashboard) pushedMetrics(name string) (map[string]any, error) {
	d.mu.Lock()
	session := d.pushAgents[name]
	d.mu.Unlock()
	if session == nil {
		return nil, errors.New("Agent is disconnected")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.metrics == nil || time.Since(session.updated) > pushMetricsMaxAge {
		return nil, errors.New("Agent metrics are unavailable or stale")
	}
	result := make(map[string]any, len(session.metrics))
	for key, value := range session.metrics {
		result[key] = value
	}
	return result, nil
}

func (d *dashboard) closePushAgents() {
	d.mu.Lock()
	sessions := make([]*pushSession, 0, len(d.pushAgents))
	for _, session := range d.pushAgents {
		sessions = append(sessions, session)
	}
	d.mu.Unlock()
	for _, session := range sessions {
		if err := session.conn.Close(); err != nil {
			log.Printf("Closing agent connection failed: %v", err)
		}
	}
}

func (d *dashboard) requestPushEvents(ctx context.Context, name string, query url.Values) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	d.mu.Lock()
	session := d.pushAgents[name]
	d.mu.Unlock()
	if session == nil {
		return nil, errors.New("Agent is disconnected")
	}
	id := session.nextID.Add(1)
	waiter := make(chan pushMessage, 1)
	session.mu.Lock()
	session.pending[id] = waiter
	session.mu.Unlock()
	defer func() {
		session.mu.Lock()
		delete(session.pending, id)
		session.mu.Unlock()
	}()
	if err := session.write(pushMessage{Type: "events", ID: id, Query: query}); err != nil {
		session.conn.Close()
		return nil, fmt.Errorf("send event request: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-session.closed:
		return nil, errors.New("Agent disconnected while retrieving events")
	case message := <-waiter:
		if message.Error != "" {
			return nil, errors.New(message.Error)
		}
		if message.Events == nil {
			return nil, errors.New("Agent sent an invalid event response")
		}
		payload, err := json.Marshal(map[string]any{"events": message.Events})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(payload))}, nil
	}
}

func (a *agent) push(ctx context.Context) error {
	rawURL := strings.TrimSpace(env("HUB_URL", ""))
	target, err := url.Parse(rawURL)
	if err != nil || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" ||
		(target.Scheme != "wss" && target.Scheme != "ws") {
		return errors.New("NODESENTINEL_HUB_URL must be a ws:// or wss:// dashboard URL")
	}
	if target.Scheme == "ws" {
		host := target.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("unencrypted WebSocket connections are allowed only to loopback; use wss://")
		}
	}
	name := env("AGENT_NAME", "")
	if !validPushName(name) {
		return errors.New("NODESENTINEL_AGENT_NAME must identify the configured push agent")
	}
	if !validPushKey(a.key) {
		return errors.New("NODESENTINEL_AGENT_KEY is not valid for a push agent")
	}
	interval, err := strconv.Atoi(env("AGENT_PUSH_SECONDS", "15"))
	if err != nil || interval < 5 || interval > 60 {
		return errors.New("NODESENTINEL_AGENT_PUSH_SECONDS must be between 5 and 60")
	}
	target.Path = strings.TrimRight(target.Path, "/") + "/api/agent/connect"
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	if target.Scheme == "ws" && target.Hostname() == "localhost" {
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		}
	}
	if caPath := env("HUB_CA_CERT", ""); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("read dashboard CA certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("dashboard CA certificate contains no valid certificates")
		}
		dialer.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	header := http.Header{"X-Agent-Name": {name}, "X-Agent-Key": {a.key}}
	delay := time.Second
	for ctx.Err() == nil {
		conn, response, err := dialer.DialContext(ctx, target.String(), header)
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if err == nil {
			delay = time.Second
			log.Printf("Connected to dashboard as %s", name)
			err = a.pushConnection(ctx, conn, time.Duration(interval)*time.Second)
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("Dashboard connection failed: %v; retrying in %s", err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
	return nil
}

func (a *agent) pushConnection(parent context.Context, conn *websocket.Conn, interval time.Duration) error {
	ctx, cancel := context.WithCancel(parent)
	var active sync.WaitGroup
	defer func() {
		cancel()
		conn.Close()
		active.Wait()
	}()
	session := &pushSession{conn: conn}
	conn.SetReadLimit(pushMaxMessage)
	if err := conn.SetReadDeadline(time.Now().Add(pushTimeout)); err != nil {
		return err
	}
	conn.SetPingHandler(func(message string) error {
		if err := conn.SetReadDeadline(time.Now().Add(pushTimeout)); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(10*time.Second))
	})
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	active.Add(1)
	go func() {
		defer active.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			data, err := a.collectMetrics(ctx)
			if err != nil {
				log.Printf("Metrics collection failed: %v", err)
			} else if err := session.write(pushMessage{Type: "metrics", Metrics: data}); err != nil {
				log.Printf("Metrics push failed: %v", err)
				conn.Close()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	workers := make(chan struct{}, 8)
	for {
		var message pushMessage
		if err := conn.ReadJSON(&message); err != nil {
			return err
		}
		if message.Type != "events" || message.ID == 0 {
			return errors.New("invalid dashboard request")
		}
		select {
		case workers <- struct{}{}:
			active.Add(1)
			go func(message pushMessage) {
				defer active.Done()
				defer func() { <-workers }()
				requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()
				reply := pushMessage{Type: "events", ID: message.ID}
				since, until, types, details, err := parseEventQuery(message.Query)
				if err == nil {
					reply.Events, err = a.collectEvents(requestCtx, since, until, types, details)
				}
				if err != nil {
					reply.Error = err.Error()
				}
				if err := session.write(reply); err != nil {
					log.Printf("Event response failed: %v", err)
					conn.Close()
				}
			}(message)
		default:
			if err := session.write(pushMessage{Type: "events", ID: message.ID, Error: "Agent event collector is busy"}); err != nil {
				return err
			}
		}
	}
}
