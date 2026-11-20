package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func main() {
	mode := "dashboard"
	args := os.Args[1:]
	if len(args) > 0 {
		mode, args = args[0], args[1:]
	}
	var err error
	switch mode {
	case "agent":
		if len(args) != 0 {
			err = errors.New("agent does not accept arguments")
		} else {
			err = runAgent()
		}
	case "dashboard":
		if len(args) == 1 && args[0] == "setup" {
			err = setupDashboardPassword()
		} else if len(args) != 0 {
			err = errors.New("usage: nodesentinel dashboard [setup]")
		} else {
			err = runDashboard()
		}
	default:
		err = errors.New("usage: nodesentinel [dashboard [setup]|agent]")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func runAgent() error {
	service, err := newAgent()
	if err != nil {
		return err
	}
	if env("HUB_URL", "") != "" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return service.push(ctx)
	}
	address := env("AGENT_BIND_ADDRESS", "0.0.0.0")
	port := env("AGENT_PORT", "9100")
	server := &http.Server{
		Addr:              netAddress(address, port),
		Handler:           service.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return serve(server, env("AGENT_TLS_CERTFILE", os.Getenv("UVICORN_SSL_CERTFILE")),
		env("AGENT_TLS_KEYFILE", os.Getenv("UVICORN_SSL_KEYFILE")))
}

func serve(server *http.Server, cert, key string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		log.Printf("NodeSentinel listening on %s", server.Addr)
		if cert != "" || key != "" {
			if cert == "" || key == "" {
				errCh <- errors.New("both TLS certificate and key must be configured")
				return
			}
			errCh <- server.ListenAndServeTLS(cert, key)
			return
		}
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func netAddress(host, port string) string {
	return net.JoinHostPort(strings.Trim(strings.TrimSpace(host), "[]"), port)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("response encoding failed: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"detail": message})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func setupDashboardPassword() error {
	cfg, err := readDashboardConfig()
	if err != nil {
		return err
	}
	store, err := openDashboardStoreAt(cfg.StateDir)
	if err != nil {
		return err
	}
	defer store.close()
	store.mu.Lock()
	defer store.mu.Unlock()
	settings, err := store.readSettings()
	if err != nil {
		return err
	}
	if _, exists := settings["password"]; exists {
		return errors.New("Password already configured; change it in the dashboard.")
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("New dashboard password (at least 12 characters): ")
	password, err := readPassword(reader)
	if err != nil {
		return err
	}
	fmt.Print("Repeat password: ")
	repeated, err := readPassword(reader)
	if err != nil {
		return err
	}
	if password != repeated {
		return errors.New("Passwords do not match.")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := passwordHash(password)
	if err != nil {
		return fmt.Errorf("secure dashboard password: %w", err)
	}
	settings["password"] = hash
	if err := store.writeSettings(settings); err != nil {
		return err
	}
	fmt.Printf("Password configured in %s/settings.json.\n", store.stateDir)
	return nil
}

func readPassword(reader *bufio.Reader) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return readLine(reader)
	}
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(value), err
}
