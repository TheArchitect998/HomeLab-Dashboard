package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (d *dashboard) startBackground(ctx context.Context) {
	for _, worker := range []func(context.Context){d.historyLoop, d.notificationLoop, d.monitoringLoop, d.checksLoop} {
		d.background.Add(1)
		go func(worker func(context.Context)) {
			defer d.background.Done()
			worker(ctx)
		}(worker)
	}
}

func (d *dashboard) historyLoop(ctx context.Context) {
	for {
		if err := d.collectHistory(ctx, time.Now()); err != nil {
			log.Printf("History collection failed: %v", err)
		}
		delay := time.Minute - time.Duration(time.Now().UnixNano()%int64(time.Minute))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (d *dashboard) checksLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := d.evaluateChecks(ctx, time.Now().Unix()); err != nil {
			log.Printf("Reachability checks failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *dashboard) evaluateChecks(ctx context.Context, now int64) error {
	settings, err := d.store.readSettings()
	if err != nil {
		return err
	}
	checks, _ := settings["checks"].([]any)
	normalized := make([]map[string]any, 0, len(checks))
	known := map[string]bool{}
	for _, raw := range checks {
		check, ok := raw.(map[string]any)
		if ok {
			normalized = append(normalized, check)
			known[stringValue(check["name"])] = true
		}
	}
	d.mu.Lock()
	for name := range d.checkStatus {
		if !known[name] {
			delete(d.checkStatus, name)
			delete(d.checkFailures, name)
		}
	}
	d.mu.Unlock()
	providers := enabledProviders(settings)
	results := make([]struct {
		ok      bool
		latency any
		err     any
	}, len(normalized))
	var workers sync.WaitGroup
	for index, check := range normalized {
		workers.Add(1)
		go func(index int, check map[string]any) {
			defer workers.Done()
			results[index].ok, results[index].latency, results[index].err = d.runCheck(check)
		}(index, check)
	}
	workers.Wait()
	for index, check := range normalized {
		name := stringValue(check["name"])
		d.mu.Lock()
		if results[index].ok {
			d.checkFailures[name] = 0
		} else {
			d.checkFailures[name]++
		}
		down := d.checkFailures[name] >= 2
		d.checkStatus[name] = map[string]any{"ok": results[index].ok, "down": down,
			"latency_ms": results[index].latency, "error": results[index].err, "checked_at": now}
		d.mu.Unlock()
		if !boolValue(check["notify"]) || len(providers) == 0 {
			continue
		}
		for provider, providerSettings := range providers {
			if d.deliveryPaused(provider, providerSettings) {
				continue
			}
			var previous sql.NullInt64
			err := d.store.monitorDB.QueryRow(`SELECT down FROM provider_checks WHERE name=? AND provider=?`,
				name, provider).Scan(&previous)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if (previous.Valid && (previous.Int64 != 0) == down) || (!previous.Valid && !down) {
				continue
			}
			message := fmt.Sprintf("🟢 Check wieder erreichbar: %s", name)
			if down {
				message = fmt.Sprintf("🔴 Check ausgefallen: %s (%s %s)\n%v", name,
					stringValue(check["type"]), stringValue(check["target"]), results[index].err)
			}
			if err := d.sendNotification(ctx, provider, providerSettings, strings.TrimSpace(message)); err != nil {
				log.Printf("Check notification failed for %s (%s): %s", name, provider, notificationError(err))
				continue
			}
			if _, err := d.store.monitorDB.Exec(`INSERT OR REPLACE INTO provider_checks VALUES (?, ?, ?)`, name, provider, down); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *dashboard) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if err := d.monitorOnce(ctx, time.Now()); err != nil {
			log.Printf("Monitoring failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *dashboard) monitorOnce(ctx context.Context, now time.Time) error {
	settings, err := d.store.readSettings()
	if err != nil {
		return err
	}
	monitoring := objectAt(settings, "monitoring")
	activeProviders := enabledProviders(settings)
	active := len(activeProviders) > 0 && (boolValue(monitoring["temperature_enabled"]) ||
		boolValue(monitoring["hardware_enabled"]) || boolValue(monitoring["daily_report"]))
	if !active {
		return nil
	}
	unix := now.Unix()
	if boolValue(monitoring["daily_report"]) {
		if err := d.collectReportEvents(ctx, unix, numberValue(monitoring["report_started_at"])); err != nil {
			log.Printf("Report event collection failed: %v", err)
		}
	}
	if !boolValue(monitoring["temperature_enabled"]) {
		if _, err := d.store.monitorDB.Exec(`DELETE FROM provider_temperatures`); err != nil {
			return err
		}
	}
	if boolValue(monitoring["hardware_enabled"]) {
		if err := d.collectHardwareAlerts(ctx, monitoring, activeProviders, now); err != nil {
			log.Printf("Hardware monitoring failed: %v", err)
		}
	} else if _, err := d.store.monitorDB.Exec(`DELETE FROM provider_hardware`); err != nil {
		return err
	}
	if err := d.collectTemperatures(ctx, monitoring, activeProviders, now); err != nil {
		log.Printf("Temperature monitoring failed: %v", err)
	}
	if boolValue(monitoring["daily_report"]) {
		if err := d.sendDailyReports(ctx, activeProviders, now, orDefault(stringValue(monitoring["daily_report_time"]), "12:00")); err != nil {
			log.Printf("Daily report failed: %v", err)
		}
	}
	_, err = d.store.monitorDB.Exec(`DELETE FROM samples WHERE time < ?`, unix-90_000)
	if err != nil {
		return err
	}
	_, err = d.store.monitorDB.Exec(`DELETE FROM events WHERE time < ?`, unix-90_000)
	if err != nil {
		return err
	}
	cutoffDay := now.AddDate(0, 0, -31).Format("2006-01-02")
	_, err = d.store.monitorDB.Exec(`DELETE FROM provider_reports WHERE day < ?`, cutoffDay)
	if err != nil {
		return err
	}
	_, err = d.store.monitorDB.Exec(`DELETE FROM reports WHERE day < ?`, cutoffDay)
	return err
}

func (d *dashboard) collectReportEvents(ctx context.Context, now int64, reportStartedAt float64) error {
	for name, item := range d.agents {
		for _, kind := range []string{"ssh_login", "ssh_logout", "docker"} {
			var started, until int64
			err := d.store.monitorDB.QueryRow(`SELECT started, until_time FROM cursors WHERE host=? AND kind=?`,
				name, kind).Scan(&started, &until)
			if errors.Is(err, sql.ErrNoRows) {
				if _, err := d.store.monitorDB.Exec(`INSERT INTO cursors VALUES (?, ?, ?, ?)`, name, kind, now, now); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if float64(until) < reportStartedAt {
				started, until = int64(reportStartedAt), int64(reportStartedAt)
				if _, err := d.store.monitorDB.Exec(`UPDATE cursors SET started=?, until_time=? WHERE host=? AND kind=?`,
					started, until, name, kind); err != nil {
					return err
				}
			}
			if until >= now {
				continue
			}
			query := url.Values{"since": {strconv.FormatInt(until, 10)}, "until": {strconv.FormatInt(now, 10)},
				"types": {kind}, "details": {"false"}}
			response, err := d.agentRequestWithQuery(ctx, item, "/api/events", query)
			if err != nil {
				log.Printf("Report collection failed for %s (%s): %s", name, kind, notificationError(err))
				continue
			}
			var payload struct {
				Events *[]map[string]any `json:"events"`
			}
			if response.StatusCode < 200 || response.StatusCode >= 300 ||
				json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&payload) != nil || payload.Events == nil {
				response.Body.Close()
				log.Printf("Report collection failed for %s (%s): invalid agent response", name, kind)
				continue
			}
			response.Body.Close()
			events := *payload.Events
			tx, err := d.store.monitorDB.Begin()
			if err != nil {
				return err
			}
			valid := true
			for _, event := range events {
				timestamp := floatValue(event["timestamp"], math.NaN())
				if stringValue(event["type"]) != kind || math.IsNaN(timestamp) || timestamp < float64(until) || timestamp >= float64(now) {
					valid = false
					break
				}
				encoded, err := json.Marshal([]any{name, event})
				if err != nil {
					valid = false
					break
				}
				digest := sha256.Sum256(encoded)
				if _, err := tx.Exec(`INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?)`, name, kind, timestamp, hex.EncodeToString(digest[:])); err != nil {
					valid = false
					break
				}
			}
			if !valid {
				tx.Rollback()
				continue
			}
			if _, err := tx.Exec(`UPDATE cursors SET until_time=?, started=CASE WHEN ?>120 THEN ? ELSE started END WHERE host=? AND kind=?`,
				now, now-until, now, name, kind); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *dashboard) collectTemperatures(ctx context.Context, monitoring map[string]any, activeProviders map[string]map[string]any, now time.Time) error {
	thresholds := objectAt(monitoring, "thresholds")
	for name, item := range d.agents {
		var sampleTime, temperature float64
		err := d.store.monitorDB.QueryRow(`SELECT time, temperature FROM samples WHERE host=? ORDER BY time DESC LIMIT 1`, name).
			Scan(&sampleTime, &temperature)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && now.Sub(time.Unix(int64(sampleTime), 0)) >= 5*time.Minute) {
			data, fetchErr := d.fetchMetrics(ctx, item)
			if fetchErr != nil {
				log.Printf("Temperature monitoring failed for %s: %s", name, notificationError(fetchErr))
				continue
			}
			value, ok := finiteNumber(data["temperature_c"])
			if !ok {
				log.Printf("Temperature monitoring failed for %s: temperature unavailable", name)
				continue
			}
			temperature, sampleTime = value, float64(now.Unix())
			if _, err := d.store.monitorDB.Exec(`INSERT INTO samples VALUES (?, ?, ?)`, name, sampleTime, temperature); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if !boolValue(monitoring["temperature_enabled"]) {
			continue
		}
		threshold := floatValue(thresholds[name], 45)
		above := temperature > threshold
		for provider, providerSettings := range activeProviders {
			if d.deliveryPaused(provider, providerSettings) {
				continue
			}
			var oldAbove int
			var lastSent float64
			err := d.store.monitorDB.QueryRow(`SELECT above, last_sent FROM provider_temperatures WHERE host=? AND provider=?`,
				name, provider).Scan(&oldAbove, &lastSent)
			hasState := err == nil
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if hasState && lastSent < math.Max(numberValue(monitoring["temperature_started_at"]), numberValue(providerSettings["enabled_at"])) {
				hasState = false
			}
			message := ""
			switch {
			case above && (!hasState || oldAbove == 0):
				message = fmt.Sprintf("⚠️ Warnung: Temperatur des %s überschritten!\nAktuell: %.1f°C (Schwelle: %g°C)", name, temperature, threshold)
			case above && now.Sub(time.Unix(int64(lastSent), 0)) >= 5*time.Minute:
				message = fmt.Sprintf("🌡️ Aktuelle Temperatur des %s: %.1f°C (Schwelle: %g°C)", name, temperature, threshold)
			case !above && hasState && oldAbove != 0:
				message = fmt.Sprintf("✅ Temperatur des %s wieder normal.\nAktuell: %.1f°C (Schwelle: %g°C)", name, temperature, threshold)
			}
			if message == "" {
				continue
			}
			if err := d.sendNotification(ctx, provider, providerSettings, message); err != nil {
				log.Printf("Temperature notification failed for %s (%s): %s", name, provider, notificationError(err))
				continue
			}
			_, err = d.store.monitorDB.Exec(`INSERT OR REPLACE INTO provider_temperatures VALUES (?, ?, ?, ?)`,
				name, provider, above, now.Unix())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *dashboard) collectHardwareAlerts(ctx context.Context, monitoring map[string]any, activeProviders map[string]map[string]any, now time.Time) error {
	for name, item := range d.agents {
		d.mu.Lock()
		last := d.hardwareCheck[name]
		if now.Sub(last) < 5*time.Minute {
			d.mu.Unlock()
			continue
		}
		d.mu.Unlock()
		data, err := d.fetchMetrics(ctx, item)
		if err != nil {
			log.Printf("Hardware monitoring failed for %s: %s", name, notificationError(err))
			continue
		}
		issues := hardwareIssues(data)
		d.mu.Lock()
		d.hardwareCheck[name] = now
		d.mu.Unlock()
		if issues == nil {
			continue
		}
		for provider, providerSettings := range activeProviders {
			if d.deliveryPaused(provider, providerSettings) {
				continue
			}
			var saved string
			var lastSent float64
			err := d.store.monitorDB.QueryRow(`SELECT issues, last_sent FROM provider_hardware WHERE host=? AND provider=?`,
				name, provider).Scan(&saved, &lastSent)
			hasState := err == nil
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if hasState && lastSent < math.Max(numberValue(monitoring["hardware_started_at"]), numberValue(providerSettings["enabled_at"])) {
				hasState = false
			}
			known := []string{}
			if hasState {
				if err := json.Unmarshal([]byte(saved), &known); err != nil {
					return fmt.Errorf("invalid stored hardware alert state: %w", err)
				}
			}
			if equalStrings(issues, known) {
				continue
			}
			message := "✅ Hardware-Warnungen für " + name + " behoben."
			if len(issues) > 0 {
				lines := make([]string, len(issues))
				for index, issue := range issues {
					lines[index] = "• " + issue
				}
				message = "⚠️ Hardware-Warnung für " + name + ":\n" + strings.Join(lines, "\n")
			}
			if err := d.sendNotification(ctx, provider, providerSettings, message); err != nil {
				log.Printf("Hardware notification failed for %s (%s): %s", name, provider, notificationError(err))
				continue
			}
			encoded, _ := json.Marshal(issues)
			if _, err := d.store.monitorDB.Exec(`INSERT OR REPLACE INTO provider_hardware VALUES (?, ?, ?, ?)`,
				name, provider, string(encoded), now.Unix()); err != nil {
				return err
			}
		}
	}
	return nil
}

func hardwareIssues(data map[string]any) []string {
	issues := []string{}
	reported := false
	smart := objectAt(data, "smart")
	if boolValue(smart["available"]) {
		reported = true
		if disks, ok := smart["disks"].([]any); ok {
			for _, value := range disks {
				disk, ok := value.(map[string]any)
				if !ok || !boolValue(disk["available"]) {
					continue
				}
				device := stringValue(disk["device"])
				model := orDefault(stringValue(disk["model"]), "?")
				problems, _ := disk["problems"].([]any)
				for _, problem := range problems {
					issues = append(issues, fmt.Sprintf("S.M.A.R.T. %s (%s): %s", device, model, problem))
				}
			}
		}
	}
	zfs := objectAt(data, "zfs")
	if boolValue(zfs["available"]) {
		reported = true
		if pools, ok := zfs["pools"].([]any); ok {
			for _, value := range pools {
				pool, ok := value.(map[string]any)
				if ok && stringValue(pool["health"]) != "ONLINE" {
					issues = append(issues, fmt.Sprintf("ZFS %s: %s", pool["name"], pool["health"]))
				}
			}
		}
	}
	if !reported {
		return nil
	}
	sort.Strings(issues)
	return issues
}

func (d *dashboard) sendDailyReports(ctx context.Context, activeProviders map[string]map[string]any, now time.Time, reportTime string) error {
	local := now.In(time.Local)
	parts := strings.Split(reportTime, ":")
	if len(parts) != 2 {
		return errors.New("invalid daily report time")
	}
	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	if local.Hour() < hour || local.Hour() == hour && local.Minute() < minute {
		return nil
	}
	day := local.Format("2006-01-02")
	for name := range d.agents {
		since := now.Unix() - 86400
		var average sql.NullFloat64
		var sampleCount int
		err := d.store.monitorDB.QueryRow(`SELECT AVG(temperature), COUNT(*) FROM samples WHERE host=? AND time>=? AND time<?`,
			name, since, now.Unix()).Scan(&average, &sampleCount)
		if err != nil {
			return err
		}
		temperature := "Nicht verfügbar"
		if average.Valid {
			temperature = fmt.Sprintf("%.1f°C", average.Float64)
		}
		lines := []string{fmt.Sprintf("%s:\n📊 Tägliche Zusammenfassung (letzte 24h):", name),
			fmt.Sprintf("Durchschnittstemperatur: %s (%d Messungen%s)", temperature, sampleCount,
				map[bool]string{true: ", unvollständig", false: ""}[sampleCount < 287])}
		for _, item := range []struct{ kind, label string }{
			{"ssh_login", "SSH-Logins"}, {"ssh_logout", "SSH-Logouts"}, {"docker", "Docker-Ereignisse"},
		} {
			var count int
			if err := d.store.monitorDB.QueryRow(`SELECT COUNT(*) FROM events WHERE host=? AND kind=? AND time>=? AND time<?`,
				name, item.kind, since, now.Unix()).Scan(&count); err != nil {
				return err
			}
			var started, until int64
			err := d.store.monitorDB.QueryRow(`SELECT started, until_time FROM cursors WHERE host=? AND kind=?`,
				name, item.kind).Scan(&started, &until)
			partial := err != nil || started > since || until < now.Unix()-30
			label := fmt.Sprintf("%s: %d", item.label, count)
			if partial {
				label += " (unvollständig)"
			}
			lines = append(lines, label)
		}
		message := strings.Join(lines, "\n")
		for provider, providerSettings := range activeProviders {
			if d.deliveryPaused(provider, providerSettings) {
				continue
			}
			var exists int
			err := d.store.monitorDB.QueryRow(`SELECT 1 FROM provider_reports WHERE host=? AND provider=? AND day=?`,
				name, provider, day).Scan(&exists)
			if err == nil {
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err := d.sendNotification(ctx, provider, providerSettings, message); err != nil {
				log.Printf("Daily report failed for %s (%s): %s", name, provider, notificationError(err))
				continue
			}
			if _, err := d.store.monitorDB.Exec(`INSERT INTO provider_reports VALUES (?, ?, ?)`, name, provider, day); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *dashboard) fetchMetrics(ctx context.Context, item agentConfig) (map[string]any, error) {
	response, err := d.agentRequest(ctx, item, "/api/metrics")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("agent returned HTTP %d", response.StatusCode)
	}
	data := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
