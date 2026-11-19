package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gonet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/sensors"
)

type agent struct {
	key           string
	containerMode bool
	mu            sync.Mutex
	cache         map[string]cachedValue
	ioSample      ioSnapshot
	containerNet  map[string]containerSnapshot
}

type cachedValue struct {
	at    time.Time
	value any
}

type ioSnapshot struct {
	at      time.Time
	disk    *disk.IOCountersStat
	network map[string]gonet.IOCountersStat
	rates   map[string]any
}

type containerSnapshot struct {
	at time.Time
	rx float64
	tx float64
}

type commandResult struct {
	Code int
	Text string
}

var (
	validCLIName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	validDevice     = regexp.MustCompile(`^/dev/[A-Za-z0-9/_-]+$`)
	validDeviceType = regexp.MustCompile(`^[A-Za-z0-9,]+$`)
	validBootID     = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
)

func newAgent() (*agent, error) {
	key := env("AGENT_KEY", "")
	if len(strings.TrimSpace(key)) < 16 || strings.TrimSpace(key) != key || key == "change-me" {
		return nil, errors.New("NODESENTINEL_AGENT_KEY is required: at least 16 characters, no surrounding whitespace, not the example value")
	}
	return &agent{
		key:           key,
		containerMode: env("AGENT_CONTAINER", "") == "1",
		cache:         make(map[string]cachedValue),
		containerNet:  make(map[string]containerSnapshot),
	}, nil
}

func (a *agent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", a.health)
	mux.HandleFunc("GET /api/metrics", a.metrics)
	mux.HandleFunc("GET /api/events", a.events)
	return securityHeaders(mux)
}

func (a *agent) authenticate(w http.ResponseWriter, r *http.Request) bool {
	provided := r.Header.Get("X-Agent-Key")
	if len(provided) != len(a.key) || subtle.ConstantTimeCompare([]byte(provided), []byte(a.key)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid agent key")
		return false
	}
	return true
}

func (a *agent) health(w http.ResponseWriter, r *http.Request) {
	if !a.authenticate(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *agent) metrics(w http.ResponseWriter, r *http.Request) {
	if !a.authenticate(w, r) {
		return
	}
	data, err := a.collectMetrics(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Metrics could not be collected")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (a *agent) collectMetrics(ctx context.Context) (map[string]any, error) {
	root := "/"
	procPath := "/"
	if a.containerMode {
		root, procPath = "/host/root", "/host/proc"
	}
	usage, err := disk.Usage(root)
	if err != nil {
		return nil, fmt.Errorf("disk usage: %w", err)
	}
	vm, _ := mem.VirtualMemory()
	swap, _ := mem.SwapMemory()
	cpuPercent, _ := cpu.Percent(200*time.Millisecond, false)
	info, _ := host.Info()
	uptime, _ := host.Uptime()
	temp := a.temperature()
	containers, dockerError := a.docker()
	rates := a.ioRates()
	dockerStats := any(unavailable("Docker is not available"))
	if dockerError == nil || len(containers) != 0 {
		dockerStats = a.cached("docker_stats", 30*time.Second, a.containerStats)
	}
	var ramPercent float64
	if vm != nil {
		ramPercent = vm.UsedPercent
	}
	cpuValue := 0.0
	if len(cpuPercent) > 0 {
		cpuValue = cpuPercent[0]
	}
	storagePercent := 0.0
	if usage.Total > 0 {
		storagePercent = math.Round(usage.UsedPercent*10) / 10
	}
	platform := ""
	if info != nil {
		platform = strings.TrimSpace(strings.Join([]string{info.Platform, info.PlatformVersion, info.KernelVersion}, " "))
	}
	return map[string]any{
		"host":               hostName(),
		"platform":           platform,
		"timestamp":          time.Now().UTC().Format(time.RFC3339Nano),
		"temperature_c":      temp,
		"cpu_percent":        cpuValue,
		"ram_percent":        ramPercent,
		"storage_percent":    storagePercent,
		"storage_free_bytes": usage.Free,
		"uptime_seconds":     uptimeFor(procPath, uptime),
		"ufw":                a.firewall(),
		"fail2ban":           a.fail2ban(),
		"docker":             containers,
		"docker_error":       errorString(dockerError),
		"docker_stats":       dockerStats,
		"swap_percent":       nullableFloat(swap),
		"disk_io":            rates["disk_io"],
		"network":            rates["network"],
		"smart":              a.cached("smart", 10*time.Minute, a.smart),
		"gpu":                a.cached("gpu", 30*time.Second, a.gpu),
		"zfs":                a.cached("zfs", 30*time.Second, a.zfs),
		"battery":            a.battery(),
	}, nil
}

func nullableFloat(value *mem.SwapMemoryStat) any {
	if value == nil || value.Total == 0 {
		return nil
	}
	return value.UsedPercent
}

func hostName() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}

func uptimeFor(procPath string, fallback uint64) uint64 {
	if content, err := os.ReadFile(filepath.Join(procPath, "uptime")); err == nil {
		fields := strings.Fields(string(content))
		if len(fields) > 0 {
			seconds, _ := strconv.ParseFloat(fields[0], 64)
			return uint64(seconds)
		}
	}
	return fallback
}

func (a *agent) temperature() any {
	temperatures, err := sensors.SensorsTemperatures()
	if err != nil {
		return nil
	}
	max := math.Inf(-1)
	for _, sensor := range temperatures {
		if sensor.Temperature > max && !math.IsNaN(sensor.Temperature) {
			max = sensor.Temperature
		}
	}
	if math.IsInf(max, -1) {
		return nil
	}
	return math.Round(max*10) / 10
}

func (a *agent) battery() map[string]any {
	base := "/sys/class/power_supply"
	entries, err := os.ReadDir(base)
	if a.containerMode {
		base = "/host/root/sys/class/power_supply"
		entries, err = os.ReadDir(base)
	}
	if err != nil {
		return unavailable("No battery found.")
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "BAT") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(base, entry.Name(), "capacity"))
		if err != nil {
			continue
		}
		percent, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err != nil {
			continue
		}
		state, _ := os.ReadFile(filepath.Join(base, entry.Name(), "status"))
		return map[string]any{"available": true, "percent": math.Round(percent*10) / 10,
			"charging": strings.EqualFold(strings.TrimSpace(string(state)), "charging")}
	}
	return unavailable("No battery found.")
}

func (a *agent) cached(key string, ttl time.Duration, producer func() any) any {
	a.mu.Lock()
	if cached, ok := a.cache[key]; ok && time.Since(cached.at) < ttl {
		a.mu.Unlock()
		return cached.value
	}
	a.mu.Unlock()
	value := safely(producer)
	a.mu.Lock()
	a.cache[key] = cachedValue{at: time.Now(), value: value}
	a.mu.Unlock()
	return value
}

func safely(producer func() any) (value any) {
	defer func() {
		if recovered := recover(); recovered != nil {
			value = unavailable(fmt.Sprintf("error: %v", recovered))
		}
	}()
	return producer()
}

func unavailable(reason string) map[string]any {
	return map[string]any{"available": false, "reason": reason}
}

func (a *agent) run(ctx context.Context, timeout time.Duration, name string, args ...string) commandResult {
	allowed := map[string]bool{
		"journalctl": true, "ufw": true, "fail2ban-client": true, "smartctl": true,
		"nvidia-smi": true, "zpool": true, "docker": true,
	}
	if !allowed[name] {
		return commandResult{Code: 1, Text: "unsupported command"}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return commandResult{Code: 1, Text: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	if a.containerMode && name == "journalctl" {
		journal := env("JOURNAL_DIR", "")
		if journal == "" {
			return commandResult{Code: 1, Text: "Host journal is not configured or accessible"}
		}
		entries, err := os.ReadDir(journal)
		if err != nil {
			return commandResult{Code: 1, Text: "Host journal is not accessible: " + err.Error()}
		}
		found := false
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".journal") || strings.HasSuffix(entry.Name(), ".journal~") {
				found = true
				break
			}
		}
		if !found {
			return commandResult{Code: 1, Text: "Host journal directory contains no journal files"}
		}
		cmd.Args = append([]string{"journalctl", "--directory=" + journal}, args...)
	}
	if a.containerMode && name == "fail2ban-client" {
		socket := env("FAIL2BAN_SOCKET", "/run/fail2ban/fail2ban.sock")
		cmd.Args = append([]string{"fail2ban-client", "-s", socket}, args...)
	}
	if !a.containerMode && (name == "ufw" || name == "fail2ban-client" || name == "smartctl") {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{"-n", path}, args...)...)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		code = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		if ctx.Err() != nil {
			return commandResult{Code: 1, Text: "command timed out"}
		}
	}
	return commandResult{Code: code, Text: strings.TrimSpace(string(out))}
}

func (a *agent) firewall() map[string]any {
	if a.containerMode && env("ENABLE_UFW", "") != "1" {
		return map[string]any{"active": nil, "raw": "UFW access is not enabled for this agent."}
	}
	result := a.run(context.Background(), 5*time.Second, "ufw", "status")
	re := regexp.MustCompile(`(?i)status:\s*(active|inactive)\b`)
	match := re.FindStringSubmatch(result.Text)
	if result.Code != 0 || len(match) == 0 {
		text := result.Text
		if text == "" {
			text = "UFW status could not be determined."
		}
		return map[string]any{"active": nil, "raw": text}
	}
	return map[string]any{"active": strings.EqualFold(match[1], "active"), "raw": result.Text}
}

func (a *agent) fail2ban() map[string]any {
	if a.containerMode && env("ENABLE_FAIL2BAN", "") != "1" {
		return map[string]any{"active": nil, "jails": []string{}, "details": map[string]string{},
			"raw": "Fail2Ban access is not enabled for this agent."}
	}
	result := a.run(context.Background(), 5*time.Second, "fail2ban-client", "status")
	if result.Code != 0 || !strings.Contains(strings.ToLower(result.Text), "jail list:") {
		text := result.Text
		if text == "" {
			text = "Fail2Ban status could not be determined."
		}
		return map[string]any{"active": nil, "jails": []string{}, "details": map[string]string{}, "raw": text}
	}
	jails := []string{}
	details := map[string]string{}
	for _, line := range strings.Split(result.Text, "\n") {
		if !strings.Contains(strings.ToLower(line), "jail list:") {
			continue
		}
		_, value, _ := strings.Cut(line, ":")
		for _, jail := range strings.Split(value, ",") {
			jail = strings.TrimSpace(jail)
			if !validCLIName.MatchString(jail) {
				continue
			}
			jails = append(jails, jail)
			info := a.run(context.Background(), 5*time.Second, "fail2ban-client", "status", jail)
			details[jail] = info.Text
		}
	}
	return map[string]any{"active": true, "jails": jails, "details": details, "raw": result.Text}
}

func (a *agent) docker() ([]map[string]any, error) {
	result := a.run(context.Background(), 5*time.Second, "docker", "ps", "-a", "--format", "{{json .}}")
	if result.Code != 0 {
		return []map[string]any{}, errors.New(orDefault(result.Text, "Docker status could not be determined."))
	}
	var containers []map[string]any
	var failures []string
	scanner := bufio.NewScanner(strings.NewReader(result.Text))
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			failures = append(failures, "Invalid Docker response: "+err.Error())
			continue
		}
		name, _ := row["Names"].(string)
		if !validCLIName.MatchString(name) {
			failures = append(failures, fmt.Sprintf("Invalid Docker container name: %q", name))
			continue
		}
		inspect := a.run(context.Background(), 5*time.Second, "docker", "inspect", "--format", "{{json .State}}", "--", name)
		if inspect.Code != 0 {
			failures = append(failures, name+": "+orDefault(inspect.Text, "Docker inspect failed"))
		}
		state := map[string]any{}
		_ = json.Unmarshal([]byte(inspect.Text), &state)
		containers = append(containers, map[string]any{
			"name": name, "image": row["Image"], "status": row["Status"], "state": state["Status"],
			"started_at": state["StartedAt"], "restart_count": state["RestartCount"],
		})
	}
	if err := scanner.Err(); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return containers, errors.New(strings.Join(failures, "; "))
	}
	return containers, nil
}

func (a *agent) ioRates() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if !a.ioSample.at.IsZero() && now.Sub(a.ioSample.at) < time.Second && a.ioSample.rates != nil {
		return a.ioSample.rates
	}
	disks, _ := disk.IOCounters()
	network, _ := gonet.IOCounters(true)
	var currentDisk *disk.IOCountersStat
	var total disk.IOCountersStat
	for _, item := range disks {
		total.ReadBytes += item.ReadBytes
		total.WriteBytes += item.WriteBytes
	}
	currentDisk = &total
	currentNetwork := make(map[string]gonet.IOCountersStat, len(network))
	for _, item := range network {
		currentNetwork[item.Name] = item
	}
	previous := a.ioSample
	if previous.at.IsZero() {
		a.ioSample = ioSnapshot{at: now, disk: currentDisk, network: currentNetwork}
		time.Sleep(500 * time.Millisecond)
		now = time.Now()
		disks, _ = disk.IOCounters()
		network, _ = gonet.IOCounters(true)
		total = disk.IOCountersStat{}
		for _, item := range disks {
			total.ReadBytes += item.ReadBytes
			total.WriteBytes += item.WriteBytes
		}
		currentDisk = &total
		currentNetwork = make(map[string]gonet.IOCountersStat, len(network))
		for _, item := range network {
			currentNetwork[item.Name] = item
		}
		previous = a.ioSample
	}
	elapsed := math.Max(now.Sub(previous.at).Seconds(), 0.001)
	var diskIO any
	if previous.disk != nil && currentDisk != nil {
		diskIO = map[string]float64{
			"read_bytes_per_s":  math.Max(0, float64(currentDisk.ReadBytes-previous.disk.ReadBytes)) / elapsed,
			"write_bytes_per_s": math.Max(0, float64(currentDisk.WriteBytes-previous.disk.WriteBytes)) / elapsed,
		}
	}
	interfaces := []map[string]any{}
	for name, current := range currentNetwork {
		old, ok := previous.network[name]
		if !ok || name == "lo" || strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
			continue
		}
		interfaces = append(interfaces, map[string]any{"name": name,
			"rx_bytes_per_s": math.Max(0, float64(current.BytesRecv-old.BytesRecv)) / elapsed,
			"tx_bytes_per_s": math.Max(0, float64(current.BytesSent-old.BytesSent)) / elapsed})
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i]["name"].(string) < interfaces[j]["name"].(string) })
	rates := map[string]any{"disk_io": diskIO, "network": interfaces}
	a.ioSample = ioSnapshot{at: now, disk: currentDisk, network: currentNetwork, rates: rates}
	return rates
}

func (a *agent) containerStats() any {
	raw := a.run(context.Background(), 6*time.Second, "docker", "stats", "--no-stream", "--format", "{{json .}}")
	if raw.Code != 0 {
		return unavailable(orDefault(raw.Text, "Docker statistics could not be determined."))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	containers := []map[string]any{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(raw.Text))
	for scanner.Scan() {
		var row map[string]any
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			continue
		}
		name, ok := row["Name"].(string)
		if !ok {
			continue
		}
		memUsed, memLimit := splitSlash(fmt.Sprint(row["MemUsage"]))
		rxText, txText := splitSlash(fmt.Sprint(row["NetIO"]))
		rx, rxOK := parseSize(rxText)
		tx, txOK := parseSize(txText)
		entry := map[string]any{
			"name": name, "cpu_percent": parsePercent(fmt.Sprint(row["CPUPerc"])),
			"ram_percent": parsePercent(fmt.Sprint(row["MemPerc"])),
			"ram_bytes":   parseSizeOrNil(memUsed), "ram_limit_bytes": parseSizeOrNil(memLimit),
			"net_rx_bytes_per_s": nil, "net_tx_bytes_per_s": nil,
		}
		old, exists := a.containerNet[name]
		if exists && rxOK && txOK && now.Sub(old.at) >= 5*time.Second && rx >= old.rx && tx >= old.tx {
			seconds := now.Sub(old.at).Seconds()
			entry["net_rx_bytes_per_s"] = (rx - old.rx) / seconds
			entry["net_tx_bytes_per_s"] = (tx - old.tx) / seconds
		}
		if rxOK && txOK && (!exists || now.Sub(old.at) >= 5*time.Second || rx < old.rx || tx < old.tx) {
			a.containerNet[name] = containerSnapshot{at: now, rx: rx, tx: tx}
		}
		seen[name] = true
		containers = append(containers, entry)
	}
	for name := range a.containerNet {
		if !seen[name] {
			delete(a.containerNet, name)
		}
	}
	return map[string]any{"available": true, "containers": containers}
}

func parseSize(text string) (float64, bool) {
	re := regexp.MustCompile(`^\s*([0-9.]+)\s*([A-Za-z]+)\s*$`)
	match := re.FindStringSubmatch(text)
	if len(match) != 3 {
		return 0, false
	}
	amount, err := strconv.ParseFloat(match[1], 64)
	factors := map[string]float64{"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
		"kib": 1024, "mib": 1024 * 1024, "gib": 1024 * 1024 * 1024,
		"tib": 1024 * 1024 * 1024 * 1024}
	factor, ok := factors[strings.ToLower(match[2])]
	if err != nil || !ok {
		return 0, false
	}
	return amount * factor, true
}

func parseSizeOrNil(text string) any {
	value, ok := parseSize(text)
	if !ok {
		return nil
	}
	return value
}

func parsePercent(text string) any {
	value, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(text), "%"), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return nil
	}
	return value
}

func splitSlash(value string) (string, string) {
	left, right, _ := strings.Cut(value, "/")
	return strings.TrimSpace(left), strings.TrimSpace(right)
}

func (a *agent) smart() any {
	if env("ENABLE_SMART", "") != "1" {
		return unavailable("S.M.A.R.T. access is not enabled for this agent.")
	}
	if _, err := exec.LookPath("smartctl"); err != nil {
		return unavailable("smartctl is not installed in this agent image.")
	}
	args := []string{"--scan", "-j"}
	scan := a.run(context.Background(), 15*time.Second, "smartctl", args...)
	var result map[string]any
	if json.Unmarshal([]byte(scan.Text), &result) != nil {
		return unavailable(truncate(orDefault(scan.Text, "smartctl scan failed"), 200))
	}
	devices, _ := result["devices"].([]any)
	if len(devices) == 0 {
		return unavailable("No S.M.A.R.T. capable devices found.")
	}
	disks := []map[string]any{}
	for _, entry := range devices {
		device, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name, _ := device["name"].(string)
		kind, _ := device["type"].(string)
		if !validDevice.MatchString(name) || (kind != "" && !validDeviceType.MatchString(kind)) {
			continue
		}
		cmdArgs := []string{"-j", "-H", "-A", "-n", "standby"}
		if kind != "" {
			cmdArgs = append(cmdArgs, "-d", kind)
		}
		cmdArgs = append(cmdArgs, name)
		raw := a.run(context.Background(), 15*time.Second, "smartctl", cmdArgs...)
		var info map[string]any
		if json.Unmarshal([]byte(raw.Text), &info) != nil {
			disks = append(disks, map[string]any{"device": name, "available": false,
				"reason": truncate(orDefault(raw.Text, "No smartctl output"), 200)})
			continue
		}
		smartctl, _ := info["smartctl"].(map[string]any)
		messages := []string{}
		if rows, ok := smartctl["messages"].([]any); ok {
			for _, row := range rows {
				message, _ := row.(map[string]any)
				if message["severity"] == "error" {
					messages = append(messages, fmt.Sprint(message["string"]))
				}
			}
		}
		status, _ := info["smart_status"].(map[string]any)
		passed, hasStatus := status["passed"].(bool)
		if !hasStatus {
			reason := strings.Join(messages, "; ")
			disks = append(disks, map[string]any{"device": name, "available": false,
				"reason": orDefault(reason, "SMART status unavailable")})
			continue
		}
		problems := []string{}
		if !passed {
			problems = append(problems, "SMART health check failed")
		}
		attributes := map[int]float64{}
		if ata, ok := info["ata_smart_attributes"].(map[string]any); ok {
			if rows, ok := ata["table"].([]any); ok {
				for _, item := range rows {
					row, _ := item.(map[string]any)
					id, _ := row["id"].(float64)
					raw, _ := row["raw"].(map[string]any)
					value, _ := raw["value"].(float64)
					attributes[int(id)] = value
				}
			}
		}
		for id, label := range map[int]string{5: "reallocated sectors", 197: "pending sectors", 198: "uncorrectable sectors"} {
			if attributes[id] > 0 {
				problems = append(problems, fmt.Sprintf("%g %s", attributes[id], label))
			}
		}
		nvme, _ := info["nvme_smart_health_information_log"].(map[string]any)
		if value, ok := nvme["critical_warning"].(float64); ok && value != 0 {
			problems = append(problems, "NVMe critical warning")
		}
		if value, ok := nvme["media_errors"].(float64); ok && value > 0 {
			problems = append(problems, fmt.Sprintf("%g media errors", value))
		}
		disks = append(disks, map[string]any{"device": name, "available": true,
			"model": info["model_name"], "passed": passed,
			"temperature_c":   nested(info, "temperature", "current"),
			"power_on_hours":  nested(info, "power_on_time", "hours"),
			"percentage_used": nvme["percentage_used"], "problems": problems})
	}
	return map[string]any{"available": true, "disks": disks}
}

func (a *agent) gpu() any {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return unavailable("No NVIDIA GPU tools found.")
	}
	result := a.run(context.Background(), 5*time.Second, "nvidia-smi",
		"--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
		"--format=csv,noheader,nounits")
	if result.Code != 0 {
		return unavailable(truncate(orDefault(result.Text, "nvidia-smi failed"), 200))
	}
	gpus := []map[string]any{}
	for _, line := range strings.Split(result.Text, "\n") {
		fields := strings.Split(line, ",")
		if len(fields) != 5 {
			continue
		}
		values := make([]any, 4)
		for i, field := range fields[1:] {
			values[i] = parsePercent(field)
		}
		gpus = append(gpus, map[string]any{"name": strings.TrimSpace(fields[0]),
			"utilization_percent": values[0], "memory_used_mib": values[1],
			"memory_total_mib": values[2], "temperature_c": values[3]})
	}
	if len(gpus) == 0 {
		return unavailable("No GPU reported.")
	}
	return map[string]any{"available": true, "gpus": gpus}
}

func (a *agent) zfs() any {
	if _, err := exec.LookPath("zpool"); err != nil {
		return unavailable("ZFS tools not found.")
	}
	result := a.run(context.Background(), 5*time.Second, "zpool", "list", "-H", "-p", "-o", "name,health,size,allocated")
	if result.Code != 0 {
		return unavailable(truncate(orDefault(result.Text, "zpool failed"), 200))
	}
	pools := []map[string]any{}
	for _, line := range strings.Split(result.Text, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			continue
		}
		size, err1 := strconv.ParseUint(parts[2], 10, 64)
		used, err2 := strconv.ParseUint(parts[3], 10, 64)
		if err1 != nil || err2 != nil || size == 0 {
			continue
		}
		pools = append(pools, map[string]any{"name": parts[0], "health": parts[1],
			"size_bytes": size, "used_percent": math.Round(float64(used)/float64(size)*1000) / 10})
	}
	if len(pools) == 0 {
		return unavailable("No ZFS pools found.")
	}
	return map[string]any{"available": true, "pools": pools}
}

func nested(data map[string]any, keys ...string) any {
	var value any = data
	for _, key := range keys {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[key]
	}
	return value
}

func (a *agent) events(w http.ResponseWriter, r *http.Request) {
	if !a.authenticate(w, r) {
		return
	}
	query := r.URL.Query()
	since, errSince := strconv.ParseInt(query.Get("since"), 10, 64)
	until, errUntil := strconv.ParseInt(query.Get("until"), 10, 64)
	types := query["types"]
	allowed := map[string]bool{"ssh_login": true, "ssh_logout": true, "fail2ban": true, "docker": true}
	if errSince != nil || errUntil != nil || since < 0 || until <= since {
		writeError(w, http.StatusBadRequest, "Invalid event query")
		return
	}
	for _, kind := range types {
		if !allowed[kind] {
			writeError(w, http.StatusBadRequest, "Invalid event query")
			return
		}
	}
	details := query.Get("details") != "false"
	found, err := a.collectEvents(r.Context(), since, until, types, details)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": found})
}

func (a *agent) collectEvents(ctx context.Context, since, until int64, types []string, details bool) ([]map[string]any, error) {
	want := map[string]bool{}
	for _, kind := range types {
		want[kind] = true
	}
	events := []map[string]any{}
	if want["ssh_login"] || want["ssh_logout"] || want["fail2ban"] {
		args := append(a.journalArgs(), "--no-pager", "-o", "json", "--since", fmt.Sprintf("@%d", since), "--until", fmt.Sprintf("@%d", until))
		result := a.run(ctx, 15*time.Second, args[0], args[1:]...)
		if result.Code != 0 {
			return nil, fmt.Errorf("Journal read failed: %s", result.Text)
		}
		scanner := bufio.NewScanner(strings.NewReader(result.Text))
		for scanner.Scan() {
			var row map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return nil, errors.New("Invalid journal entry")
			}
			micros, err := strconv.ParseInt(fmt.Sprint(row["__REALTIME_TIMESTAMP"]), 10, 64)
			if err != nil {
				return nil, errors.New("Invalid journal entry")
			}
			timestamp := float64(micros) / 1e6
			if timestamp < float64(since) || timestamp >= float64(until) {
				continue
			}
			message, _ := row["MESSAGE"].(string)
			identifier, _ := row["SYSLOG_IDENTIFIER"].(string)
			kind := ""
			if strings.HasPrefix(identifier, "sshd") || identifier == "ssh" {
				if strings.Contains(message, "session opened for user") {
					kind = "ssh_login"
				} else if strings.Contains(message, "session closed for user") {
					kind = "ssh_logout"
				}
			} else if strings.HasPrefix(identifier, "fail2ban") && regexp.MustCompile(`\]\s+(Ban|Unban)\s+`).MatchString(message) {
				kind = "fail2ban"
			}
			if !want[kind] || kind == "" {
				continue
			}
			event := map[string]any{"type": kind, "message": message, "timestamp": timestamp}
			if details && (kind == "ssh_login" || kind == "ssh_logout") {
				user, ip, detailErr := a.sshDetails(ctx, row, timestamp, kind, message)
				if detailErr != nil {
					return nil, detailErr
				}
				event["user"], event["remote_ip"] = user, ip
			}
			events = append(events, event)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if want["docker"] {
		result := a.run(ctx, 15*time.Second, "docker", "events", "--since", strconv.FormatInt(since, 10),
			"--until", strconv.FormatInt(until, 10), "--filter", "type=container", "--format", "{{json .}}")
		if result.Code != 0 {
			return nil, fmt.Errorf("Docker event read failed: %s", result.Text)
		}
		scanner := bufio.NewScanner(strings.NewReader(result.Text))
		for scanner.Scan() {
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				return nil, errors.New("Invalid Docker event")
			}
			nanos, err := strconv.ParseInt(fmt.Sprint(row["timeNano"]), 10, 64)
			action, _ := row["Action"].(string)
			actor, _ := row["Actor"].(map[string]any)
			attributes, _ := actor["Attributes"].(map[string]any)
			id, _ := row["id"].(string)
			name := fmt.Sprint(attributes["name"])
			if name == "<nil>" || name == "" {
				if len(id) > 12 {
					id = id[:12]
				}
				name = id
			}
			if err != nil {
				return nil, errors.New("Invalid Docker event")
			}
			ts := float64(nanos) / 1e9
			if ts < float64(since) || ts >= float64(until) || (action != "start" && action != "die") {
				continue
			}
			events = append(events, map[string]any{"type": "docker", "message": "Docker " + action + ": " + name,
				"timestamp": ts, "action": action, "name": name, "image": attributes["image"], "exit_code": attributes["exitCode"]})
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i]["timestamp"].(float64) < events[j]["timestamp"].(float64) })
	return events, nil
}

func (a *agent) journalArgs() []string {
	if !a.containerMode {
		return []string{"journalctl"}
	}
	dir := env("JOURNAL_DIR", "")
	if dir == "" {
		return []string{"journalctl"}
	}
	return []string{"journalctl", "--directory=" + dir}
}

func (a *agent) sshDetails(ctx context.Context, entry map[string]any, timestamp float64, kind, message string) (any, any, error) {
	sessionRe := regexp.MustCompile(`session (opened|closed) for user ([^\s(]+)`)
	match := sessionRe.FindStringSubmatch(message)
	if len(match) < 3 {
		return nil, nil, nil
	}
	user := match[2]
	pid, pidOK := entry["_PID"].(string)
	bootID, bootOK := entry["_BOOT_ID"].(string)
	if !pidOK || !regexp.MustCompile(`^\d+$`).MatchString(pid) || !bootOK || !validBootID.MatchString(bootID) {
		return user, nil, nil
	}
	args := append(a.journalArgs(), "--no-pager", "-o", "json", "_BOOT_ID="+bootID, "_PID="+pid,
		"--until", fmt.Sprintf("@%d", int64(timestamp)+1))
	result := a.run(ctx, 15*time.Second, args[0], args[1:]...)
	if result.Code != 0 {
		return nil, nil, fmt.Errorf("SSH journal read failed: %s", result.Text)
	}
	type record struct {
		at   float64
		text string
	}
	records := []record{}
	scanner := bufio.NewScanner(strings.NewReader(result.Text))
	for scanner.Scan() {
		var item map[string]any
		if json.Unmarshal(scanner.Bytes(), &item) != nil {
			return nil, nil, errors.New("Invalid SSH journal entry")
		}
		micros, err := strconv.ParseInt(fmt.Sprint(item["__REALTIME_TIMESTAMP"]), 10, 64)
		if err != nil {
			return nil, nil, errors.New("Invalid SSH journal entry")
		}
		text, _ := item["MESSAGE"].(string)
		at := float64(micros) / 1e6
		if at <= timestamp {
			records = append(records, record{at, text})
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].at < records[j].at })
	openedAt := timestamp
	if kind == "ssh_logout" {
		found := false
		for _, item := range records {
			if item.at >= timestamp {
				break
			}
			session := sessionRe.FindStringSubmatch(item.text)
			if len(session) > 0 {
				found = session[1] == "opened" && session[2] == user
				if found {
					openedAt = item.at
				}
			}
		}
		if !found {
			return user, nil, nil
		}
	}
	accepted := regexp.MustCompile(`\bAccepted \S+ for (\S+) from (\S+) port \d+`)
	for i := len(records) - 1; i >= 0; i-- {
		item := records[i]
		if item.at > openedAt || openedAt-item.at > 120 {
			continue
		}
		fields := accepted.FindStringSubmatch(item.text)
		if len(fields) < 3 || fields[1] != user {
			continue
		}
		address, err := netip.ParseAddr(fields[2])
		if err == nil {
			return user, address.String(), nil
		}
	}
	return user, nil, nil
}

func errorString(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

func env(key, fallback string) string {
	if value, ok := os.LookupEnv("NODESENTINEL_" + key); ok {
		return value
	}
	if value, ok := os.LookupEnv("HOMELAB_" + key); ok {
		return value
	}
	return fallback
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
