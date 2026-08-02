package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

var (
	ErrNotConfigured = errors.New("xray metrics are not configured")
	ErrUnavailable   = errors.New("xray metrics are temporarily unavailable")
)

const (
	discoveryInterval = 30 * time.Second
	retryInterval     = 10 * time.Second
	processInterval   = 5 * time.Second
	requestTimeout    = 1500 * time.Millisecond
	maxMetricsBody    = 8 << 20
)

var commonConfigPaths = []string{
	"/usr/local/etc/xray/config.json",
	"/usr/local/etc/xray",
	"/etc/xray/config.json",
	"/etc/xray",
}

type Options struct {
	MetricsEndpoint string
	ConfigPath      string
	ProcessName     string
}

type Traffic struct {
	TotalUp   int64
	TotalDown int64
	BootTime  int64
}

type trafficData struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

type metricsResponse struct {
	Stats *struct {
		Inbound  map[string]trafficData `json:"inbound"`
		Outbound map[string]trafficData `json:"outbound"`
		User     map[string]trafficData `json:"user"`
	} `json:"stats"`
}

type metricsConfig struct {
	Metrics *struct {
		Listen string `json:"listen"`
	} `json:"metrics"`
}

type Collector struct {
	mu              sync.Mutex
	httpClient      *http.Client
	endpoint        string
	optionsKey      string
	lastDiscovery   time.Time
	nextAttempt     time.Time
	bootTime        int64
	lastProcessName string
	lastProcessScan time.Time
	now             func() time.Time
	processBootTime func(string) (int64, error)
}

func NewCollector() *Collector {
	return &Collector{
		httpClient:      &http.Client{},
		now:             time.Now,
		processBootTime: findProcessBootTime,
	}
}

func (c *Collector) Collect(ctx context.Context, options Options) (*Traffic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	options = normalizeOptions(options)
	now := c.now()
	key := options.MetricsEndpoint + "\x00" + options.ConfigPath
	if key != c.optionsKey {
		c.optionsKey = key
		c.endpoint = ""
		c.lastDiscovery = time.Time{}
		c.nextAttempt = time.Time{}
	}
	if now.Before(c.nextAttempt) {
		return nil, ErrUnavailable
	}

	if c.lastDiscovery.IsZero() || now.Sub(c.lastDiscovery) >= discoveryInterval {
		endpoint, err := resolveEndpoint(options)
		c.lastDiscovery = now
		if err != nil {
			c.endpoint = ""
			return nil, err
		}
		c.endpoint = endpoint
	}
	if c.endpoint == "" {
		return nil, ErrNotConfigured
	}

	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create xray metrics request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.nextAttempt = now.Add(retryInterval)
		return nil, fmt.Errorf("read xray metrics: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.nextAttempt = now.Add(retryInterval)
		return nil, fmt.Errorf("read xray metrics: unexpected HTTP status %d", resp.StatusCode)
	}

	var metrics metricsResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxMetricsBody))
	if err := decoder.Decode(&metrics); err != nil {
		c.nextAttempt = now.Add(retryInterval)
		return nil, fmt.Errorf("decode xray metrics: %w", err)
	}
	if metrics.Stats == nil {
		c.nextAttempt = now.Add(retryInterval)
		return nil, errors.New("xray metrics response does not contain stats")
	}

	totalUp, totalDown, err := sumInboundTraffic(metrics.Stats.Inbound)
	if err != nil {
		return nil, err
	}
	c.nextAttempt = time.Time{}

	if options.ProcessName != c.lastProcessName || c.lastProcessScan.IsZero() || now.Sub(c.lastProcessScan) >= processInterval {
		bootTime, processErr := c.processBootTime(options.ProcessName)
		if processErr == nil {
			c.bootTime = bootTime
		}
		c.lastProcessName = options.ProcessName
		c.lastProcessScan = now
	}

	return &Traffic{TotalUp: totalUp, TotalDown: totalDown, BootTime: c.bootTime}, nil
}

func normalizeOptions(options Options) Options {
	options.MetricsEndpoint = strings.TrimSpace(options.MetricsEndpoint)
	options.ConfigPath = strings.TrimSpace(options.ConfigPath)
	options.ProcessName = strings.TrimSpace(options.ProcessName)
	if options.ProcessName == "" {
		options.ProcessName = "xray"
	}
	return options
}

func resolveEndpoint(options Options) (string, error) {
	if options.MetricsEndpoint != "" {
		return normalizeEndpoint(options.MetricsEndpoint)
	}

	paths, explicit, err := configPaths(options.ConfigPath)
	if err != nil {
		return "", err
	}
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			if explicit {
				return "", fmt.Errorf("read xray config %s: %w", path, readErr)
			}
			continue
		}
		var config metricsConfig
		if decodeErr := json.Unmarshal(data, &config); decodeErr != nil {
			if explicit {
				return "", fmt.Errorf("decode xray config %s: %w", path, decodeErr)
			}
			continue
		}
		if config.Metrics == nil || strings.TrimSpace(config.Metrics.Listen) == "" {
			continue
		}
		endpoint, endpointErr := normalizeEndpoint(config.Metrics.Listen)
		if endpointErr != nil {
			if explicit {
				return "", fmt.Errorf("invalid metrics.listen in %s: %w", path, endpointErr)
			}
			continue
		}
		return endpoint, nil
	}
	return "", ErrNotConfigured
}

func configPaths(configPath string) ([]string, bool, error) {
	if configPath != "" {
		info, err := os.Stat(configPath)
		if err != nil {
			return nil, false, err
		}
		paths, err := expandConfigPath(configPath)
		return paths, !info.IsDir(), err
	}

	seen := make(map[string]struct{})
	var paths []string
	for _, candidate := range commonConfigPaths {
		expanded, err := expandConfigPath(candidate)
		if err != nil {
			continue
		}
		for _, path := range expanded {
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			paths = append(paths, path)
		}
	}
	return paths, false, nil
}

func expandConfigPath(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	paths, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func normalizeEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrNotConfigured
	}
	if strings.HasPrefix(value, "unix:") {
		return "", errors.New("unix socket metrics endpoints are not supported")
	}
	if strings.HasPrefix(value, ":") {
		value = "127.0.0.1" + value
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", errors.New("metrics endpoint has no host")
	}
	hostname := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		return "", errors.New("metrics endpoint has no port")
	}
	if hostname == "0.0.0.0" || hostname == "::" || hostname == "[::]" {
		hostname = "127.0.0.1"
	}
	parsed.Host = net.JoinHostPort(hostname, port)
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/debug/vars"
	}
	return parsed.String(), nil
}

func sumInboundTraffic(inbound map[string]trafficData) (int64, int64, error) {
	var totalUp, totalDown int64
	for _, data := range inbound {
		if data.Uplink < 0 || data.Downlink < 0 {
			return 0, 0, errors.New("xray metrics contain a negative traffic counter")
		}
		if data.Uplink > math.MaxInt64-totalUp || data.Downlink > math.MaxInt64-totalDown {
			return 0, 0, errors.New("xray traffic counters exceed int64")
		}
		totalUp += data.Uplink
		totalDown += data.Downlink
	}
	return totalUp, totalDown, nil
}

func findProcessBootTime(processNames string) (int64, error) {
	targets := make(map[string]struct{})
	for _, name := range strings.FieldsFunc(processNames, func(r rune) bool { return r == ',' || r == ';' }) {
		name = normalizeProcessName(name)
		if name != "" {
			targets[name] = struct{}{}
		}
	}
	if len(targets) == 0 {
		targets["xray"] = struct{}{}
	}

	processes, err := process.Processes()
	if err != nil {
		return 0, err
	}
	var earliest int64
	for _, item := range processes {
		name, nameErr := item.Name()
		if nameErr != nil {
			continue
		}
		if _, ok := targets[normalizeProcessName(name)]; !ok {
			exe, exeErr := item.Exe()
			if exeErr != nil {
				continue
			}
			if _, ok = targets[normalizeProcessName(filepath.Base(exe))]; !ok {
				continue
			}
		}
		createdAt, createErr := item.CreateTime()
		if createErr != nil || createdAt <= 0 {
			continue
		}
		createdAt /= 1000
		if earliest == 0 || createdAt < earliest {
			earliest = createdAt
		}
	}
	return earliest, nil
}

func normalizeProcessName(name string) string {
	name = strings.ToLower(strings.TrimSpace(filepath.Base(name)))
	return strings.TrimSuffix(name, ".exe")
}
