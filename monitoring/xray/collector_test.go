package xray

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEndpoint(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:11111":               "http://127.0.0.1:11111/debug/vars",
		":11111":                        "http://127.0.0.1:11111/debug/vars",
		"0.0.0.0:11111":                 "http://127.0.0.1:11111/debug/vars",
		"http://localhost:11111/custom": "http://localhost:11111/custom",
	}
	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			actual, err := normalizeEndpoint(input)
			if err != nil {
				t.Fatalf("normalizeEndpoint failed: %v", err)
			}
			if actual != expected {
				t.Fatalf("expected %q, got %q", expected, actual)
			}
		})
	}
}

func TestResolveEndpointFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"metrics":{"tag":"metrics","listen":"0.0.0.0:38889"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolveEndpoint(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("resolveEndpoint failed: %v", err)
	}
	if endpoint != "http://127.0.0.1:38889/debug/vars" {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
}

func TestResolveEndpointFromConfigDirectorySkipsUnrelatedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00-routing.json"), []byte(`{"routing":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10-metrics.json"), []byte(`{"metrics":{"listen":":38889"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolveEndpoint(Options{ConfigPath: dir})
	if err != nil {
		t.Fatalf("resolveEndpoint failed: %v", err)
	}
	if endpoint != "http://127.0.0.1:38889/debug/vars" {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
}

func TestCollectSumsInboundOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/debug/vars" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
            "stats": {
                "inbound": {
                    "vless": {"uplink": 100, "downlink": 200},
                    "trojan": {"uplink": 30, "downlink": 40}
                },
                "outbound": {"direct": {"uplink": 130, "downlink": 240}},
                "user": {"user@example.com": {"uplink": 100, "downlink": 200}}
            }
        }`))
	}))
	defer server.Close()

	collector := NewCollector()
	collector.processBootTime = func(name string) (int64, error) {
		if name != "xray" {
			t.Fatalf("unexpected process name: %s", name)
		}
		return 12345, nil
	}
	traffic, err := collector.Collect(context.Background(), Options{MetricsEndpoint: server.URL})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if traffic.TotalUp != 130 || traffic.TotalDown != 240 || traffic.BootTime != 12345 {
		t.Fatalf("unexpected traffic: %+v", traffic)
	}
}

func TestCollectBacksOffAfterFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	collector := NewCollector()
	collector.now = func() time.Time { return now }
	_, err := collector.Collect(context.Background(), Options{MetricsEndpoint: "127.0.0.1:1"})
	if err == nil {
		t.Fatal("expected first request to fail")
	}
	_, err = collector.Collect(context.Background(), Options{MetricsEndpoint: "127.0.0.1:1"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable during backoff, got %v", err)
	}
}

func TestNormalizeEndpointRejectsMissingPort(t *testing.T) {
	_, err := normalizeEndpoint("http://localhost")
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected missing port error, got %v", err)
	}
}
