package monitoring

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkCounterAdjusterMigratesLegacyTotals(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.json")
	legacyPath := filepath.Join(tempDir, "net_static.json")
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	legacyJSON := `{
  "interfaces": {
    "eth0": [
      {"timestamp": 1754006400, "tx": 10, "rx": 20},
      {"timestamp": 1786320000, "tx": 500, "rx": 700}
    ],
    "docker0": [
      {"timestamp": 1786320000, "tx": 9000, "rx": 9000}
    ]
  }
}`
	if err := os.WriteFile(legacyPath, []byte(legacyJSON), 0o600); err != nil {
		t.Fatalf("failed to write legacy counters: %v", err)
	}

	adjuster := &networkCounterAdjuster{statePath: statePath, legacyPath: legacyPath}
	up, down := adjuster.apply(10_000, 20_000, "boot-a", "|", 1, now, nil, nil)
	if up != 500 || down != 700 {
		t.Fatalf("expected legacy baseline up=500 down=700, got up=%d down=%d", up, down)
	}

	up, down = adjuster.apply(10_150, 20_200, "boot-a", "|", 1, now, nil, nil)
	if up != 650 || down != 900 {
		t.Fatalf("expected raw deltas on legacy baseline up=650 down=900, got up=%d down=%d", up, down)
	}

	restarted := &networkCounterAdjuster{statePath: statePath, legacyPath: legacyPath}
	up, down = restarted.apply(10_200, 20_250, "boot-a", "|", 1, now, nil, nil)
	if up != 700 || down != 950 {
		t.Fatalf("expected persisted migration after restart up=700 down=950, got up=%d down=%d", up, down)
	}
}

func TestNetworkCounterAdjusterSwitchesToRawAfterReboot(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.json")
	legacyPath := filepath.Join(tempDir, "net_static.json")
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	if err := os.WriteFile(legacyPath, []byte(`{"interfaces":{}}`), 0o600); err != nil {
		t.Fatalf("failed to write legacy counters: %v", err)
	}

	adjuster := &networkCounterAdjuster{statePath: statePath, legacyPath: legacyPath}
	adjuster.apply(10_000, 20_000, "boot-a", "|", 1, now, nil, nil)

	up, down := adjuster.apply(100, 200, "boot-b", "|", 1, now, nil, nil)
	if up != 100 || down != 200 {
		t.Fatalf("expected raw counters after reboot up=100 down=200, got up=%d down=%d", up, down)
	}

	restarted := &networkCounterAdjuster{statePath: statePath, legacyPath: legacyPath}
	up, down = restarted.apply(150, 260, "boot-b", "|", 1, now, nil, nil)
	if up != 150 || down != 260 {
		t.Fatalf("expected raw mode to persist after reboot, got up=%d down=%d", up, down)
	}
}

func TestNetworkCounterAdjusterStartsAtZeroWithoutLegacyFile(t *testing.T) {
	tempDir := t.TempDir()
	adjuster := &networkCounterAdjuster{
		statePath:  filepath.Join(tempDir, "state.json"),
		legacyPath: filepath.Join(tempDir, "missing.json"),
	}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)

	up, down := adjuster.apply(1000, 2000, "boot-a", "|", 1, now, nil, nil)
	if up != 0 || down != 0 {
		t.Fatalf("expected zero compatibility baseline, got up=%d down=%d", up, down)
	}

	up, down = adjuster.apply(1100, 2250, "boot-a", "|", 1, now, nil, nil)
	if up != 100 || down != 250 {
		t.Fatalf("expected deltas from zero baseline up=100 down=250, got up=%d down=%d", up, down)
	}
}

func TestNetworkCounterAdjusterLeavesRawCountersUnchangedByDefault(t *testing.T) {
	tempDir := t.TempDir()
	adjuster := &networkCounterAdjuster{
		statePath:  filepath.Join(tempDir, "state.json"),
		legacyPath: filepath.Join(tempDir, "missing.json"),
	}

	up, down := adjuster.apply(1000, 2000, "boot-a", "|", 0, time.Now(), nil, nil)
	if up != 1000 || down != 2000 {
		t.Fatalf("expected raw counters without legacy month rotation, got up=%d down=%d", up, down)
	}
}

func TestNetworkCounterAdjusterReplacesIncompatibleState(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.json")
	if err := os.WriteFile(statePath, []byte(`{"version":99,"base_raw_up":10,"base_raw_down":20}`), 0o600); err != nil {
		t.Fatalf("failed to write incompatible state: %v", err)
	}

	adjuster := &networkCounterAdjuster{
		statePath:  statePath,
		legacyPath: filepath.Join(tempDir, "missing.json"),
	}
	up, down := adjuster.apply(1000, 2000, "boot-a", "|", 1, time.Now(), nil, nil)
	if up != 1000 || down != 2000 {
		t.Fatalf("expected raw counters for incompatible state, got up=%d down=%d", up, down)
	}

	state, err := loadNetworkCounterState(statePath)
	if err != nil {
		t.Fatalf("failed to read replacement state: %v", err)
	}
	if state.Version != networkCounterStateVersion || !state.RawMode {
		t.Fatalf("expected persisted raw-mode replacement state, got %+v", state)
	}
}
