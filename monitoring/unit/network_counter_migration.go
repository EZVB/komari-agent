package monitoring

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari-agent/utils"
)

const networkCounterStateVersion = 1

// Keep the first upgrade from the legacy monthly sampler continuous. Once the
// host reboots, the backend can safely follow the kernel counters directly.
var defaultNetworkCounterAdjuster = &networkCounterAdjuster{
	statePath:  ".komari-network-counter.json",
	legacyPath: "net_static.json",
}

type networkCounterState struct {
	Version      int    `json:"version"`
	RawMode      bool   `json:"raw_mode"`
	BootID       string `json:"boot_id,omitempty"`
	FilterKey    string `json:"filter_key"`
	BaseRawUp    uint64 `json:"base_raw_up"`
	BaseRawDown  uint64 `json:"base_raw_down"`
	BaseReportUp uint64 `json:"base_report_up"`
	BaseReportDn uint64 `json:"base_report_down"`
}

type legacyNetworkCounterFile struct {
	Interfaces map[string][]legacyNetworkCounterSample `json:"interfaces"`
}

type legacyNetworkCounterSample struct {
	Timestamp uint64 `json:"timestamp"`
	Tx        uint64 `json:"tx"`
	Rx        uint64 `json:"rx"`
}

type networkCounterAdjuster struct {
	sync.Mutex
	initialized bool
	state       *networkCounterState
	statePath   string
	legacyPath  string
}

func adjustNetworkTotalsForLegacy(rawUp, rawDown uint64, includeNics, excludeNics map[string]struct{}) (uint64, uint64) {
	bootID := readBootID(procRoot())
	return defaultNetworkCounterAdjuster.apply(
		rawUp,
		rawDown,
		bootID,
		networkFilterKey(includeNics, excludeNics),
		flags.MonthRotate,
		time.Now(),
		includeNics,
		excludeNics,
	)
}

func (adjuster *networkCounterAdjuster) apply(
	rawUp, rawDown uint64,
	bootID, filterKey string,
	monthRotate int,
	now time.Time,
	includeNics, excludeNics map[string]struct{},
) (uint64, uint64) {
	adjuster.Lock()
	defer adjuster.Unlock()

	if !adjuster.initialized {
		adjuster.initialized = true
		state, err := loadNetworkCounterState(adjuster.statePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("failed to load network counter compatibility state: %v", err)
		}
		adjuster.state = state
	}

	if adjuster.state == nil {
		if monthRotate < 1 || monthRotate > 31 {
			return rawUp, rawDown
		}

		legacyUp, legacyDown, err := readLegacyNetworkTotals(
			adjuster.legacyPath,
			uint64(utils.GetLastResetDate(monthRotate, now).Unix()),
			includeNics,
			excludeNics,
		)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("failed to read legacy network counters: %v", err)
		}

		adjuster.state = &networkCounterState{
			Version:      networkCounterStateVersion,
			BootID:       bootID,
			FilterKey:    filterKey,
			BaseRawUp:    rawUp,
			BaseRawDown:  rawDown,
			BaseReportUp: legacyUp,
			BaseReportDn: legacyDown,
		}
		if err := saveNetworkCounterState(adjuster.statePath, adjuster.state); err != nil {
			log.Printf("failed to save network counter compatibility state: %v", err)
		}
		return legacyUp, legacyDown
	}

	state := adjuster.state
	if state.Version != networkCounterStateVersion {
		adjuster.state = &networkCounterState{
			Version:   networkCounterStateVersion,
			RawMode:   true,
			BootID:    bootID,
			FilterKey: filterKey,
		}
		if err := saveNetworkCounterState(adjuster.statePath, adjuster.state); err != nil {
			log.Printf("failed to replace incompatible network counter state: %v", err)
		}
		return rawUp, rawDown
	}
	if state.RawMode {
		return rawUp, rawDown
	}

	bootChanged := state.BootID != "" && bootID != "" && state.BootID != bootID
	if bootChanged {
		state.RawMode = true
		state.BootID = bootID
		state.FilterKey = filterKey
		if err := saveNetworkCounterState(adjuster.statePath, state); err != nil {
			log.Printf("failed to update network counter compatibility state: %v", err)
		}
		return rawUp, rawDown
	}

	filterChanged := state.FilterKey != filterKey
	upReset := rawUp < state.BaseRawUp
	downReset := rawDown < state.BaseRawDown
	if filterChanged || upReset || downReset {
		// Preserve the last reported total when the interface set changes. For a
		// one-direction rollback, the unaffected direction may still book its
		// normal delta. This mirrors the persistent per-direction baseline used
		// by miaomiaowuX without exposing a raw-counter jump to the backend.
		reportUp := state.BaseReportUp
		reportDown := state.BaseReportDn
		if !filterChanged && !upReset {
			reportUp += safeCounterDelta(rawUp, state.BaseRawUp)
		}
		if !filterChanged && !downReset {
			reportDown += safeCounterDelta(rawDown, state.BaseRawDown)
		}

		state.BootID = bootID
		state.FilterKey = filterKey
		state.BaseRawUp = rawUp
		state.BaseRawDown = rawDown
		state.BaseReportUp = reportUp
		state.BaseReportDn = reportDown
		if err := saveNetworkCounterState(adjuster.statePath, state); err != nil {
			log.Printf("failed to rebase network counter compatibility state: %v", err)
		}
		return reportUp, reportDown
	}

	reportUp := state.BaseReportUp + safeCounterDelta(rawUp, state.BaseRawUp)
	reportDown := state.BaseReportDn + safeCounterDelta(rawDown, state.BaseRawDown)
	// Keep the in-memory baseline at the last emitted sample. The persisted
	// baseline only needs updating when a reset/filter transition occurs; this
	// avoids writing the state file on every report.
	state.BaseRawUp = rawUp
	state.BaseRawDown = rawDown
	state.BaseReportUp = reportUp
	state.BaseReportDn = reportDown
	return reportUp, reportDown
}

func networkFilterKey(includeNics, excludeNics map[string]struct{}) string {
	return strings.Join(sortedSetKeys(includeNics), ",") + "|" + strings.Join(sortedSetKeys(excludeNics), ",")
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func readBootID(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func loadNetworkCounterState(path string) (*networkCounterState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var state networkCounterState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveNetworkCounterState(path string, state *networkCounterState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}

	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			_ = os.Remove(temporaryPath)
			return err
		}
		if retryErr := os.Rename(temporaryPath, path); retryErr != nil {
			_ = os.Remove(temporaryPath)
			return retryErr
		}
	}
	return nil
}

func readLegacyNetworkTotals(
	path string,
	start uint64,
	includeNics, excludeNics map[string]struct{},
) (totalUp, totalDown uint64, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}

	var legacy legacyNetworkCounterFile
	if err := json.Unmarshal(data, &legacy); err != nil {
		return 0, 0, err
	}

	for name, samples := range legacy.Interfaces {
		if !shouldInclude(name, includeNics, excludeNics) {
			continue
		}
		for _, sample := range samples {
			if sample.Timestamp < start {
				continue
			}
			totalUp += sample.Tx
			totalDown += sample.Rx
		}
	}
	return totalUp, totalDown, nil
}
