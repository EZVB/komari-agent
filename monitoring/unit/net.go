package monitoring

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
)

func ConnectionsCount() (tcpCount, udpCount int, err error) {
	if runtime.GOOS == "linux" {
		return connectionsCountWithProcFallback(procRoot(), gopsutilConnectionsCount)
	}

	return gopsutilConnectionsCount()
}

func connectionsCountWithProcFallback(root string, fallback func() (int, int, error)) (tcpCount, udpCount int, err error) {
	var procErr error
	tcpCount, udpCount, procErr = procNetConnectionsCount(root)
	if procErr == nil {
		return tcpCount, udpCount, nil
	}

	tcpCount, udpCount, err = fallback()
	if err != nil && procErr != nil {
		return 0, 0, fmt.Errorf("proc net fast path failed: %w; gopsutil fallback failed: %w", procErr, err)
	}
	return tcpCount, udpCount, err
}

func gopsutilConnectionsCount() (tcpCount, udpCount int, err error) {
	tcps, err := net.Connections("tcp")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get TCP connections: %w", err)
	}
	udps, err := net.Connections("udp")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get UDP connections: %w", err)
	}

	return len(tcps), len(udps), nil
}

func procRoot() string {
	if flags.HostProc != "" {
		return flags.HostProc
	}
	return "/proc"
}

func procNetConnectionsCount(root string) (tcpCount, udpCount int, err error) {
	tcpCount, err = countProcNetFiles(root, "tcp", "tcp6")
	if err != nil {
		return 0, 0, err
	}
	udpCount, err = countProcNetFiles(root, "udp", "udp6")
	if err != nil {
		return 0, 0, err
	}
	return tcpCount, udpCount, nil
}

func countProcNetFiles(root string, names ...string) (int, error) {
	total := 0
	readAny := false
	for _, name := range names {
		count, err := countProcNetFile(filepath.Join(root, "net", name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, err
		}
		total += count
		readAny = true
	}
	if !readAny {
		return 0, fmt.Errorf("no proc net files found under %s", filepath.Join(root, "net"))
	}
	return total, nil
}

func countProcNetFile(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	header := true
	for scanner.Scan() {
		if header {
			header = false
			continue
		}
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count, scanner.Err()
}

var defaultExcludedNICPrefixes = map[string]struct{}{
	"br":        {},
	"calico":    {},
	"cni":       {},
	"docker":    {},
	"dummy":     {},
	"flannel":   {},
	"fwbr":      {},
	"fwpr":      {},
	"podman":    {},
	"tap":       {},
	"tailscale": {},
	"tun":       {},
	"tunl":      {},
	"veth":      {},
	"virbr":     {},
	"vmbr":      {},
	"vnet":      {},
	"wg":        {},
}

// VnstatInterface represents a network interface in vnstat output
type VnstatInterface struct {
	Name    string        `json:"name"`
	Alias   string        `json:"alias"`
	Created VnstatDate    `json:"created"`
	Updated VnstatUpdated `json:"updated"`
	Traffic VnstatTraffic `json:"traffic"`
}

// VnstatDate represents date information
type VnstatDate struct {
	Date      VnstatDateInfo `json:"date"`
	Timestamp int64          `json:"timestamp"`
}

// VnstatUpdated represents updated information
type VnstatUpdated struct {
	Date      VnstatDateInfo `json:"date"`
	Time      VnstatTimeInfo `json:"time"`
	Timestamp int64          `json:"timestamp"`
}

// VnstatDateInfo represents date components
type VnstatDateInfo struct {
	Year  int `json:"year"`
	Month int `json:"month"`
	Day   int `json:"day"`
}

// VnstatTimeInfo represents time components
type VnstatTimeInfo struct {
	Hour   int `json:"hour"`
	Minute int `json:"minute"`
}

// VnstatTraffic represents traffic data from vnstat
type VnstatTraffic struct {
	Total      VnstatTotal        `json:"total"`
	FiveMinute []VnstatTimeEntry  `json:"fiveminute"`
	Hour       []VnstatTimeEntry  `json:"hour"`
	Day        []VnstatTimeEntry  `json:"day"`
	Month      []VnstatMonthEntry `json:"month"`
	Year       []VnstatYearEntry  `json:"year"`
	Top        []VnstatTimeEntry  `json:"top"`
}

// VnstatTotal represents total traffic data
type VnstatTotal struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

// VnstatTimeEntry represents a time-based traffic entry
type VnstatTimeEntry struct {
	ID        int            `json:"id"`
	Date      VnstatDateInfo `json:"date"`
	Time      VnstatTimeInfo `json:"time,omitempty"`
	Timestamp int64          `json:"timestamp"`
	Rx        uint64         `json:"rx"`
	Tx        uint64         `json:"tx"`
}

// VnstatMonthEntry represents a monthly traffic entry
type VnstatMonthEntry struct {
	ID        int            `json:"id"`
	Date      VnstatDateInfo `json:"date"`
	Timestamp int64          `json:"timestamp"`
	Rx        uint64         `json:"rx"`
	Tx        uint64         `json:"tx"`
}

// VnstatYearEntry represents a yearly traffic entry
type VnstatYearEntry struct {
	ID        int            `json:"id"`
	Date      VnstatDateInfo `json:"date"`
	Timestamp int64          `json:"timestamp"`
	Rx        uint64         `json:"rx"`
	Tx        uint64         `json:"tx"`
}

// VnstatOutput represents the complete vnstat JSON output
type VnstatOutput struct {
	VnstatVersion string            `json:"vnstatversion"`
	JsonVersion   string            `json:"jsonversion"`
	Interfaces    []VnstatInterface `json:"interfaces"`
}

func NetworkSpeed() (totalUp, totalDown, upSpeed, downSpeed uint64, err error) {
	includeNics := parseNics(flags.IncludeNics)
	excludeNics := parseNics(flags.ExcludeNics)
	return getNetworkSpeedFallback(includeNics, excludeNics)
}

func getNetworkSpeedFallback(includeNics, excludeNics map[string]struct{}) (totalUp, totalDown, upSpeed, downSpeed uint64, err error) {
	totalUp, totalDown, err = collectNetworkTotals(includeNics, excludeNics)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	upSpeed, downSpeed = updateNetworkSpeedSample(totalUp, totalDown, time.Now())
	totalUp, totalDown = adjustNetworkTotalsForLegacy(totalUp, totalDown, includeNics, excludeNics)
	return totalUp, totalDown, upSpeed, downSpeed, nil
}

func collectNetworkTotals(includeNics, excludeNics map[string]struct{}) (totalUp, totalDown uint64, err error) {
	if runtime.GOOS == "linux" {
		totalUp, totalDown, procErr := collectProcNetworkTotals(procRoot(), includeNics, excludeNics)
		if procErr == nil {
			return totalUp, totalDown, nil
		}

		totalUp, totalDown, fallbackErr := collectGopsutilNetworkTotals(includeNics, excludeNics)
		if fallbackErr != nil {
			return 0, 0, fmt.Errorf("proc net counters failed: %w; gopsutil fallback failed: %v", procErr, fallbackErr)
		}
		return totalUp, totalDown, nil
	}

	return collectGopsutilNetworkTotals(includeNics, excludeNics)
}

func collectProcNetworkTotals(root string, includeNics, excludeNics map[string]struct{}) (totalUp, totalDown uint64, err error) {
	file, err := os.Open(filepath.Join(root, "net", "dev"))
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	return parseProcNetworkTotals(file, includeNics, excludeNics)
}

func parseProcNetworkTotals(reader io.Reader, includeNics, excludeNics map[string]struct{}) (totalUp, totalDown uint64, err error) {
	scanner := bufio.NewScanner(reader)
	parsedInterface := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		separator := strings.IndexByte(line, ':')
		if separator < 0 {
			continue
		}

		name := strings.TrimSpace(line[:separator])
		fields := strings.Fields(line[separator+1:])
		if name == "" || len(fields) < 9 {
			continue
		}

		received, receiveErr := strconv.ParseUint(fields[0], 10, 64)
		transmitted, transmitErr := strconv.ParseUint(fields[8], 10, 64)
		if receiveErr != nil || transmitErr != nil {
			continue
		}
		parsedInterface = true

		if shouldInclude(name, includeNics, excludeNics) {
			totalUp += transmitted
			totalDown += received
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if !parsedInterface {
		return 0, 0, fmt.Errorf("no valid network counters found")
	}

	return totalUp, totalDown, nil
}

func collectGopsutilNetworkTotals(includeNics, excludeNics map[string]struct{}) (totalUp, totalDown uint64, err error) {
	ioCounters, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get network IO counters: %w", err)
	}

	if len(ioCounters) == 0 {
		return 0, 0, fmt.Errorf("no network interfaces found")
	}

	for _, interfaceStats := range ioCounters {
		if shouldInclude(interfaceStats.Name, includeNics, excludeNics) {
			totalUp += interfaceStats.BytesSent
			totalDown += interfaceStats.BytesRecv
		}
	}

	return totalUp, totalDown, nil
}

type networkSpeedState struct {
	sync.Mutex
	totalUp   uint64
	totalDown uint64
	sampledAt time.Time
}

var networkSpeedSample networkSpeedState

func updateNetworkSpeedSample(totalUp, totalDown uint64, now time.Time) (upSpeed, downSpeed uint64) {
	networkSpeedSample.Lock()
	defer networkSpeedSample.Unlock()

	if networkSpeedSample.sampledAt.IsZero() {
		networkSpeedSample.totalUp = totalUp
		networkSpeedSample.totalDown = totalDown
		networkSpeedSample.sampledAt = now
		return 0, 0
	}

	elapsed := now.Sub(networkSpeedSample.sampledAt).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}

	upDelta := safeCounterDelta(totalUp, networkSpeedSample.totalUp)
	downDelta := safeCounterDelta(totalDown, networkSpeedSample.totalDown)

	networkSpeedSample.totalUp = totalUp
	networkSpeedSample.totalDown = totalDown
	networkSpeedSample.sampledAt = now

	return uint64(float64(upDelta) / elapsed), uint64(float64(downDelta) / elapsed)
}

func safeCounterDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return 0
}

func parseNics(nics string) map[string]struct{} {
	if nics == "" {
		return nil
	}
	nicSet := make(map[string]struct{})
	for _, nic := range strings.Split(nics, ",") {
		nicSet[strings.TrimSpace(nic)] = struct{}{}
	}
	return nicSet
}

func shouldInclude(nicName string, includeNics, excludeNics map[string]struct{}) bool {
	name := strings.ToLower(strings.TrimSpace(nicName))
	if name == "lo" || strings.HasPrefix(name, "lo:") {
		return false
	}

	// An explicit allow-list wins over the built-in virtual-interface filter.
	// This keeps provider-facing traffic accurate by default while allowing an
	// operator to intentionally monitor a tunnel interface.
	for pattern := range includeNics {
		if matched, _ := filepath.Match(pattern, nicName); matched {
			return true
		}
	}
	if len(includeNics) != 0 {
		return false
	}

	for prefix := range defaultExcludedNICPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	for pattern := range excludeNics {
		if matched, _ := filepath.Match(pattern, nicName); matched {
			return false
		}
	}

	return true
}

func InterfaceList() ([]string, error) {
	includeNics := parseNics(flags.IncludeNics)
	excludeNics := parseNics(flags.ExcludeNics)
	interfaces := []string{}

	ioCounters, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}
	for _, interfaceStats := range ioCounters {
		if shouldInclude(interfaceStats.Name, includeNics, excludeNics) {
			interfaces = append(interfaces, interfaceStats.Name)
		}
	}
	return interfaces, nil
}
