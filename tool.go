package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

//go:embed tool.html
var toolIndex []byte

func StartToolServer() {
	http.HandleFunc("/tool/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(toolIndex)
	})
	http.HandleFunc("/tool", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tool/", http.StatusMovedPermanently)
	})
	http.HandleFunc("/tool/sys-info", sysInfoHandler)
}

type SystemInfo struct {
	Timestamp    string           `json:"timestamp"`
	Unix         int64            `json:"unix"`
	Hostname     string           `json:"hostname"`
	OS           OSInfo           `json:"os"`
	Runtime      RuntimeInfo      `json:"runtime"`
	CPU          CPUInfo          `json:"cpu"`
	SystemMemory SystemMemoryInfo `json:"system_memory"`
	Network      NetworkInfo      `json:"network"`
	Environment  EnvironmentInfo  `json:"environment"`
	Process      ProcessInfo      `json:"process"`
	User         UserInfo         `json:"user"`
}

type OSInfo struct {
	Type    string `json:"type"`
	Arch    string `json:"arch"`
	Family  string `json:"family,omitempty"`
	Version string `json:"version,omitempty"`
}

type RuntimeInfo struct {
	Version    string `json:"version"`
	Goroutines int    `json:"goroutines"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	GCEnabled  bool   `json:"gc_enabled"`
	CgoEnabled bool   `json:"cgo_enabled"`
}

type CPUInfo struct {
	Cores      int    `json:"cores"`
	Model      string `json:"model,omitempty"`
	MHz        string `json:"mhz,omitempty"`
	CacheSize  string `json:"cache_size,omitempty"`
	Endianness string `json:"endianness"`
}

type SystemMemoryInfo struct {
	Total       string `json:"total"`
	Available   string `json:"available,omitempty"`
	Used        string `json:"used,omitempty"`
	UsedPercent string `json:"used_percent,omitempty"`
}

type NetworkInfo struct {
	Hostname   string          `json:"hostname"`
	Interfaces []InterfaceInfo `json:"interfaces"`
}

type InterfaceInfo struct {
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	Flags       string   `json:"flags"`
	MTU         int      `json:"mtu"`
	Addresses   []string `json:"addresses"`
	IsUp        bool     `json:"is_up"`
	IsLoopback  bool     `json:"is_loopback"`
	IsMulticast bool     `json:"is_multicast"`
}

type EnvironmentInfo struct {
	Variables map[string]string `json:"variables"`
	Count     int               `json:"count"`
	Path      string            `json:"path"`
	Home      string            `json:"home"`
	Temp      string            `json:"temp"`
	Shell     string            `json:"shell,omitempty"`
	Lang      string            `json:"lang,omitempty"`
	Pwd       string            `json:"pwd"`
}

type ProcessInfo struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	WorkingDir string `json:"working_dir"`
	ExecPath   string `json:"exec_path"`
}

type UserInfo struct {
	UID      string `json:"uid"`
	GID      string `json:"gid"`
	Username string `json:"username"`
	Name     string `json:"name"`
	HomeDir  string `json:"home_dir"`
	Group    string `json:"group,omitempty"`
}

func sysInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	info := getSystemInfo()
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"` + err.Error() + `"}`))
		return
	}
	_, _ = w.Write(data)
}

func getSystemInfo() SystemInfo {
	var info SystemInfo
	now := time.Now()
	info.Timestamp = now.Format(time.RFC3339)
	info.Unix = now.Unix()
	info.Hostname = getHostname()
	info.OS = getOSInfo()
	info.Runtime = getRuntimeInfo()
	info.CPU = getCPUInfo()
	info.SystemMemory = getSystemMemoryInfo()
	info.Network = getNetworkInfo()
	info.Environment = getEnvironmentInfo()
	info.Process = getProcessInfo()
	info.User = getUserInfo()
	return info
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getOSInfo() OSInfo {
	info := OSInfo{
		Type: runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	switch runtime.GOOS {
	case "linux":
		info.Family = "Unix"
	case "darwin":
		info.Family = "Unix"
	case "windows":
		info.Family = "Windows"
	case "freebsd", "netbsd", "openbsd":
		info.Family = "BSD"
	case "android":
		info.Family = "Linux"
	default:
		info.Family = "Unknown"
	}
	return info
}

func getRuntimeInfo() RuntimeInfo {
	return RuntimeInfo{
		Version:    runtime.Version(),
		Goroutines: runtime.NumGoroutine(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		GCEnabled:  true,
		CgoEnabled: runtime.GOARCH != "" && runtime.GOOS != "",
	}
}

func getCPUInfo() CPUInfo {
	info := CPUInfo{
		Cores: runtime.NumCPU(),
	}
	switch runtime.GOARCH {
	case "amd64", "386":
		info.Endianness = "LittleEndian"
	case "arm", "arm64":
		info.Endianness = "LittleEndian"
	case "ppc64", "s390x":
		info.Endianness = "BigEndian"
	case "mips", "mipsle":
		if runtime.GOARCH == "mipsle" {
			info.Endianness = "LittleEndian"
		} else {
			info.Endianness = "BigEndian"
		}
	default:
		info.Endianness = "Unknown"
	}
	return info
}

func getSystemMemoryInfo() SystemMemoryInfo {
	info := SystemMemoryInfo{}
	switch runtime.GOOS {
	case "windows":
		info = getWindowsMemoryInfo()
	case "linux":
		info = getLinuxMemoryInfo()
	case "darwin":
		info = getDarwinMemoryInfo()
	default:
		info = getLinuxMemoryInfo()
	}
	if info.Total == "" {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		info.Total = formatBytes(m.Sys) + " (Go runtime)"
	}
	return info
}

func getWindowsMemoryInfo() SystemMemoryInfo {
	info := SystemMemoryInfo{}
	out, err := exec.Command("powershell", "-Command",
		"Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json").Output()
	if err != nil {
		return info
	}
	var result struct {
		TotalVisibleMemorySize uint64 `json:"TotalVisibleMemorySize"`
		FreePhysicalMemory     uint64 `json:"FreePhysicalMemory"`
	}
	if err := json.Unmarshal(out, &result); err == nil {
		if result.TotalVisibleMemorySize > 0 {
			total := result.TotalVisibleMemorySize * 1024
			free := result.FreePhysicalMemory * 1024
			used := total - free
			info.Total = formatBytes(total)
			info.Available = formatBytes(free)
			info.Used = formatBytes(used)
			info.UsedPercent = fmt.Sprintf("%.1f%%", float64(used)/float64(total)*100)
		}
	}
	return info
}

func getLinuxMemoryInfo() SystemMemoryInfo {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return SystemMemoryInfo{}
	}
	lines := string(data)
	memTotal := parseMemInfo(lines, "MemTotal:")
	memAvailable := parseMemInfo(lines, "MemAvailable:")
	if memTotal == 0 {
		return SystemMemoryInfo{}
	}
	info := SystemMemoryInfo{
		Total: formatBytes(memTotal * 1024),
	}
	if memAvailable > 0 {
		info.Available = formatBytes(memAvailable * 1024)
		used := memTotal - memAvailable
		info.Used = formatBytes(used * 1024)
		info.UsedPercent = fmt.Sprintf("%.1f%%", float64(used)/float64(memTotal)*100)
	}
	return info
}

func getDarwinMemoryInfo() SystemMemoryInfo {
	info := SystemMemoryInfo{}
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		var total uint64
		fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &total)
		if total > 0 {
			info.Total = formatBytes(total)
		}
	}
	out, err = exec.Command("vm_stat").Output()
	if err == nil {
		pageSize := uint64(4096)
		freePages := parseVMStat(string(out), "free")
		activePages := parseVMStat(string(out), "active")
		inactivePages := parseVMStat(string(out), "inactive")
		if freePages > 0 {
			info.Available = formatBytes(freePages * pageSize)
		}
		usedPages := activePages + inactivePages
		if usedPages > 0 {
			info.Used = formatBytes(usedPages * pageSize)
		}
		if info.Total != "" && freePages > 0 {
			totalBytes := parseBytesFromFormat(info.Total)
			if totalBytes > 0 {
				usedBytes := totalBytes - freePages*pageSize
				info.UsedPercent = fmt.Sprintf("%.1f%%", float64(usedBytes)/float64(totalBytes)*100)
			}
		}
	}
	return info
}

func parseVMStat(data string, key string) uint64 {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.Contains(line, key) {
			parts := strings.Fields(line)
			for i, p := range parts {
				if strings.Contains(p, key) && i+1 < len(parts) {
					val := strings.TrimRight(parts[i+1], ".")
					var result uint64
					fmt.Sscanf(val, "%d", &result)
					return result
				}
			}
		}
	}
	return 0
}

func parseBytesFromFormat(s string) uint64 {
	s = strings.TrimSpace(s)
	var val float64
	var unit string
	fmt.Sscanf(s, "%f %s", &val, &unit)
	switch strings.ToUpper(unit) {
	case "KB", "KIB":
		return uint64(val * 1024)
	case "MB", "MIB":
		return uint64(val * 1024 * 1024)
	case "GB", "GIB":
		return uint64(val * 1024 * 1024 * 1024)
	case "TB", "TIB":
		return uint64(val * 1024 * 1024 * 1024 * 1024)
	default:
		return uint64(val)
	}
}

func parseMemInfo(data, key string) uint64 {
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) > len(key) && line[:len(key)] == key {
			var val uint64
			fmt.Sscanf(line[len(key):], "%d", &val)
			return val
		}
	}
	return 0
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func getNetworkInfo() NetworkInfo {
	info := NetworkInfo{
		Hostname: getHostname(),
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return info
	}
	for _, iface := range interfaces {
		ifaceInfo := InterfaceInfo{
			Name:        iface.Name,
			MAC:         iface.HardwareAddr.String(),
			MTU:         iface.MTU,
			IsUp:        iface.Flags&net.FlagUp != 0,
			IsLoopback:  iface.Flags&net.FlagLoopback != 0,
			IsMulticast: iface.Flags&net.FlagMulticast != 0,
		}
		var flags []string
		if iface.Flags&net.FlagUp != 0 {
			flags = append(flags, "UP")
		}
		if iface.Flags&net.FlagBroadcast != 0 {
			flags = append(flags, "BROADCAST")
		}
		if iface.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "LOOPBACK")
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			flags = append(flags, "POINTTOPOINT")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			flags = append(flags, "MULTICAST")
		}
		ifaceInfo.Flags = fmt.Sprintf("%v", flags)
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ifaceInfo.Addresses = append(ifaceInfo.Addresses, addr.String())
			}
		}
		info.Interfaces = append(info.Interfaces, ifaceInfo)
	}
	return info
}

func getEnvironmentInfo() EnvironmentInfo {
	info := EnvironmentInfo{
		Variables: make(map[string]string),
	}
	env := os.Environ()
	info.Count = len(env)
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				key := e[:i]
				value := e[i+1:]
				info.Variables[key] = value
				break
			}
		}
	}
	info.Path = os.Getenv("PATH")
	info.Home = os.Getenv("HOME")
	if info.Home == "" {
		info.Home = os.Getenv("USERPROFILE")
	}
	info.Temp = os.TempDir()
	info.Shell = os.Getenv("SHELL")
	info.Lang = os.Getenv("LANG")
	if info.Lang == "" {
		info.Lang = os.Getenv("LC_ALL")
	}
	pwd, err := os.Getwd()
	if err == nil {
		info.Pwd = pwd
	}
	return info
}

func getProcessInfo() ProcessInfo {
	info := ProcessInfo{
		PID:  os.Getpid(),
		PPID: os.Getppid(),
	}
	pwd, err := os.Getwd()
	if err == nil {
		info.WorkingDir = pwd
	}
	execPath, err := os.Executable()
	if err == nil {
		info.ExecPath = execPath
	}
	return info
}

func getUserInfo() UserInfo {
	info := UserInfo{}
	u, err := user.Current()
	if err == nil {
		info.UID = u.Uid
		info.GID = u.Gid
		info.Username = u.Username
		info.Name = u.Name
		info.HomeDir = u.HomeDir
	}
	return info
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
