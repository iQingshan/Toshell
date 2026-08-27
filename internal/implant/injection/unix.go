//go:build !windows
// +build !windows

package injection

import "fmt"

// InjectionMethod defines injection method type
type InjectionMethod int

const (
	MethodRemoteThread InjectionMethod = iota
	MethodAPC
	MethodEarlyBird
	MethodThreadHijack
	MethodProcessHollowing
	MethodDLLInjection
)

// String returns string representation of injection method
func (m InjectionMethod) String() string {
	switch m {
	case MethodRemoteThread:
		return "RemoteThread"
	case MethodAPC:
		return "APC"
	case MethodEarlyBird:
		return "EarlyBird"
	case MethodThreadHijack:
		return "ThreadHijack"
	case MethodProcessHollowing:
		return "ProcessHollowing"
	case MethodDLLInjection:
		return "DLLInjection"
	default:
		return "Unknown"
	}
}

// Config contains configuration for injection
type Config struct {
	TargetPID  int
	TargetPath string
	Shellcode  []byte
	DLLPath    string
	ParentPID  int
}

// Result contains the result of injection
type Result struct {
	Success   bool
	ProcessID uint32
	ThreadID  uint32
	Error     string
}

// Injector is the interface for injection methods
type Injector interface {
	Inject(config *Config) (*Result, error)
	Method() InjectionMethod
	Description() string
}

// NewInjector creates a new injector based on method
func NewInjector(method InjectionMethod) (Injector, error) {
	return nil, fmt.Errorf("injection not supported on this platform")
}

// Execute performs injection with the given method and configuration
func Execute(method InjectionMethod, config *Config) (*Result, error) {
	return &Result{
		Success: false,
		Error:   "injection not supported on this platform",
	}, fmt.Errorf("injection not supported on this platform")
}

// Validate validates the configuration for the given method
func (c *Config) Validate(method InjectionMethod) error {
	return fmt.Errorf("injection not supported on this platform")
}