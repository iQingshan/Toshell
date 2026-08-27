//go:build windows
// +build windows

package injection

import (
	"fmt"
)

// InjectionMethod defines the injection method type
type InjectionMethod int

const (
	MethodRemoteThread InjectionMethod = iota
	MethodAPC
	MethodEarlyBird
	MethodThreadHijack
	MethodProcessHollowing
	MethodDLLInjection
)

// String returns the string representation of the injection method
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

// Config contains the configuration for injection
type Config struct {
	// TargetPID is the target process ID for injection
	// Required for: RemoteThread, APC, ThreadHijack, DLLInjection
	TargetPID int

	// TargetPath is the path to the target executable
	// Required for: ProcessHollowing, EarlyBird
	TargetPath string

	// Shellcode is the payload to inject
	// Required for: RemoteThread, APC, EarlyBird, ThreadHijack, ProcessHollowing
	Shellcode []byte

	// DLLPath is the path to the DLL file to inject
	// Required for: DLLInjection
	DLLPath string

	// ParentPID is the parent process ID to spoof
	// Optional for: ProcessHollowing, EarlyBird
	ParentPID int
}

// Result contains the result of injection
type Result struct {
	// Success indicates if the injection was successful
	Success bool

	// ProcessID is the ID of the injected/spawned process
	ProcessID uint32

	// ThreadID is the ID of the created thread (if applicable)
	ThreadID uint32

	// Error contains any error message
	Error string
}

// Injector is the interface for injection methods
type Injector interface {
	// Inject performs the injection
	Inject(config *Config) (*Result, error)

	// Method returns the injection method
	Method() InjectionMethod

	// Description returns a description of the injection method
	Description() string
}

// NewInjector creates a new injector based on the method
func NewInjector(method InjectionMethod) (Injector, error) {
	switch method {
	case MethodRemoteThread:
		return &RemoteThreadInjector{}, nil
	case MethodAPC:
		return &APCInjector{}, nil
	case MethodEarlyBird:
		return &EarlyBirdInjector{}, nil
	case MethodThreadHijack:
		return &ThreadHijackInjector{}, nil
	case MethodProcessHollowing:
		return &ProcessHollowingInjector{}, nil
	case MethodDLLInjection:
		return &DLLInjector{}, nil
	default:
		return nil, fmt.Errorf("unsupported injection method: %d", method)
	}
}

// Execute performs injection with the given method and configuration
func Execute(method InjectionMethod, config *Config) (*Result, error) {
	injector, err := NewInjector(method)
	if err != nil {
		return nil, err
	}

	return injector.Inject(config)
}

// Validate validates the configuration for the given method
func (c *Config) Validate(method InjectionMethod) error {
	switch method {
	case MethodRemoteThread, MethodAPC, MethodThreadHijack:
		if c.TargetPID == 0 {
			return fmt.Errorf("TargetPID is required for %s injection", method)
		}
		if len(c.Shellcode) == 0 {
			return fmt.Errorf("Shellcode is required for %s injection", method)
		}

	case MethodProcessHollowing, MethodEarlyBird:
		if c.TargetPath == "" {
			return fmt.Errorf("TargetPath is required for %s injection", method)
		}
		if len(c.Shellcode) == 0 {
			return fmt.Errorf("Shellcode is required for %s injection", method)
		}

	case MethodDLLInjection:
		if c.TargetPID == 0 {
			return fmt.Errorf("TargetPID is required for %s injection", method)
		}
		if c.DLLPath == "" {
			return fmt.Errorf("DLLPath is required for %s injection", method)
		}
	}

	return nil
}