// +build !windows

package injection

// Command represents an injection command
type Command struct {
	Method            string `json:"method"`
	TargetPID         int    `json:"target_pid,omitempty"`
	TargetProcessName string `json:"target_process_name,omitempty"`
	TargetPath        string `json:"target_path,omitempty"`
	Shellcode         string `json:"shellcode,omitempty"`
	DLLPath           string `json:"dll_path,omitempty"`
	ParentPID         int    `json:"parent_pid,omitempty"`
}

// CommandResult represents the result of an injection command
type CommandResult struct {
	Success   bool   `json:"success"`
	ProcessID uint32 `json:"process_id,omitempty"`
	ThreadID  uint32 `json:"thread_id,omitempty"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

// MethodInfo contains information about an injection method
type MethodInfo struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	RequiresPID      bool   `json:"requires_pid"`
	RequiresPath     bool   `json:"requires_path"`
	RequiresShellcode bool   `json:"requires_shellcode"`
	RequiresDLL      bool   `json:"requires_dll"`
}