//go:build !windows
// +build !windows

package injection

import "fmt"

// GetProcessPath returns the full path of a process by PID (non-Windows stub)
func GetProcessPath(pid uint32) (string, error) {
	return "", fmt.Errorf("process path retrieval not supported on this platform")
}

// ExecuteCommandStruct executes an injection command (non-Windows stub)
func ExecuteCommandStruct(cmd *Command) (*CommandResult, error) {
	return &CommandResult{
		Success: false,
		Error:   "injection not supported on this platform",
	}, fmt.Errorf("injection operations are only supported on Windows")
}