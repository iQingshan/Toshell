// +build windows

package injection

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// DLLInjector implements DLL injection
type DLLInjector struct{}

// Method returns the injection method
func (i *DLLInjector) Method() InjectionMethod {
	return MethodDLLInjection
}

// Description returns a description of the injection method
func (i *DLLInjector) Description() string {
	return "DLL Injection: Injects a DLL into a running process by creating a remote thread that calls LoadLibrary. " +
		"Steps: OpenProcess -> VirtualAllocEx -> WriteProcessMemory(DLL path) -> GetProcAddress(LoadLibrary) -> CreateRemoteThread"
}

// Inject performs DLL injection
func (i *DLLInjector) Inject(config *Config) (*Result, error) {
	// Validate configuration
	if err := config.Validate(i.Method()); err != nil {
		return &Result{Success: false, Error: err.Error()}, err
	}

	// Convert DLL path to UTF16 bytes with null terminator
	dllPathBytes := append([]byte(config.DLLPath), 0)

	// 1. Open the target process
	process, err := OpenProcess(PROCESS_ALL_ACCESS, false, uint32(config.TargetPID))
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to open process %d: %v", config.TargetPID, err),
		}, err
	}
	defer windows.CloseHandle(process)

	// 2. Allocate memory for the DLL path
	addr, err := VirtualAllocEx(process, 0, uintptr(len(dllPathBytes)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to allocate memory in process: %v", err),
		}, err
	}

	// 3. Write the DLL path to the allocated memory
	_, err = WriteProcessMemory(process, addr, dllPathBytes)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to write DLL path: %v", err),
		}, err
	}

	// 4. Get the address of LoadLibraryA
	kernel32, err := GetModuleHandle("kernel32.dll")
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to get kernel32 handle: %v", err),
		}, err
	}

	loadLibraryAddr, err := GetProcAddress(kernel32, "LoadLibraryA")
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to get LoadLibraryA address: %v", err),
		}, err
	}

	// 5. Create a remote thread that calls LoadLibraryA with the DLL path
	thread, threadID, err := CreateRemoteThread(process, loadLibraryAddr, addr)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to create remote thread: %v", err),
		}, err
	}
	defer windows.CloseHandle(thread)

	// 6. Wait for the thread to complete (optional)
	// In a real implementation, you might want to wait for the thread to finish
	// to ensure the DLL is loaded before returning
	// windows.WaitForSingleObject(thread, windows.INFINITE)

	return &Result{
		Success:   true,
		ProcessID: uint32(config.TargetPID),
		ThreadID:  threadID,
	}, nil
}