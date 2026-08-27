// +build windows

package injection

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants
const (
	PROCESS_ALL_ACCESS         = 0x1F0FFF
	PROCESS_CREATE_THREAD      = 0x0002
	PROCESS_VM_OPERATION       = 0x0008
	PROCESS_VM_READ            = 0x0010
	PROCESS_VM_WRITE           = 0x0020
	PROCESS_QUERY_INFORMATION  = 0x0400

	MEM_COMMIT                 = 0x00001000
	MEM_RESERVE                = 0x00002000
	MEM_RELEASE                = 0x8000

	PAGE_EXECUTE_READWRITE     = 0x40
	PAGE_READWRITE             = 0x04
	PAGE_EXECUTE_READ          = 0x20

	CREATE_SUSPENDED           = 0x00000004
	CREATE_NEW_CONSOLE         = 0x00000010

	THREAD_ALL_ACCESS          = 0x1F03FF

	CONTEXT_FULL               = 0x00010007
	CONTEXT_CONTROL             = 0x00010001
	CONTEXT_INTEGER             = 0x00010002

	TH32CS_SNAPPROCESS         = 0x00000002
	TH32CS_SNAPTHREAD          = 0x00000004
)

// CONTEXT structure for x64
type CONTEXT struct {
	P1Home         uint64
	P2Home         uint64
	P3Home         uint64
	P4Home         uint64
	P5Home         uint64
	P6Home         uint64
	ContextFlags  uint32
	MxCsr         uint32
	SegCs         uint16
	SegDs         uint16
	SegEs         uint16
	SegFs         uint16
	SegGs         uint16
	SegSs         uint16
	EFlags       uint32
	Dr0           uint64
	Dr1           uint64
	Dr2           uint64
	Dr3           uint64
	Dr6           uint64
	Dr7           uint64
	Rax           uint64
	Rcx           uint64
	Rdx           uint64
	Rbx           uint64
	Rsp           uint64
	Rbp           uint64
	Rsi           uint64
	Rdi           uint64
	R8            uint64
	R9            uint64
	R10           uint64
	R11           uint64
	R12           uint64
	R13           uint64
	R14           uint64
	R15           uint64
	Rip           uint64
	FltSave       [512]byte
	VectorRegister [26]uint128
	VectorControl uint64
	DebugControl  uint64
	LastBranchToRip uint64
	LastBranchFromRip uint64
	LastExceptionToRip uint64
	LastExceptionFromRip uint64
}

// uint128 represents a 128-bit integer
type uint128 struct {
	Low  uint64
	High int64
}

// PROCESSENTRY32 structure for process enumeration
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	HeapProcessID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

// THREADENTRY32 structure for thread enumeration
type THREADENTRY32 struct {
	Size           uint32
	CntUsage       uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}

// STARTUPINFO structure
type STARTUPINFO struct {
	Cb              uint32
	LPReserved      *uint16
	LPDesktop       *uint16
	LPTitle         *uint16
	DwX             uint32
	DwY             uint32
	DwXSize         uint32
	DwYSize         uint32
	DwXCountChars   uint32
	DwYCountChars   uint32
	DwFillAttribute uint32
	DwFlags         uint32
	WShowWindow     uint16
	CbReserved2     uint16
	LPReserved2     *byte
	HStdInput       windows.Handle
	HStdOutput      windows.Handle
	HStdError       windows.Handle
}

// PROCESS_INFORMATION structure
type PROCESS_INFORMATION struct {
	Process   windows.Handle
	Thread    windows.Handle
	ProcessID uint32
	ThreadID  uint32
}

// Windows API functions
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")

	procOpenProcess               = modkernel32.NewProc("OpenProcess")
	procVirtualAllocEx            = modkernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx              = modkernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory         = modkernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")
	procCreateRemoteThread         = modkernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC              = modkernel32.NewProc("QueueUserAPC")
	procGetThreadContext          = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext          = modkernel32.NewProc("SetThreadContext")
	procSuspendThread             = modkernel32.NewProc("SuspendThread")
	procResumeThread              = modkernel32.NewProc("ResumeThread")
	procCreateToolhelp32Snapshot  = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First            = modkernel32.NewProc("Process32FirstW")
	procProcess32Next             = modkernel32.NewProc("Process32NextW")
	procThread32First             = modkernel32.NewProc("Thread32First")
	procThread32Next              = modkernel32.NewProc("Thread32Next")
	procCreateProcess             = modkernel32.NewProc("CreateProcessW")
	procVirtualProtectEx          = modkernel32.NewProc("VirtualProtectEx")
	procGetModuleHandle           = modkernel32.NewProc("GetModuleHandleW")
	procGetProcAddress            = modkernel32.NewProc("GetProcAddress")

	procNtUnmapViewOfSection      = modntdll.NewProc("NtUnmapViewOfSection")
)

// OpenProcess opens a process
func OpenProcess(desiredAccess uint32, inheritHandle bool, processID uint32) (windows.Handle, error) {
	var inherit uint32
	if inheritHandle {
		inherit = 1
	}

	handle, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processID),
	)

	if handle == 0 {
		return 0, err
	}

	return windows.Handle(handle), nil
}

// VirtualAllocEx allocates memory in a remote process
func VirtualAllocEx(process windows.Handle, addr uintptr, size uintptr, allocationType uint32, protect uint32) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(process),
		addr,
		size,
		uintptr(allocationType),
		uintptr(protect),
	)

	if ret == 0 {
		return 0, err
	}

	return ret, nil
}

// VirtualFreeEx frees memory in a remote process
func VirtualFreeEx(process windows.Handle, addr uintptr, size uintptr, freeType uint32) error {
	ret, _, err := procVirtualFreeEx.Call(
		uintptr(process),
		addr,
		size,
		uintptr(freeType),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// WriteProcessMemory writes data to a process
func WriteProcessMemory(process windows.Handle, baseAddress uintptr, buffer []byte) (int, error) {
	var bytesWritten uintptr

	ret, _, err := procWriteProcessMemory.Call(
		uintptr(process),
		baseAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return 0, err
	}

	return int(bytesWritten), nil
}

// ReadProcessMemory reads data from a process
func ReadProcessMemory(process windows.Handle, baseAddress uintptr, buffer []byte) (int, error) {
	var bytesRead uintptr

	ret, _, err := procReadProcessMemory.Call(
		uintptr(process),
		baseAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return 0, err
	}

	return int(bytesRead), nil
}

// CreateRemoteThread creates a thread in a remote process
func CreateRemoteThread(process windows.Handle, startAddress uintptr, parameter uintptr) (windows.Handle, uint32, error) {
	var threadID uint32

	handle, _, err := procCreateRemoteThread.Call(
		uintptr(process),
		0,
		0,
		startAddress,
		parameter,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)

	if handle == 0 {
		return 0, 0, err
	}

	return windows.Handle(handle), threadID, nil
}

// QueueUserAPC queues an APC to a thread
func QueueUserAPC(apcFunc uintptr, thread windows.Handle, parameter uintptr) error {
	ret, _, err := procQueueUserAPC.Call(
		apcFunc,
		uintptr(thread),
		parameter,
	)

	if ret == 0 {
		return err
	}

	return nil
}

// GetThreadContext gets the context of a thread
func GetThreadContext(thread windows.Handle) (*CONTEXT, error) {
	ctx := &CONTEXT{}
	ctx.ContextFlags = CONTEXT_FULL

	ret, _, err := procGetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(ctx)),
	)

	if ret == 0 {
		return nil, err
	}

	return ctx, nil
}

// SetThreadContext sets the context of a thread
func SetThreadContext(thread windows.Handle, ctx *CONTEXT) error {
	ret, _, err := procSetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(ctx)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// SuspendThread suspends a thread
func SuspendThread(thread windows.Handle) (uint32, error) {
	ret, _, err := procSuspendThread.Call(uintptr(thread))

	if ret == 0xFFFFFFFF {
		return 0, err
	}

	return uint32(ret), nil
}

// ResumeThread resumes a thread
func ResumeThread(thread windows.Handle) (uint32, error) {
	ret, _, err := procResumeThread.Call(uintptr(thread))

	if ret == 0xFFFFFFFF {
		return 0, err
	}

	return uint32(ret), nil
}

// CreateToolhelp32Snapshot creates a snapshot
func CreateToolhelp32Snapshot(flags uint32, processID uint32) (windows.Handle, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processID),
	)

	if handle == 0 {
		return 0, err
	}

	return windows.Handle(handle), nil
}

// Process32First retrieves information about the first process
func Process32First(snapshot windows.Handle, entry *PROCESSENTRY32) error {
	ret, _, err := procProcess32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(entry)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// Process32Next retrieves information about the next process
func Process32Next(snapshot windows.Handle, entry *PROCESSENTRY32) error {
	ret, _, err := procProcess32Next.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(entry)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// Thread32First retrieves information about the first thread
func Thread32First(snapshot windows.Handle, entry *THREADENTRY32) error {
	ret, _, err := procThread32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(entry)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// Thread32Next retrieves information about the next thread
func Thread32Next(snapshot windows.Handle, entry *THREADENTRY32) error {
	ret, _, err := procThread32Next.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(entry)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// CreateProcess creates a new process
func CreateProcess(applicationPath string, commandLine string, suspended bool) (*PROCESS_INFORMATION, error) {
	var si STARTUPINFO
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi PROCESS_INFORMATION

	var creationFlags uint32 = CREATE_NEW_CONSOLE
	if suspended {
		creationFlags |= CREATE_SUSPENDED
	}

	appName, _ := syscall.UTF16PtrFromString(applicationPath)
	var cmdLine *uint16
	if commandLine != "" {
		cmdLine, _ = syscall.UTF16PtrFromString(commandLine)
	}

	ret, _, err := procCreateProcess.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		0,
		0,
		0,
		uintptr(creationFlags),
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return nil, err
	}

	return &pi, nil
}

// VirtualProtectEx changes memory protection in a remote process
func VirtualProtectEx(process windows.Handle, addr uintptr, size uintptr, newProtect uint32) (uint32, error) {
	var oldProtect uint32

	ret, _, err := procVirtualProtectEx.Call(
		uintptr(process),
		addr,
		size,
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret == 0 {
		return 0, err
	}

	return oldProtect, nil
}

// NtUnmapViewOfSection unmaps a view of a section
func NtUnmapViewOfSection(process windows.Handle, baseAddress uintptr) error {
	ret, _, _ := procNtUnmapViewOfSection.Call(
		uintptr(process),
		baseAddress,
	)

	// NTSTATUS error handling
	if ret != 0 {
		return fmt.Errorf("NtUnmapViewOfSection failed with status: 0x%X", ret)
	}

	return nil
}

// GetModuleHandle gets a module handle
func GetModuleHandle(moduleName string) (windows.Handle, error) {
	var moduleNamePtr *uint16
	if moduleName != "" {
		moduleNamePtr, _ = syscall.UTF16PtrFromString(moduleName)
	}

	handle, _, err := procGetModuleHandle.Call(
		uintptr(unsafe.Pointer(moduleNamePtr)),
	)

	if handle == 0 {
		return 0, err
	}

	return windows.Handle(handle), nil
}

// GetProcAddress gets the address of a procedure
func GetProcAddress(module windows.Handle, procName string) (uintptr, error) {
	procNamePtr, _ := syscall.BytePtrFromString(procName)

	addr, _, err := procGetProcAddress.Call(
		uintptr(module),
		uintptr(unsafe.Pointer(procNamePtr)),
	)

	if addr == 0 {
		return 0, err
	}

	return addr, nil
}

// FindProcessByName finds a process ID by name
func FindProcessByName(processName string) (uint32, error) {
	snapshot, err := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := Process32First(snapshot, &entry); err != nil {
		return 0, err
	}

	for {
		exeFile := syscall.UTF16ToString(entry.ExeFile[:])
		if exeFile == processName {
			return entry.ProcessID, nil
		}

		if err := Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process not found: %s", processName)
}

// FindThreadsByProcessID finds all threads for a process
func FindThreadsByProcessID(processID uint32) ([]uint32, error) {
	snapshot, err := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := Thread32First(snapshot, &entry); err != nil {
		return nil, err
	}

	var threads []uint32
	for {
		if entry.OwnerProcessID == processID {
			threads = append(threads, entry.ThreadID)
		}

		if err := Thread32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return threads, nil
}