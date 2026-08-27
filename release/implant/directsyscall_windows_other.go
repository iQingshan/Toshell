//go:build windows && !amd64

package main

import (
	"unsafe"
)

// 非 amd64（386/arm64）不实现直接系统调用，统一回退到 apihash 解析调用。
// 接口与 directsyscall_windows_amd64.go 保持一致，便于 plugin_windows.go 无差别调用。

const currentProcess = ^uintptr(0)

func ntAllocateVirtualMemory(process uintptr, baseAddr, regionSize *uintptr, allocType, protect uint32) uintptr {
	r1, _, _ := resolveAPI("ntdll.dll", "NtAllocateVirtualMemory").Call(process, uintptr(unsafe.Pointer(baseAddr)), 0, uintptr(unsafe.Pointer(regionSize)), uintptr(allocType), uintptr(protect))
	return r1
}

func ntFreeVirtualMemory(process uintptr, baseAddr, regionSize *uintptr, freeType uint32) uintptr {
	r1, _, _ := resolveAPI("ntdll.dll", "NtFreeVirtualMemory").Call(process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), uintptr(freeType))
	return r1
}

func ntProtectVirtualMemory(process uintptr, baseAddr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) uintptr {
	r1, _, _ := resolveAPI("ntdll.dll", "NtProtectVirtualMemory").Call(process, uintptr(unsafe.Pointer(baseAddr)), uintptr(unsafe.Pointer(regionSize)), uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)))
	return r1
}

func ntWriteVirtualMemory(process, baseAddr, buffer uintptr, size uintptr, bytesWritten *uintptr) uintptr {
	r1, _, _ := resolveAPI("ntdll.dll", "NtWriteVirtualMemory").Call(process, baseAddr, buffer, size, uintptr(unsafe.Pointer(bytesWritten)))
	return r1
}

func ntCreateThreadEx(threadHandle *uintptr, desiredAccess, objAttr, process, startRoutine, argument, createFlags, zeroBits, stackSize, maxStackSize, attributeList uintptr) uintptr {
	r1, _, _ := resolveAPI("ntdll.dll", "NtCreateThreadEx").Call(uintptr(unsafe.Pointer(threadHandle)), desiredAccess, objAttr, process, startRoutine, argument, createFlags, zeroBits, stackSize, maxStackSize, attributeList)
	return r1
}

func ntClose(handle uintptr) uintptr {
	r1, _, _ := resolveAPI("ntdll.dll", "NtClose").Call(handle)
	return r1
}
