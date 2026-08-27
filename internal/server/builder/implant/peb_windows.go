//go:build windows && (amd64 || 386)

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── PEB 模块遍历（amd64 / 386）────────────────────────────────────────
// 通过汇编读取 GS/FS 段寄存器中的 PEB，再沿 Ldr.InMemoryOrderModuleList
// 遍历已加载模块。全程纯内存操作，不调用任何 API，也无模块/API 名明文。

// getPEB 返回当前线程的 PEB 指针（汇编实现，见 getpeb_amd64.s / getpeb_386.s）。
func getPEB() uintptr

// 以下结构体布局需与 Windows 原生结构一致，指针大小随架构自动适配。

type listEntry struct {
	flink *listEntry
	blink *listEntry
}

type unicodeString struct {
	length    uint16
	maxLength uint16
	buffer    *uint16
}

// peb 对应 PEB 前部字段（Ldr 在 offset 0x18/0x30）
type peb struct {
	reserved1     [2]byte
	beingDebugged byte
	reserved2     [1]byte
	reserved3     [2]uintptr
	ldr           *pebLdrData
}

// pebLdrData 对应 PEB_LDR_DATA（InMemoryOrderModuleList 在前部）
type pebLdrData struct {
	reserved1          [8]byte
	reserved2          [3]uintptr
	inMemoryOrderLinks listEntry
}

// ldrDataTableEntry 对应 LDR_DATA_TABLE_ENTRY 前部字段
type ldrDataTableEntry struct {
	reserved1          [2]uintptr
	inMemoryOrderLinks listEntry
	reserved2          [2]uintptr
	dllBase            uintptr
	entryPoint         uintptr
	sizeOfImage        uintptr
	fullDllName        unicodeString
	baseDllName        unicodeString
}

func readUnicodeString(u unicodeString) string {
	if u.buffer == nil || u.length < 2 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(u.buffer, int(u.length)/2))
}

// getModuleBase 通过 PEB 模块链表返回指定模块的基址。
func getModuleBase(name string) uintptr {
	pebPtr := getPEB()
	if pebPtr == 0 {
		return 0
	}
	p := (*peb)(unsafe.Pointer(pebPtr))
	if p.ldr == nil {
		return 0
	}
	head := &p.ldr.inMemoryOrderLinks
	target := strings.ToLower(name)
	cur := head.flink
	for cur != nil && cur != head {
		// cur 指向当前节点的 inMemoryOrderLinks 字段
		entry := (*ldrDataTableEntry)(unsafe.Pointer(
			uintptr(unsafe.Pointer(cur)) - unsafe.Sizeof(ldrDataTableEntry{}.inMemoryOrderLinks)))
		if entry.dllBase != 0 {
			modName := strings.ToLower(readUnicodeString(entry.baseDllName))
			if strings.TrimSuffix(modName, ".dll") == strings.TrimSuffix(target, ".dll") {
				return entry.dllBase
			}
		}
		cur = cur.flink
	}
	return 0
}

// getAPIFastPEB 是 amd64/386 平台的快速解析实现。
func getAPIFastPEB(module, api string) uintptr {
	base := getModuleBase(module)
	if base == 0 {
		return 0
	}
	return getProcAddr(base, apiHash(api))
}

func init() {
	getAPIFast = getAPIFastPEB
}
