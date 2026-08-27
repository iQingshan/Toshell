//go:build windows && amd64

#include "textflag.h"

// func directSyscall(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12 uintptr) uintptr
//
// 直接系统调用（Direct Syscall）：不经过 ntdll 的 syscall 桩（该桩可能被 EDR 用户态 hook），
// 由运行时从 ntdll 导出函数中提取 SSN 后直接执行 SYSCALL 指令。
// Windows x64 原生系统调用约定：
//   - RAX = SSN
//   - R10 = arg1, RDX = arg2, R8 = arg3, R9 = arg4
//   - [RSP+0x28] = arg5, [RSP+0x30] = arg6, ...（内核从用户栈读取第 5 个及之后的参数）
TEXT ·directSyscall(SB), NOSPLIT, $0x80-112
	// 第 5~12 个参数写入栈帧（内核从 [rsp+0x28] 起读取）
	MOVQ a5+40(FP), CX
	MOVQ CX, 0x28(SP)
	MOVQ a6+48(FP), CX
	MOVQ CX, 0x30(SP)
	MOVQ a7+56(FP), CX
	MOVQ CX, 0x38(SP)
	MOVQ a8+64(FP), CX
	MOVQ CX, 0x40(SP)
	MOVQ a9+72(FP), CX
	MOVQ CX, 0x48(SP)
	MOVQ a10+80(FP), CX
	MOVQ CX, 0x50(SP)
	MOVQ a11+88(FP), CX
	MOVQ CX, 0x58(SP)
	MOVQ a12+96(FP), CX
	MOVQ CX, 0x60(SP)
	// 前 4 个参数放入寄存器
	MOVQ a1+8(FP), R10
	MOVQ a2+16(FP), DX
	MOVQ a3+24(FP), R8
	MOVQ a4+32(FP), R9
	// SSN 放入 EAX 并执行 syscall
	MOVQ ssn+0(FP), AX
	SYSCALL
	// 返回值（NTSTATUS）在 AX
	MOVQ AX, ret+104(FP)
	RET
