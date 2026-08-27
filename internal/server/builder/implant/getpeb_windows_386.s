// getPEB 返回当前线程的 PEB 指针（Windows x86）。
// x86 TEB 基址位于 FS 段，PEB 在 TEB+0x30。
TEXT ·getPEB(SB), 4, $0-4
	MOVL 0x30(FS), AX
	MOVL AX, ret+0(FP)
	RET
