// getPEB 返回当前线程的 PEB 指针（Windows x64）。
// x64 TEB 基址位于 GS 段，PEB 在 TEB+0x60。
TEXT ·getPEB(SB), 4, $0-8
	MOVQ 0x60(GS), AX
	MOVQ AX, ret+0(FP)
	RET
