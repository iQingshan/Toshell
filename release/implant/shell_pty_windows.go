//go:build windows

package main

import "fmt"

// ─── Windows 交互式 Shell：管道实现（无 PTY）─────────────────────────
// Windows 的 ConPTY 支持有限且复杂，当前保持原有 cmd.exe 管道实现
// （见 handleShellOpen 的 windows 分支）。这些 stub 满足 Linux 端
// PTY 函数的接口引用，Windows 构建不实际调用。

func shellOpenPTY(shell string) error {
	return fmt.Errorf("pty not supported on windows")
}

func shellWritePTY(data []byte) error {
	return fmt.Errorf("pty not supported on windows")
}

func shellResizePTY(cols, rows uint16) error {
	return fmt.Errorf("pty not supported on windows")
}

func shellClosePTY() {}
