//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// ─── Linux/macOS 交互式 Shell：PTY 伪终端 ────────────────────────────
// 传统管道实现（stdout/stderr 分管道、无 TTY）在 bash 下表现为非交互模式：
// 无提示符、无行编辑、clear/top/vim 等全屏程序异常、输出乱序。
// PTY 让 shell 获得真实终端（交互模式 + 行编辑 + 全屏程序），
// stdout/stderr 合流消除乱序。Windows 走管道实现（见 shell_pty_windows.go）。

// shellOpenPTY 在 Linux/macOS 上以 PTY 启动交互式 shell。
// ptyTty/ptyCmd 在 main.go 声明，本文件赋值。
func shellOpenPTY(shell string) error {
	if shell == "" {
		shell = "/bin/bash"
	}

	// 交互模式必须：-i 启用交互（PTY 下提示符/行编辑生效），
	// 去掉 --noediting（PTY 本身提供行编辑）
	cmd := exec.Command(shell, "-i")
	cmd.Env = append(os.Environ(),
		"TERM=xterm",
		"PS1=$ ",
		"COLUMNS=120",
		"LINES=40",
	)

	f, err := pty.Start(cmd)
	if err != nil {
		return err
	}

	ptyTty = f
	ptyCmd = cmd

	// shell 输出（stdout+stderr 合流）→ 上行
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				shellSendOutput(buf[:n])
			}
		}
	}()

	// 进程退出清理
	go func() {
		cmd.Wait()
		shellRunning = false
		shellSendOutput([]byte("\r\n[Shell exited]\r\n"))
		f.Close()
		ptyTty = nil
		ptyCmd = nil
	}()

	return nil
}

// shellWritePTY 写入 PTY（模拟终端输入）。
func shellWritePTY(data []byte) error {
	if ptyTty == nil {
		return fmt.Errorf("pty not open")
	}
	_, err := ptyTty.Write(data)
	return err
}

// shellResizePTY 调整 PTY 终端尺寸（前端 FitAddon 变化时调用）。
func shellResizePTY(cols, rows uint16) error {
	if ptyTty == nil {
		return fmt.Errorf("pty not open")
	}
	return pty.Setsize(ptyTty, &pty.Winsize{Cols: cols, Rows: rows})
}

// shellClosePTY 终止 shell 进程。
func shellClosePTY() {
	if ptyCmd != nil && ptyCmd.Process != nil {
		_ = ptyCmd.Process.Kill()
	}
}
