//go:build light

package main

// ─── 精简构建（light profile）功能 stub ──────────────────────────────
//
// light 构建档案通过 -tags light 裁剪重量级可选模块（截图/屏幕流/中继/
// BOF/凭据/持久化/EDR/BYOVD/UAC/进程注入/插件/全内存执行），显著减小
// 植入端体积。本文件提供这些功能的空实现，使 main.go 的任务分发可编译，
// 运行时返回"未编译此功能"提示。

// 截图 / 屏幕流
func handleScreenshot(taskData string) (string, int32, string) {
	return "", -1, "截图功能未包含在精简构建中（请使用完整档案构建）"
}

func handleScreenStream(taskData string) (string, int32, string) {
	return "", -1, "屏幕流功能未包含在精简构建中"
}

// 中继
func handleRelayControl(taskData string) (string, int32, string) {
	return "", -1, "Beacon Mesh 中继未包含在精简构建中"
}

func startRelayListener(listenAddr string) error {
	return nil // 精简构建不启用中继监听
}

func handleRelayDown(payload []byte) {}

// BOF / 插件（BOF 与 EXE/DLL/shellcode 插件在精简构建中裁剪；
// fileless_exec 入口与 DLL 反射加载由 main.go / memload 保留，此处不重复定义）
func loadBOF(data string, args string) (string, int32, string) {
	return "", -1, "BOF 未包含在精简构建中"
}

func loadEXE(data string, args string) (string, int32, string) {
	return "", -1, "插件未包含在精简构建中"
}

func loadDLL(data string) (string, int32, string) {
	return "", -1, "插件未包含在精简构建中"
}

func loadShellcode(data string) (string, int32, string) {
	return "", -1, "插件未包含在精简构建中"
}

// 模块伪造（内存隐匿 2.0）
func stompShellcode(data string) (string, int32, string) {
	return "", -1, "模块伪造未包含在精简构建中"
}

// 进程注入
func handleProcessInject(data string) (string, int32, string) {
	return "", -1, "进程注入未包含在精简构建中"
}

func handleProcessSpoof(data string) (string, int32, string) {
	return "", -1, "进程注入未包含在精简构建中"
}

func handleAutoInject(data string) (string, int32, string) {
	return "", -1, "进程注入未包含在精简构建中"
}

func handleInjection(data string) (string, int32, string) {
	return "", -1, "进程注入未包含在精简构建中"
}

func handleSpawn(data string) (string, int32, string) {
	return "", -1, "spawn 未包含在精简构建中"
}

// 凭据 / 持久化
func handleCredentials(action string) (string, int32, string) {
	return "", -1, "凭据收集未包含在精简构建中"
}

func handlePersistence(taskData string) (string, int32, string) {
	return "", -1, "持久化未包含在精简构建中"
}

// EDR / BYOVD / PPL / UAC
func handleEDRBlind(taskData string) (string, int32, string) {
	return "", -1, "EDR 失明未包含在精简构建中"
}

func handleEDRKill(taskData string) (string, int32, string) {
	return "", -1, "EDR 击杀未包含在精简构建中"
}

func handleBYOVDLoad(taskData string) (string, int32, string) {
	return "", -1, "BYOVD 未包含在精简构建中"
}

func handleBYOVDUnload(taskData string) (string, int32, string) {
	return "", -1, "BYOVD 未包含在精简构建中"
}

func handlePPLKill(taskData string) (string, int32, string) {
	return "", -1, "PPL 击杀未包含在精简构建中"
}

func handleUACBypass(taskData string) (string, int32, string) {
	return "", -1, "UAC 提权未包含在精简构建中"
}
