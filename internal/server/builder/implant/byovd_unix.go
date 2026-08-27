//go:build !windows && !light

package main

// handleBYOVDLoad BYOVD 驱动加载：非 Windows 平台不支持。
func handleBYOVDLoad(taskData string) (string, int32, string) {
	return "", -1, "BYOVD driver loading is only supported on Windows"
}

// handleBYOVDUnload BYOVD 驱动卸载：非 Windows 平台不支持。
func handleBYOVDUnload(taskData string) (string, int32, string) {
	return "", -1, "BYOVD driver unload is only supported on Windows"
}

// handlePPLKill PPL 击杀：非 Windows 平台不支持。
func handlePPLKill(taskData string) (string, int32, string) {
	return "", -1, "PPL kill is only supported on Windows"
}
