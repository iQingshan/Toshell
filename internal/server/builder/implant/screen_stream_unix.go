//go:build !windows

package main

// handleScreenStream 实时屏幕流：非 Windows 平台不支持。
func handleScreenStream(taskData string) (string, int32, string) {
	return "", -1, "screen stream is only supported on Windows"
}
