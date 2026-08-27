//go:build !windows && !light

package main

// handleEDRBlind EDR 失明：非 Windows 平台不支持。
func handleEDRBlind(taskData string) (string, int32, string) {
	return "", -1, "EDR blind is only supported on Windows"
}

// handleEDRKill EDR 击杀：非 Windows 平台不支持。
func handleEDRKill(taskData string) (string, int32, string) {
	return "", -1, "EDR kill is only supported on Windows"
}
