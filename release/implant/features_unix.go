//go:build !windows

package main

// handlePersistence 持久化功能仅支持 Windows
func handlePersistence(data string) (string, int32, string) {
	return "", -1, "persistence only supported on Windows"
}

// handleCredentials 凭据收集功能仅支持 Windows
func handleCredentials(action string) (string, int32, string) {
	return "", -1, "credentials collection only supported on Windows"
}

// handleScreenshot 截图功能仅支持 Windows
func handleScreenshot(taskData string) (string, int32, string) {
	return "", -1, "screenshot only supported on Windows"
}
