//go:build !windows && !light

package main

import "fmt"

// handleUACBypass UAC 提权仅 Windows 有效。
func handleUACBypass(taskData string) (string, int32, string) {
	return "", -1, fmt.Sprintf("UAC bypass is not supported on this platform")
}
