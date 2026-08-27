//go:build !windows

package main

func handleProcessInject(data string) (string, int32, string) {
	return "", -1, "process injection only supported on Windows"
}

func handleProcessSpoof(data string) (string, int32, string) {
	return "", -1, "process spoofing only supported on Windows"
}

func handleAutoInject(data string) (string, int32, string) {
	return "", -1, "auto inject only supported on Windows"
}

func handleInjection(data string) (string, int32, string) {
	return "", -1, "injection only supported on Windows"
}

func handleSpawn(data string) (string, int32, string) {
	return "", -1, "spawn only supported on Windows"
}
