//go:build !windows

package main

// loadDLLMem 反射加载 DLL：非 Windows 平台不支持。
func loadDLLMem(dataB64, entryName string) (string, int32, string) {
	return "", -1, "DLL reflective loading is only supported on Windows"
}
