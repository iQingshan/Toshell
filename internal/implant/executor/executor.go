package executor

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type Executor interface {
	Execute(cmd string, args []string, timeout uint32) (*ExecutionResult, error)
}

type ExecutionResult struct {
	ExitCode int32
	Output   string
	Error    string
	Duration time.Duration
}

type ShellExecutor struct {
	shell    string
	shellArg string
}

func NewShellExecutor() *ShellExecutor {
	shell := "cmd"
	shellArg := "/c"

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		shell = "/bin/sh"
		shellArg = "-c"
	}

	return &ShellExecutor{
		shell:    shell,
		shellArg: shellArg,
	}
}

func (e *ShellExecutor) Execute(cmd string, args []string, timeout uint32) (*ExecutionResult, error) {
	startTime := time.Now()

	fullCmd := cmd
	if len(args) > 0 {
		fullCmd = fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))
	}

	command := exec.Command(e.shell, e.shellArg, fullCmd)
	command.Env = os.Environ()
	if runtime.GOOS == "windows" {
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	if timeout > 0 {
		timeoutDuration := time.Duration(timeout) * time.Second
		done := make(chan error, 1)

		go func() {
			done <- command.Run()
		}()

		select {
		case err := <-done:
			duration := time.Since(startTime)
			result := &ExecutionResult{
				Duration: duration,
			}

			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					result.ExitCode = int32(exitError.ExitCode())
					result.Error = stderr.String()
				} else {
					result.Error = err.Error()
				}
			} else {
				result.ExitCode = 0
			}

			result.Output = stdout.String()
			return result, nil

		case <-time.After(timeoutDuration):
			command.Process.Kill()
			duration := time.Since(startTime)
			return &ExecutionResult{
				ExitCode: -1,
				Error:    "timeout",
				Duration: duration,
			}, fmt.Errorf("command timeout")
		}
	}

	err := command.Run()
	duration := time.Since(startTime)

	result := &ExecutionResult{
		Duration: duration,
	}

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = int32(exitError.ExitCode())
			result.Error = stderr.String()
		} else {
			result.Error = err.Error()
		}
	} else {
		result.ExitCode = 0
	}

	result.Output = stdout.String()
	return result, nil
}

type PowerShellExecutor struct {
	powershellPath string
}

func NewPowerShellExecutor() *PowerShellExecutor {
	path := "powershell"
	if runtime.GOOS == "windows" {
		path = "powershell.exe"
	}

	return &PowerShellExecutor{
		powershellPath: path,
	}
}

func (e *PowerShellExecutor) Execute(cmd string, args []string, timeout uint32) (*ExecutionResult, error) {
	startTime := time.Now()

	allArgs := append([]string{"-NoProfile", "-NonInteractive", "-Command", cmd}, args...)

	command := exec.Command(e.powershellPath, allArgs...)
	command.Env = os.Environ()
	if runtime.GOOS == "windows" {
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	if timeout > 0 {
		timeoutDuration := time.Duration(timeout) * time.Second
		done := make(chan error, 1)

		go func() {
			done <- command.Run()
		}()

		select {
		case err := <-done:
			duration := time.Since(startTime)
			result := &ExecutionResult{
				Duration: duration,
			}

			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					result.ExitCode = int32(exitError.ExitCode())
					result.Error = stderr.String()
				} else {
					result.Error = err.Error()
				}
			} else {
				result.ExitCode = 0
			}

			result.Output = stdout.String()
			return result, nil

		case <-time.After(timeoutDuration):
			command.Process.Kill()
			duration := time.Since(startTime)
			return &ExecutionResult{
				ExitCode: -1,
				Error:    "timeout",
				Duration: duration,
			}, fmt.Errorf("command timeout")
		}
	}

	err := command.Run()
	duration := time.Since(startTime)

	result := &ExecutionResult{
		Duration: duration,
	}

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = int32(exitError.ExitCode())
			result.Error = stderr.String()
		} else {
			result.Error = err.Error()
		}
	} else {
		result.ExitCode = 0
	}

	result.Output = stdout.String()
	return result, nil
}

func ExecuteCommand(cmdType, cmd string, args []string, timeout uint32) (*ExecutionResult, error) {
	var executor Executor

	switch strings.ToLower(cmdType) {
	case "powershell":
		executor = NewPowerShellExecutor()
	case "shell", "cmd", "bash", "sh":
		executor = NewShellExecutor()
	default:
		executor = NewShellExecutor()
	}

	return executor.Execute(cmd, args, timeout)
}
