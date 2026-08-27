//go:build legacy_shellcode
// +build legacy_shellcode

package builder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	donut "github.com/Binject/go-donut/donut"
)

func (b *Builder) buildShellcode(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compile(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %v", err)
	}

	shellcode, err := b.generateShellcodeWithDonutLib(binary, opts.Arch)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shellcode: %v", err)
	}

	configData, _ := json.Marshal(b.buildConfig(opts))
	shellcodeHex := hex.EncodeToString(shellcode)

	fmt.Printf("[DEBUG] buildShellcode: shellcode len=%d, hex len=%d\n",
		len(shellcode), len(shellcodeHex))

	return &BuildResult{
		Binary:       shellcode,
		Config:       configData,
		Shellcode:    shellcode,
		ShellcodeHex: shellcodeHex,
	}, nil
}

func (b *Builder) buildShellcodeBin(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compile(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %v", err)
	}

	shellcode, err := b.generateShellcodeWithDonutLib(binary, opts.Arch)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shellcode: %v", err)
	}

	configData, _ := json.Marshal(b.buildConfig(opts))

	return &BuildResult{
		Binary:    shellcode,
		Config:    configData,
		Shellcode: shellcode,
	}, nil
}

func (b *Builder) generateShellcodeWithDonutLib(binary []byte, arch string) ([]byte, error) {
	targetArch := donut.X84
	switch arch {
	case "386":
		targetArch = donut.X32
	case "amd64":
		targetArch = donut.X64
	default:
		targetArch = donut.X84
	}

	config := &donut.DonutConfig{
		Arch:       targetArch,
		InstType:   donut.DONUT_INSTANCE_PIC,
		Type:       donut.DONUT_MODULE_EXE,
		Entropy:    donut.DONUT_ENTROPY_DEFAULT,
		Thread:     0,
		Compress:   1,
		Unicode:    0,
		ExitOpt:    2,      // ExitProcess (V1.0.0)
		Format:     1,
		Bypass:     3,
		Parameters: "",
	}

	shellcode, err := donut.ShellcodeFromBytes(bytes.NewBuffer(binary), config)
	if err != nil {
		return nil, fmt.Errorf("donut shellcode generation failed: %v", err)
	}

	return shellcode.Bytes(), nil
}
