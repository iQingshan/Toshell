package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type PluginType string

const (
	PluginTypeEXE       PluginType = "exe"
	PluginTypeDLL       PluginType = "dll"
	PluginTypeShellcode PluginType = "shellcode"
	PluginTypeBOF       PluginType = "bof"
)

type Plugin struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        PluginType `json:"type"`
	Size        int64      `json:"size"`
	Path        string     `json:"path"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Manager struct {
	pluginDir string
	plugins   map[string]*Plugin
	mu        sync.RWMutex
}

var (
	manager *Manager
	once    sync.Once
)

func Init(pluginDir string) (*Manager, error) {
	var initErr error
	once.Do(func() {
		if err := os.MkdirAll(pluginDir, 0755); err != nil {
			initErr = fmt.Errorf("failed to create plugin directory: %w", err)
			return
		}
		manager = &Manager{
			pluginDir: pluginDir,
			plugins:   make(map[string]*Plugin),
		}
		initErr = manager.scanPlugins()
	})
	return manager, initErr
}

func GetManager() *Manager {
	return manager
}

func (m *Manager) scanPlugins() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	m.plugins = make(map[string]*Plugin)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		pluginType := m.detectPluginType(entry.Name())
		if pluginType == "" {
			continue
		}

		plugin := &Plugin{
			ID:        entry.Name(),
			Name:      entry.Name(),
			Type:      pluginType,
			Size:      info.Size(),
			Path:      filepath.Join(m.pluginDir, entry.Name()),
			CreatedAt: info.ModTime(),
			UpdatedAt: info.ModTime(),
		}

		m.plugins[plugin.ID] = plugin
	}

	return nil
}

func (m *Manager) detectPluginType(filename string) PluginType {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".exe":
		return PluginTypeEXE
	case ".dll":
		return PluginTypeDLL
	case ".bin", ".raw", ".sc":
		return PluginTypeShellcode
	case ".o", ".obj":
		return PluginTypeBOF
	default:
		return ""
	}
}

func (m *Manager) List() []*Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]*Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (m *Manager) Get(id string) (*Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.plugins[id]
	if !ok {
		return nil, fmt.Errorf("plugin not found: %s", id)
	}
	return plugin, nil
}

// ErrInvalidName 表示插件名未通过安全校验（调用方参数问题，可映射为 4xx）。
//
// 调用方可用 errors.Is(err, ErrInvalidName) 把"名字非法"与"服务端写盘失败"区分开。
var ErrInvalidName = errors.New("插件名非法")

// MaxPluginNameLen 是插件文件名的字节数上限。
const MaxPluginNameLen = 64

// ValidatePluginName 校验一个"将直接被用作插件目录内文件名"的插件名。
//
// 这是**安全边界**函数：MCP `plugin_upload` 的 name 与 HTTP multipart 的上传文件名
// 都来自不可信输入，必须经过这里。策略是"只拒绝会影响路径语义的字符"，不误伤正常文件名：
//   - 1..64 **字节**（UTF-8 编码后长度），必须是合法 UTF-8；
//   - 必须是纯 basename（filepath.Base(name) == name），拒绝 `/`、`\`、`:` 与 NUL；
//   - 拒绝控制字符（<0x20、0x7f 及其它 Unicode 控制符）；
//   - 拒绝空串、`.`、`..` 与以 `.` 开头的隐藏文件名；
//   - ASCII 允许可打印字符（字母数字、空格、`_`、`-`、括号等）；
//     非 ASCII 允许 Unicode 文字/数字/组合符/标点/符号（中文等）；
//   - 拒绝 Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，含带扩展名形式）；
//   - 扩展名必须在 detectPluginType 的白名单内：未知扩展名直接拒绝，不猜类型、不兜底。
//
// 返回的错误都包裹 ErrInvalidName，消息为中文（直接面向 API 调用方展示）。
func ValidatePluginName(name string) error {
	if name == "" {
		return fmt.Errorf("%w：插件名不能为空", ErrInvalidName)
	}
	if len(name) > MaxPluginNameLen {
		return fmt.Errorf("%w：插件名过长（%d 字节，上限 %d 字节；中文按 UTF-8 计 3 字节）",
			ErrInvalidName, len(name), MaxPluginNameLen)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w：插件名不是合法的 UTF-8 字符串", ErrInvalidName)
	}
	if filepath.Base(name) != name {
		return fmt.Errorf("%w：插件名不能包含路径（只允许纯文件名）", ErrInvalidName)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w：插件名不能是相对路径占位符 %q", ErrInvalidName, name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("%w：插件名不能以 . 开头（隐藏文件或相对路径）", ErrInvalidName)
	}
	for _, r := range name {
		switch {
		case r == 0:
			return fmt.Errorf("%w：插件名不能包含 NUL 字节", ErrInvalidName)
		case r < 0x20 || r == 0x7f || unicode.IsControl(r):
			return fmt.Errorf("%w：插件名不能包含控制字符 0x%02x", ErrInvalidName, r)
		case r == '/' || r == '\\' || r == ':':
			return fmt.Errorf("%w：插件名不能包含 / \\ : 等路径字符", ErrInvalidName)
		case r < 0x80:
			// 其余可打印 ASCII（字母数字、空格、_ - .、括号等）均允许。
			continue
		case unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) ||
			unicode.IsPunct(r) || unicode.IsSymbol(r):
			// 非 ASCII 的合法 Unicode 文字/标点（中文等）允许。
			continue
		default:
			return fmt.Errorf("%w：插件名含非法 Unicode 字符 %q", ErrInvalidName, string(r))
		}
	}
	if isReservedDeviceName(name) {
		return fmt.Errorf("%w：插件名 %q 是 Windows 保留设备名", ErrInvalidName, name)
	}
	if !IsValidPluginType(name) {
		return fmt.Errorf("%w：不支持的插件扩展名 %q（允许的扩展名：.exe/.dll/.bin/.raw/.sc/.o/.obj）",
			ErrInvalidName, filepath.Ext(name))
	}
	return nil
}

// isReservedDeviceName 拒绝 Windows 保留设备名（NUL/COM1/...）：在 Windows 上
// `NUL.exe` 会被解析成设备而不是普通文件，写入不会真正落到插件目录里。
// Windows 会忽略设备名末尾的空格，故取第一个点前的主名并去掉尾部空格后比较。
func isReservedDeviceName(name string) bool {
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToUpper(strings.Trim(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	}
	return false
}

// assertWithinDir 断言 target（Clean 后）位于 dir 内：Rel 结果不得为 ".."、
// 不得以 ".."+分隔符 开头，也不得是绝对路径。
func assertWithinDir(dir, target string) error {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return fmt.Errorf("%w：插件目标路径不可解析: %v", ErrInvalidName, err)
	}
	if rel == "." || filepath.IsAbs(rel) || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%w：插件目标路径越出插件目录", ErrInvalidName)
	}
	return nil
}

// oNoFollowFlag 返回 O_NOFOLLOW 的平台取值。
//
// Go 的 os/syscall 在 Windows 上不导出 O_NOFOLLOW（该平台没有这个语义），
// 因此这里不能直接写 os.O_NOFOLLOW（GOOS=windows 会编译失败）。取值：
//   - Linux 全架构统一为 0x20000（asm-generic/fcntl.h 的 0400000）；
//   - Darwin/BSD 为 0x100；
//   - 其它平台返回 0，由 Add 里的 Lstat 预检拒绝符号链接兜底。
func oNoFollowFlag() int {
	switch runtime.GOOS {
	case "linux":
		return 0x20000
	case "darwin", "freebsd", "netbsd", "openbsd", "dragonfly":
		return 0x100
	default:
		return 0
	}
}

// writePluginFile 以"不跟随末级符号链接"的方式覆盖写插件文件。
//
// O_CREATE 与 O_NOFOLLOW 同用时，若末级路径已是符号链接，Linux 返回 ELOOP，
// 绝不会打开链接目标。它配合 Add 里的 Lstat 预检构成双重防护：
// 预检失败/被并发替换时，仍由内核拒绝跟随。
func writePluginFile(target string, data []byte) error {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|oNoFollowFlag(), 0o644)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// isSymlinkWriteError 判断写盘错误是否来自"目标是符号链接"（ELOOP/EMLINK）。
func isSymlinkWriteError(err error) bool {
	if err == nil {
		return false
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "symbolic link") ||
		strings.Contains(msg, "too many levels") ||
		strings.Contains(msg, "too many links")
}

// Add 把插件字节写入插件目录并登记到内存索引。
//
// name 完全来自不可信输入，因此这里**不依赖调用方校验**，自带四道防线：
//  1. ValidatePluginName：纯 basename + 字符/长度白名单 + 扩展名白名单；
//  2. filepath.Join + Clean 后做 Rel 前缀断言（必须在 pluginDir 内）；
//  3. EvalSymlinks(pluginDir) 得到真实根后再断言一次（防 pluginDir 自身是软链），
//     并用 Lstat 拒绝"末级已是符号链接"的目标；
//  4. 真正写盘用 O_NOFOLLOW（见 writePluginFile），即使预检与写入之间被并发替换
//     成符号链接，内核也不会跟随链接写入（不会写到链接目标）。
func (m *Manager) Add(name string, data []byte, description string) (*Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 防线一：名字白名单。
	if err := ValidatePluginName(name); err != nil {
		return nil, err
	}
	pluginType := m.detectPluginType(name)
	if pluginType == "" {
		// ValidatePluginName 已拦下未知扩展名；保留显式分支，避免将来两处漂移。
		return nil, fmt.Errorf("%w：不支持的插件扩展名 %q", ErrInvalidName, filepath.Ext(name))
	}

	// 防线二：拼接 + Clean 后的 Rel 前缀断言。
	root, err := filepath.Abs(m.pluginDir)
	if err != nil {
		return nil, fmt.Errorf("解析插件目录失败: %w", err)
	}
	target := filepath.Clean(filepath.Join(root, name))
	if err := assertWithinDir(root, target); err != nil {
		return nil, err
	}

	// 防线三：pluginDir 可能是符号链接，用真实根再断言一次；并拒绝末级符号链接。
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("解析插件目录真实路径失败（插件目录不可用）: %w", err)
	}
	if err := assertWithinDir(realRoot, filepath.Join(realRoot, name)); err != nil {
		return nil, err
	}
	if fi, lerr := os.Lstat(target); lerr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("拒绝写入插件 %q：目标是符号链接，已阻止跟随链接写盘", name)
		}
	} else if !os.IsNotExist(lerr) {
		return nil, fmt.Errorf("检查插件目标失败: %w", lerr)
	}

	// 防线四：O_NOFOLLOW 写入。
	if werr := writePluginFile(target, data); werr != nil {
		if isSymlinkWriteError(werr) {
			return nil, fmt.Errorf("拒绝写入插件 %q：目标是符号链接（或被并发替换为符号链接），已阻止跟随链接写盘", name)
		}
		return nil, fmt.Errorf("failed to write plugin file: %w", werr)
	}

	id := strings.TrimSuffix(name, filepath.Ext(name))
	plugin := &Plugin{
		ID:          id,
		Name:        name,
		Description: description,
		Type:        pluginType,
		Size:        int64(len(data)),
		Path:        target,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	m.plugins[id] = plugin
	return plugin, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, ok := m.plugins[id]
	if !ok {
		return fmt.Errorf("plugin not found: %s", id)
	}

	// If file was already removed manually, just clean up the in-memory entry
	if err := os.Remove(plugin.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete plugin file: %w", err)
	}

	delete(m.plugins, id)
	return nil
}

func (m *Manager) ReadPluginData(id string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.plugins[id]
	if !ok {
		return nil, fmt.Errorf("plugin not found: %s", id)
	}

	data, err := os.ReadFile(plugin.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin file: %w", err)
	}

	return data, nil
}

func (m *Manager) Refresh() error {
	return m.scanPlugins()
}

func (p *Plugin) ToJSON() string {
	data, _ := json.Marshal(p)
	return string(data)
}

func IsValidPluginType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	validTypes := []string{".exe", ".dll", ".bin", ".raw", ".sc", ".o", ".obj"}
	for _, t := range validTypes {
		if ext == t {
			return true
		}
	}
	return false
}

func GetPluginTypes() []string {
	return []string{"exe", "dll", "shellcode", "bof"}
}

func (m *Manager) GetPluginInfo() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	counts := make(map[PluginType]int)
	for _, p := range m.plugins {
		counts[p.Type]++
	}

	return map[string]interface{}{
		"total":  len(m.plugins),
		"counts": counts,
		"types":  GetPluginTypes(),
		"dir":    m.pluginDir,
	}
}

func (m *Manager) WalkPlugins(fn func(path string, d fs.DirEntry, err error) error) error {
	return filepath.WalkDir(m.pluginDir, fn)
}
