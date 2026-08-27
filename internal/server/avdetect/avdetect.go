// Package avdetect 提供基于进程名指纹库的安全软件识别（服务端侧）。
//
// 指纹库数据源为 data/av_fingerprints.json（av 456 + edr 51 + office 50 条），
// 由服务端加载维护，可热更新而无需重新编译植入端。
// 植入端只需上报原始进程名列表，匹配与结果组装全部在本包完成。
package avdetect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Fingerprint 对应 av_fingerprints.json 中的单条指纹：进程名 -> 产品。
type Fingerprint struct {
	Process  string `json:"process"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Found 命中结果，字段与旧版植入端输出保持一致，前端无需改动。
type Found struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Process  string `json:"process"`
}

// categoryCN 将指纹库英文分类映射为旧版展示用的中文分类。
func categoryCN(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "av":
		return "杀毒软件"
	case "edr":
		return "EDR"
	case "office":
		return "安全工具"
	default:
		if c == "" {
			return "安全工具"
		}
		return c
	}
}

var (
	mu       sync.RWMutex
	byProc   map[string]Fingerprint // 归一化进程名 -> 指纹
	loaded   bool
	loadErr  error
	loadPath string
)

// normalize 归一化进程名用于匹配：去引号、取 base、去 .exe 后缀、转小写。
func normalize(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"`)
	p = filepath.Base(p)
	p = strings.TrimSuffix(strings.ToLower(p), ".exe")
	return p
}

// CandidatePaths 返回指纹库候选路径，按优先级排列。
func CandidatePaths() []string {
	var paths []string
	if env := os.Getenv("TOSHELL_AV_FINGERPRINTS"); env != "" {
		paths = append(paths, env)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		paths = append(paths,
			filepath.Join(exeDir, "data", "av_fingerprints.json"),
			filepath.Join(exeDir, "av_fingerprints.json"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		paths = append(paths,
			filepath.Join(wd, "data", "av_fingerprints.json"),
			filepath.Join(wd, "av_fingerprints.json"),
		)
	}
	return paths
}

func loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw struct {
		Fingerprints map[string][]Fingerprint `json:"fingerprints"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	idx := make(map[string]Fingerprint)
	for _, list := range raw.Fingerprints {
		for _, fp := range list {
			key := normalize(fp.Process)
			if key == "" {
				continue
			}
			if _, dup := idx[key]; !dup {
				idx[key] = fp
			}
		}
	}
	if len(idx) == 0 {
		return fmt.Errorf("no valid fingerprints in %s", path)
	}
	byProc = idx
	return nil
}

// Load 从候选路径加载指纹库，成功一次即停止；重复调用只加载一次。
func Load() error {
	mu.Lock()
	defer mu.Unlock()
	if loaded {
		return loadErr
	}
	var lastErr error
	for _, p := range CandidatePaths() {
		if p == "" {
			continue
		}
		if err := loadFile(p); err == nil {
			loadPath = p
			loaded = true
			loadErr = nil
			return nil
		} else if !os.IsNotExist(err) {
			lastErr = err
		}
	}
	loaded = true
	loadErr = lastErr
	if loadErr == nil {
		loadErr = fmt.Errorf("av_fingerprints.json not found in any candidate path")
	}
	return loadErr
}

// Loaded 返回指纹库是否已成功加载。
func Loaded() bool {
	mu.RLock()
	defer mu.RUnlock()
	return loaded && loadErr == nil && byProc != nil
}

// Path 返回实际加载的指纹库路径。
func Path() string {
	mu.RLock()
	defer mu.RUnlock()
	return loadPath
}

// ProcessCount 返回指纹库中可匹配的进程条目数。
func ProcessCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(byProc)
}

// Match 对进程名列表做指纹匹配，返回命中结果（按产品去重，按产品名排序）。
func Match(processes []string) []Found {
	mu.RLock()
	idx := byProc
	mu.RUnlock()
	if idx == nil {
		return nil
	}
	matchedName := make(map[string]bool)
	var found []Found
	for _, p := range processes {
		fp, ok := idx[normalize(p)]
		if !ok {
			continue
		}
		if matchedName[fp.Name] {
			continue
		}
		matchedName[fp.Name] = true
		found = append(found, Found{Name: fp.Name, Category: categoryCN(fp.Category), Process: strings.TrimSpace(p)})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found
}

// DetectFromOutput 处理 av_detect 任务结果输出，兼容新/旧植入端：
//   - 新植入端输出进程名 JSON 数组（["360sd.exe", ...]），本函数匹配并组装命中结果 JSON；
//   - 旧植入端输出已含 "name" 字段的命中结果 JSON，直接透传；
//   - 解析失败或空输出时原样返回。
func DetectFromOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}
	if strings.Contains(output, `"name"`) {
		return output // 旧版植入端，已是命中结果
	}
	var procs []string
	if err := json.Unmarshal([]byte(output), &procs); err != nil {
		return output
	}
	found := Match(procs)
	if len(found) == 0 {
		return ""
	}
	data, err := json.MarshalIndent(found, "", "  ")
	if err != nil {
		return output
	}
	return string(data)
}
