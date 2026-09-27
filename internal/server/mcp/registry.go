// Package mcp 提供 ToShell 的「工具元数据单一来源 + 统一结果信封 + 结果外置存储」，
// 以及对外暴露的 MCP（Model Context Protocol）服务端实现。
//
// 设计约束（见 ROADMAP.md 的「S1 开放 MCP 服务接口 + 公共执行基础设施」）：
//   - **工具元数据只能有一处定义**：REST `/api/v1/mcp/tools`、内置 AI 的 tool schema、
//     对外 MCP 的 `tools/list` 全部从本注册表派生，杜绝"三处硬编码各改一遍"导致的漂移；
//   - **本包不得反向依赖 `api` / `ai`**：执行能力通过 Executor 接口由上层注入，
//     避免 api ↔ ai ↔ mcp 的循环依赖；
//   - **风险分级（Level）是默认白名单与审批门的唯一依据**：新增工具默认按危险处理，
//     只有显式标成 LevelRead 的才免审批（与旧实现"允许列表 + fail-open"相反）。
package mcp

import (
	"sort"
	"strings"
)

// Level 工具风险等级。分级是默认白名单与审批门的唯一依据。
type Level int

const (
	// LevelRead 只读、不接触被控主机（查询类）。可免审批，默认放行。
	LevelRead Level = iota
	// LevelConfirm 影响目标会话（下发任务、读写文件、启停隧道等）。需用户确认。
	LevelConfirm
	// LevelDanger 不可逆或高风险（载荷构建、注入、驱动加载、杀软对抗、进程终止等）。
	// 每次调用都要审批，且不放进默认白名单。
	LevelDanger
)

func (l Level) String() string {
	switch l {
	case LevelRead:
		return "read"
	case LevelConfirm:
		return "confirm"
	case LevelDanger:
		return "danger"
	default:
		return "unknown"
	}
}

// ParseLevel 解析配置文件里写的等级字符串；无法识别时按最严格的 LevelDanger 处理（fail-closed）。
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read", "readonly", "read_only":
		return LevelRead
	case "confirm", "write", "session":
		return LevelConfirm
	default:
		return LevelDanger
	}
}

// Param 单个工具参数的元数据。Type 用于生成 JSON Schema，必须与执行侧实际解析保持一致。
type Param struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string | integer | boolean | array
	Required    bool     `json:"required"`
	Description string   `json:"description"`
	Enum        []string `json:"enum,omitempty"`
	Example     string   `json:"example,omitempty"`
}

// ToolDef 单个工具的完整定义（全项目唯一的元数据来源）。
type ToolDef struct {
	Name string `json:"name"`
	// Description 写成"指令"而不是"规格"：何时调用 / 何时不要调用 / 前置依赖。
	Description string  `json:"description"`
	Level       Level   `json:"level"`
	Params      []Param `json:"params"`
	// Deprecated：为 true 时 REST 与 MCP 都不再暴露（用于下线工具时保留 invokeTool 分支）。
	Deprecated bool `json:"deprecated,omitempty"`
}

// JSONSchema 生成 JSON Schema（2020-12 子集），供 MCP tools/list 与 LLM function calling 共用。
func (t *ToolDef) JSONSchema() map[string]interface{} {
	props := make(map[string]interface{}, len(t.Params))
	required := make([]string, 0, len(t.Params))
	for _, p := range t.Params {
		typ := p.Type
		if typ == "" {
			typ = "string"
		}
		prop := map[string]interface{}{
			"type":        typ,
			"description": p.Description,
		}
		if len(p.Enum) > 0 {
			prop["enum"] = p.Enum
		}
		if p.Example != "" {
			prop["examples"] = []string{p.Example}
		}
		props[p.Name] = prop
		if p.Required {
			required = append(required, p.Name)
		}
	}
	schema := map[string]interface{}{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// ParamNames 返回参数名列表（保持定义顺序），供旧 REST 的 `parameters []string` 字段复用。
func (t *ToolDef) ParamNames() []string {
	out := make([]string, 0, len(t.Params))
	for _, p := range t.Params {
		out = append(out, p.Name)
	}
	return out
}

// RequiredNames 返回必填参数名。
func (t *ToolDef) RequiredNames() []string {
	out := make([]string, 0, len(t.Params))
	for _, p := range t.Params {
		if p.Required {
			out = append(out, p.Name)
		}
	}
	return out
}

// Registry 工具注册表：名字 → 定义，附稳定的展示顺序。
type Registry struct {
	byName map[string]*ToolDef
	order  []string
}

// NewRegistry 用给定定义构造注册表（重复名字以后者为准，但保留首次出现的顺序）。
func NewRegistry(defs []ToolDef) *Registry {
	r := &Registry{byName: make(map[string]*ToolDef, len(defs))}
	for i := range defs {
		d := defs[i]
		if d.Name == "" {
			continue
		}
		if _, exists := r.byName[d.Name]; !exists {
			r.order = append(r.order, d.Name)
		}
		cp := d
		r.byName[d.Name] = &cp
	}
	return r
}

// Len 工具总数（含已弃用工具）。
func (r *Registry) Len() int { return len(r.order) }

// Get 按名字取定义。
func (r *Registry) Get(name string) (*ToolDef, bool) {
	d, ok := r.byName[name]
	return d, ok
}

// All 返回全部定义（按注册顺序，跳过已弃用）。
func (r *Registry) All() []*ToolDef {
	out := make([]*ToolDef, 0, len(r.order))
	for _, n := range r.order {
		if d := r.byName[n]; d != nil && !d.Deprecated {
			out = append(out, d)
		}
	}
	return out
}

// Names 返回全部工具名（按注册顺序，跳过已弃用）。
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.order))
	for _, n := range r.order {
		if d := r.byName[n]; d != nil && !d.Deprecated {
			out = append(out, n)
		}
	}
	return out
}

// ByLevel 返回指定风险等级的工具（按注册顺序）。
func (r *Registry) ByLevel(l Level) []*ToolDef {
	out := make([]*ToolDef, 0, len(r.order))
	for _, d := range r.All() {
		if d.Level == l {
			out = append(out, d)
		}
	}
	return out
}

// LevelOf 返回工具的风险等级；**未注册的工具一律视为 LevelDanger**（fail-closed）。
func (r *Registry) LevelOf(name string) Level {
	if d, ok := r.byName[name]; ok {
		return d.Level
	}
	return LevelDanger
}

// IsRegistered 判断工具是否在案（用于"幻觉工具调用防护"）。
func (r *Registry) IsRegistered(name string) bool {
	_, ok := r.byName[name]
	return ok
}

// NamesSorted 返回按字典序排序的工具名（给需要稳定输出的审计/测试用）。
func (r *Registry) NamesSorted() []string {
	out := r.Names()
	sort.Strings(out)
	return out
}

var defaultRegistry *Registry

// Default 返回内置注册表（数据在 registry_tools.go，构造一次后复用）。
func Default() *Registry {
	if defaultRegistry == nil {
		defaultRegistry = NewRegistry(builtinTools())
	}
	return defaultRegistry
}

// DefaultAllowed 返回"默认放行"的工具集合：仅只读工具。
// 对外暴露 MCP 时若未显式配置白名单，就用这个集合——宁可少给，不可多给。
func (r *Registry) DefaultAllowed() []string {
	return r.levelNames(LevelRead)
}

func (r *Registry) levelNames(l Level) []string {
	out := make([]string, 0, 8)
	for _, d := range r.ByLevel(l) {
		out = append(out, d.Name)
	}
	return out
}
