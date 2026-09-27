package mcp

import (
	"strings"
	"testing"
)

// TestBuiltinRegistryShape 校验内置注册表的基本形状：数量、唯一性、字段完备、类型合法。
// 这些断言的作用是"新增工具时忘了填字段"能在 CI 立刻暴露，而不是等模型调用时才发现。
func TestBuiltinRegistryShape(t *testing.T) {
	reg := Default()
	if reg.Len() == 0 {
		t.Fatal("内置注册表为空：builtinTools() 没被填？")
	}

	seen := map[string]bool{}
	for _, d := range reg.All() {
		if d.Name == "" {
			t.Fatalf("存在空名字的工具定义")
		}
		if seen[d.Name] {
			t.Fatalf("工具名重复: %s", d.Name)
		}
		seen[d.Name] = true

		if strings.TrimSpace(d.Description) == "" {
			t.Errorf("工具 %s 缺少 description（模型据此决定何时调用）", d.Name)
		}
		// description 必须"有实质内容"，不能是占位/与工具名一样的敷衍说明。
		// 刻意**不**用关键词白名单来判"是否指令"——那会把措辞不同但同样合格的描述误判
		//（例如 intel_query 用的是"必须是下方枚举值之一…别用自造类型名去试探"）。
		// 是否"写成指令"由人评审；机器只保证下限。
		if len([]rune(d.Description)) < 20 {
			t.Errorf("工具 %s 的 description 过短（%d 字），疑似占位，应说明何时调用/何时不要调用/前置依赖: %q",
				d.Name, len([]rune(d.Description)), d.Description)
		}
		if strings.TrimSpace(d.Description) == d.Name {
			t.Errorf("工具 %s 的 description 就是工具名本身，没写用途", d.Name)
		}
		for _, p := range d.Params {
			if p.Name == "" {
				t.Errorf("工具 %s 存在无名参数", d.Name)
			}
			if strings.TrimSpace(p.Description) == "" {
				t.Errorf("工具 %s 的参数 %s 缺少 description", d.Name, p.Name)
			}
			switch p.Type {
			case "string", "integer", "boolean", "array":
			default:
				t.Errorf("工具 %s 的参数 %s 类型非法: %q（只允许 string/integer/boolean/array）", d.Name, p.Name, p.Type)
			}
		}
	}
}

// TestRegistryLevelsFailClosed 未注册的工具必须按最危险处理（fail-closed）。
func TestRegistryLevelsFailClosed(t *testing.T) {
	reg := Default()
	if got := reg.LevelOf("definitely_not_a_tool"); got != LevelDanger {
		t.Fatalf("未注册工具的风险等级 = %v, want LevelDanger（fail-closed）", got)
	}
	if reg.IsRegistered("definitely_not_a_tool") {
		t.Fatal("未注册工具不应被认为已登记")
	}
}

// TestDefaultAllowedOnlyReadOnly 默认放行集合必须只包含只读工具。
func TestDefaultAllowedOnlyReadOnly(t *testing.T) {
	reg := Default()
	allowed := reg.DefaultAllowed()
	if len(allowed) == 0 {
		t.Fatal("默认放行集合为空：应至少包含只读工具")
	}
	for _, name := range allowed {
		if lv := reg.LevelOf(name); lv != LevelRead {
			t.Fatalf("默认放行集合里出现了非只读工具 %s（等级 %v）", name, lv)
		}
	}
	// 危险工具绝不能出现在默认放行集合里（这里是"别再退回 fail-open"的回归门）。
	for _, danger := range []string{"exec", "run_command", "credentials", "fileless_exec", "plugin_load", "delegate", "session_kill"} {
		for _, name := range allowed {
			if name == danger {
				t.Fatalf("危险工具 %s 出现在默认放行集合里", danger)
			}
		}
	}
}

// TestJSONSchemaShape 校验 schema 生成的形状（MCP 与 LLM 共用）。
func TestJSONSchemaShape(t *testing.T) {
	reg := Default()
	var target *ToolDef
	for _, d := range reg.All() {
		if d.Name == "exec" {
			target = d
		}
	}
	if target == nil {
		t.Fatal("注册表里没有 exec 工具")
	}
	schema := target.JSONSchema()
	if schema["type"] != "object" {
		t.Fatalf("schema.type = %v, want object", schema["type"])
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("schema.additionalProperties 必须为 false（拒绝多余参数）")
	}
	props, ok := schema["properties"].(map[string]interface{})
	if !ok || len(props) == 0 {
		t.Fatalf("schema.properties 缺失或为空")
	}
	sid, ok := props["session_id"].(map[string]interface{})
	if !ok {
		t.Fatalf("exec 的 session_id 参数未出现在 schema.properties 里")
	}
	if sid["type"] != "string" {
		t.Fatalf("session_id 类型 = %v, want string", sid["type"])
	}
	if _, hasReq := schema["required"]; !hasReq {
		t.Fatalf("exec 应至少有一个必填参数（session_id），但 schema 里没有 required")
	}
}

// TestResultReadToolExists 大结果回读元工具必须存在且为只读（信封的 handle 约定依赖它）。
func TestResultReadToolExists(t *testing.T) {
	reg := Default()
	d, ok := reg.Get("result_read")
	if !ok {
		t.Fatal("缺少 result_read 元工具：外置结果将无法回读")
	}
	if d.Level != LevelRead {
		t.Fatalf("result_read 等级 = %v, want LevelRead", d.Level)
	}
	names := d.ParamNames()
	want := map[string]bool{"handle": false, "offset": false, "limit": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("result_read 缺少参数 %s", n)
		}
	}
}
