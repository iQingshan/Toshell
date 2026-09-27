package ai

import (
	"testing"

	"toshell/internal/server/mcp"
)

// TestAgentToolSchemasCoveredByRegistry 保证"对 Agent 暴露的工具"在注册表里都有定义。
// 这条断言防的是最隐蔽的一类回归：注册表改名/漏填 → toolSchemas() 静默少给模型一个工具。
func TestAgentToolSchemasCoveredByRegistry(t *testing.T) {
	reg := mcp.Default()
	for _, name := range agentToolNames {
		if !reg.IsRegistered(name) {
			t.Errorf("Agent 工具 %q 未在工具注册表（internal/server/mcp）登记：模型将看不到它", name)
		}
		if d, ok := reg.Get(name); ok && d.Deprecated {
			t.Errorf("Agent 工具 %q 在注册表里被标记为 Deprecated，但仍列在 agentToolNames 中", name)
		}
	}
	if got, want := len(toolSchemas()), len(agentToolNames); got != want {
		t.Fatalf("toolSchemas() 生成 %d 条，agentToolNames 有 %d 个：有工具从注册表里取不到", got, want)
	}
}

// TestAgentToolSchemasShape schema 必须带上类型化参数（不能是清一色 string + 全必填）。
func TestAgentToolSchemasShape(t *testing.T) {
	for _, s := range toolSchemas() {
		if s.Function.Name == "" || s.Function.Description == "" {
			t.Fatalf("schema 缺少 name/description: %+v", s.Function)
		}
		params := s.Function.Parameters
		if params == nil {
			t.Fatalf("%s 的 parameters 为空", s.Function.Name)
		}
		if params["type"] != "object" {
			t.Fatalf("%s 的 parameters.type != object", s.Function.Name)
		}
		if params["additionalProperties"] != false {
			t.Fatalf("%s 的 parameters 应禁止额外字段", s.Function.Name)
		}
	}
}

// TestIsRiskyToolFailClosed 审批判定的安全默认值：
//   - 影响会话/不可逆的工具必须 risky（含 v1.4.0 修的 `delegate` 越权点）；
//   - 只读工具不 risky；
//   - **未知工具一律 risky**（旧实现是 fail-open，新加的工具会默认免审批）。
func TestIsRiskyToolFailClosed(t *testing.T) {
	mustRisky := []string{
		"delegate", "exec", "run_command", "task_submit", "credentials",
		"fileless_exec", "plugin_load", "process_kill", "session_kill", "screenshot",
	}
	for _, name := range mustRisky {
		if !isRiskyTool(name) {
			t.Errorf("isRiskyTool(%q) = false，但它是影响会话/不可逆的工具，必须需用户同意", name)
		}
	}

	mustFree := []string{"session_list", "session_context", "intel_query", "attack_suggest", "result_read"}
	for _, name := range mustFree {
		if isRiskyTool(name) {
			t.Errorf("isRiskyTool(%q) = true，但它是只读工具，应免审批", name)
		}
	}

	if !isRiskyTool("some_future_tool_not_in_registry") {
		t.Error("未登记的工具必须按危险处理（fail-closed），否则新工具会默认免审批")
	}
}
