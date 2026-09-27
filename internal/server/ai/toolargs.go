package ai

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ─── LLM 工具参数解析（v1.4.0 S2 修复）────────────────────────────────
//
// 为什么需要这个函数（这是一个被"分页回读"暴露出来的既有 bug）：
//
// 工具 schema 把一批参数声明为 integer（`pid` / `task_id` / `timeout_sec` / `wait_ms` /
// `local_port`，以及结果回读的 `offset` / `limit`）。模型会**按 JSON 数字**给出这些参数
// （`{"handle":"20260927/ab…","offset":8192}`），而历史实现是
//
//	var args map[string]string
//	_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
//
// `map[string]string` 遇到数字会返回 UnmarshalTypeError；错误被 `_ =` 丢弃后，
// **该字段直接丢失**（其余能解析的字段仍在）。后果：
//   - `result_read` 的 offset/limit 永远为 0 → "分页回读"退化成反复读第一页，
//     模型翻不动页（这正是本次增量必须修掉的：外置了却读不回来）；
//   - `process_kill` 的 pid / `task_wait` 的 task_id 等也一并丢失，报"参数缺失"。
//
// 转换口径与 `mcp` 包 buildArgs（对外 MCP 路径的 JSON → map[string]string）保持一致：
// 数字取规范十进制文本、布尔取 true/false、数组用英文逗号连接（invokeTool 侧就是按
// 逗号切分多会话的）、对象整体 JSON 编码、null 视为未提供。
func toolArgs(raw string) map[string]string {
	out := map[string]string{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return out
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		// 少数上游会把参数再包一层字符串（`"{\"a\":1}"`）：尽力再解一层。
		// 仍失败就返回空表，让工具按"缺参数"明确报错 —— 比静默用错参数好排查得多。
		var s string
		if json.Unmarshal([]byte(trimmed), &s) != nil {
			return out
		}
		if json.Unmarshal([]byte(strings.TrimSpace(s)), &m) != nil {
			return out
		}
	}

	for k, v := range m {
		if s, ok := toolArgScalar(v); ok {
			out[k] = s
			continue
		}
		switch t := v.(type) {
		case []interface{}:
			parts := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := toolArgScalar(e); ok {
					parts = append(parts, s)
				}
			}
			out[k] = strings.Join(parts, ",")
		case map[string]interface{}:
			if b, err := json.Marshal(t); err == nil {
				out[k] = string(b)
			}
		}
		// nil（JSON null）与其它无法转换的值一律忽略，等同"未提供"。
	}
	return out
}

// toolArgScalar 把标量转成字符串；非标量返回 ok=false。
func toolArgScalar(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		// 用 -1 精度输出最短表示：8192 而不是 8192.000000（后者会让 Atoi/ParseUint 失败）。
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case json.Number:
		return t.String(), true
	default:
		return "", false
	}
}
