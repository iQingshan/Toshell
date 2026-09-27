package ai

import (
	"reflect"
	"testing"
)

// TestToolArgsKeepsIntegerParams integer 参数必须以规范十进制文本保留下来。
//
// 这是"分页回读"能不能真正翻页的前提：模型按 JSON 数字给 offset/limit（schema 里就是
// integer），旧实现 json.Unmarshal 到 map[string]string 会因类型不符丢掉该字段，
// 于是 offset 恒为 0，模型永远只能读到第一页。
func TestToolArgsKeepsIntegerParams(t *testing.T) {
	got := toolArgs(`{"handle":"20260927/ab12cd34ef567890","offset":8192,"limit":4096}`)
	want := map[string]string{
		"handle": "20260927/ab12cd34ef567890",
		"offset": "8192",
		"limit":  "4096",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("toolArgs = %#v, want %#v", got, want)
	}
	// 不能输出成 8192.000000：那会让 strconv.Atoi/ParseUint 全部失败。
	if got["offset"] != "8192" {
		t.Fatalf("整数必须是最短十进制文本，实际 %q", got["offset"])
	}
}

// TestToolArgsOtherShapes 字符串/布尔/数组/对象/null 的转换口径。
func TestToolArgsOtherShapes(t *testing.T) {
	got := toolArgs(`{"session_id":"s1","timeout_sec":180,"wait_ms":0,` +
		`"force":true,"session_ids":["s1","s2"],"meta":{"a":1},"nothing":null,"ratio":1.5}`)
	want := map[string]string{
		"session_id":  "s1",
		"timeout_sec": "180",
		"wait_ms":     "0",
		"force":       "true",
		"session_ids": "s1,s2", // invokeTool 侧按逗号切分多会话，必须与服务端口径一致
		"meta":        `{"a":1}`,
		"ratio":       "1.5",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("toolArgs = %#v, want %#v", got, want)
	}
	if _, ok := got["nothing"]; ok {
		t.Fatal("JSON null 应视为未提供")
	}
}

// TestToolArgsDegradesSafely 空/非法/双层编码的输入都不能 panic，也不能编造参数。
func TestToolArgsDegradesSafely(t *testing.T) {
	if got := toolArgs(""); len(got) != 0 {
		t.Fatalf("空串应返回空表，实际 %#v", got)
	}
	if got := toolArgs("null"); len(got) != 0 {
		t.Fatalf("null 应返回空表，实际 %#v", got)
	}
	if got := toolArgs(`{"a":`); len(got) != 0 {
		t.Fatalf("截断的 JSON 应返回空表（让工具按缺参数明确报错），实际 %#v", got)
	}
	// 双层编码（上游把参数再包一层字符串）：尽力解一层。
	if got := toolArgs(`"{\"offset\":16}"`); got["offset"] != "16" {
		t.Fatalf("双层编码应被解开，实际 %#v", got)
	}
}

// TestToolArgsMatchesRegistryIntegerParams 注册表里声明为 integer 的参数，模型给数字后
// 必须真的传到工具层（用几个真实工具名做端到端形状确认）。
func TestToolArgsMatchesRegistryIntegerParams(t *testing.T) {
	got := toolArgs(`{"session_id":"s1","pid":4242}`)
	if got["pid"] != "4242" {
		t.Fatalf("process_kill 的 pid 丢了：%#v", got)
	}
	got = toolArgs(`{"task_id":1024,"timeout_sec":60}`)
	if got["task_id"] != "1024" || got["timeout_sec"] != "60" {
		t.Fatalf("task_wait 的参数丢了：%#v", got)
	}
	got = toolArgs(`{"handle":"20260927/ab12cd34ef567890","mode":"tail","limit":1024}`)
	if got["handle"] == "" || got["mode"] != "tail" || got["limit"] != "1024" {
		t.Fatalf("result_read 的参数丢了：%#v", got)
	}
}
