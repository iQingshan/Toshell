package api

import (
	"strings"
	"testing"

	"toshell/internal/server/ai"
	"toshell/internal/server/task"
)

// TestToolTaskTimeoutTable 工具 → 内部任务超时的**单一来源**表。
//
// 这张表把改造前散落在 invokeTool 各 case 里的 60/90/180/300/120 收敛成一处，
// 并同时钉住两件事：
//  1. 同步等待路径的超时值与改造前逐字一致（否则是行为变更，不是重构）；
//  2. 长任务判定所依赖的"预估超时"与该值同源（判定与创建不能各用一套数）。
func TestToolTaskTimeoutTable(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	cases := []struct {
		tool        string
		params      map[string]string
		wantTimeout int
		wantTask    bool
	}{
		{"file_list", map[string]string{"session_id": "s", "path": "/"}, 60, true},
		{"file_download", map[string]string{"session_id": "s", "path": "C:\\a.zip"}, 300, true},
		{"process_list", map[string]string{"session_id": "s"}, 60, true},
		{"process_kill", map[string]string{"session_id": "s", "pid": "4"}, 60, true},
		{"screenshot", map[string]string{"session_id": "s"}, 90, true},
		{"credentials", map[string]string{"session_id": "s"}, 180, true},
		{"fileless_exec", map[string]string{"session_id": "s", "source": "x.bin"}, 180, true},
		{"plugin_load", map[string]string{"session_id": "s", "plugin_id": "p"}, 180, true},
		{"exec", map[string]string{"session_id": "s", "command": "whoami"}, 120, true},
		{"exec", map[string]string{"session_id": "s", "command": "whoami", "timeout_sec": "200"}, 200, true},
		// 超过上限一律截到 300（与改造前 pushAndAwait/execAndAwait 的 clamp 一致）。
		{"exec", map[string]string{"session_id": "s", "command": "whoami", "timeout_sec": "9999"}, 300, true},
		// 非法/非正数 timeout_sec 回落默认 120。
		{"exec", map[string]string{"session_id": "s", "command": "whoami", "timeout_sec": "abc"}, 120, true},
		{"exec", map[string]string{"session_id": "s", "command": "whoami", "timeout_sec": "-1"}, 120, true},
		{"run_command", map[string]string{"session_id": "s", "command": "ipconfig"}, 120, true},
		{"system_info", map[string]string{"session_id": "s"}, 120, true},
		{"check_av", map[string]string{"session_id": "s"}, 120, true},
		// 非任务类工具：isTask=false，且没有超时（不会被长任务判定看中）。
		{"session_list", nil, 0, false},
		{"intel_query", nil, 0, false},
		{"task_wait", map[string]string{"task_id": "1"}, 0, false},
		{"task_submit", map[string]string{"session_id": "s", "command": "x"}, 0, false},
		{"session_kill", map[string]string{"session_id": "s"}, 0, false},
		{"result_read", map[string]string{"handle": "20260927/0011223344556677"}, 0, false},
		{"not_a_tool", nil, 0, false},
	}
	for _, tc := range cases {
		gotTimeout, gotTask := env.s.toolTaskTimeout(tc.tool, tc.params)
		if gotTask != tc.wantTask || gotTimeout != tc.wantTimeout {
			t.Errorf("toolTaskTimeout(%s, %v) = (%d, %v), want (%d, %v)",
				tc.tool, tc.params, gotTimeout, gotTask, tc.wantTimeout, tc.wantTask)
		}
	}
}

// TestTaskToolNamesCovered 任务工具清单必须与超时表一致：
// 清单里每个名字都要被判为任务类工具（否则长任务判定会漏掉它），
// 且非任务工具不得混进来（混进来会让同步路径把只读工具当任务下发）。
func TestTaskToolNamesCovered(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	// 每个工具的最小可用参数（只用于"是否为任务类工具"的判定，不真正创建任务）。
	minParams := map[string]map[string]string{
		"file_list":     {"session_id": "s", "path": "/"},
		"file_download": {"session_id": "s", "path": "/a"},
		"process_list":  {"session_id": "s"},
		"process_kill":  {"session_id": "s", "pid": "1"},
		"screenshot":    {"session_id": "s"},
		"credentials":   {"session_id": "s"},
		"fileless_exec": {"session_id": "s", "source": "x.bin"},
		"plugin_load":   {"session_id": "s", "plugin_id": "p"},
		"exec":          {"session_id": "s", "command": "whoami"},
	}
	for _, name := range taskToolNames {
		params := minParams[name]
		if params == nil {
			params = map[string]string{"session_id": "s", "command": "whoami"}
		}
		if _, ok := env.s.toolTaskTimeout(name, params); !ok {
			t.Errorf("清单里的 %q 未被判定为任务类工具", name)
		}
	}
	// 只读/本地工具绝不能出现在任务工具清单里。
	for _, name := range []string{"session_list", "session_context", "intel_query", "result_read",
		"task_wait", "task_submit", "task_result", "web_search", "tool_list", "playbook_status"} {
		for _, listed := range taskToolNames {
			if listed == name {
				t.Errorf("%q 不该出现在任务工具清单里", name)
			}
		}
	}
}

// TestPlanToolTaskCreatesMatchingTasks 创建入口与超时表一致，且创建出的任务参数与
// 改造前 invokeTool 的各 case 相同（task_type / command / data）。
func TestPlanToolTaskCreatesMatchingTasks(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	cases := []struct {
		tool        string
		params      map[string]string
		wantType    string
		wantCommand string
		wantData    string // 子串
	}{
		{"credentials", map[string]string{"session_id": env.sid, "action": "all"},
			"credentials", "", `"action":"all"`},
		{"screenshot", map[string]string{"session_id": env.sid}, "screenshot", "", ""},
		{"exec", map[string]string{"session_id": env.sid, "command": "whoami"},
			task.TaskTypeCommand, "whoami", ""},
		// exec 带 kind：走内置语义命令（与改造前的 builtinCommand 行为一致）。
		{"exec", map[string]string{"session_id": env.sid, "kind": "user_info"},
			task.TaskTypeCommand, "whoami && whoami /priv && net user", ""},
		{"system_info", map[string]string{"session_id": env.sid},
			task.TaskTypeCommand, "systeminfo", ""},
	}
	for _, tc := range cases {
		plan, ok, err := env.s.planToolTask(tc.tool, tc.params)
		if !ok || err != nil {
			t.Fatalf("planToolTask(%s) = ok=%v err=%v", tc.tool, ok, err)
		}
		if plan.Task == nil {
			t.Fatalf("planToolTask(%s) 未创建任务", tc.tool)
		}
		if plan.Task.TaskType != tc.wantType {
			t.Errorf("%s 任务类型 = %q, want %q", tc.tool, plan.Task.TaskType, tc.wantType)
		}
		if tc.wantCommand != "" && plan.Task.Command != tc.wantCommand {
			t.Errorf("%s 命令 = %q, want %q", tc.tool, plan.Task.Command, tc.wantCommand)
		}
		if tc.wantData != "" && !strings.Contains(plan.Task.Data, tc.wantData) {
			t.Errorf("%s 数据 = %q, 应包含 %q", tc.tool, plan.Task.Data, tc.wantData)
		}
		if plan.Task.Status != task.StatusPending {
			t.Errorf("%s 新建任务状态 = %q, want pending", tc.tool, plan.Task.Status)
		}
		// 超时必须与超时表同源。
		if wantTimeout, _ := env.s.toolTaskTimeout(tc.tool, tc.params); plan.TimeoutSec != wantTimeout {
			t.Errorf("%s 计划超时 %d 与超时表 %d 不一致", tc.tool, plan.TimeoutSec, wantTimeout)
		}
	}

	// 参数缺失时的错误文案（对外错误信息也是契约）。
	if _, ok, err := env.s.planToolTask("file_list", map[string]string{"session_id": env.sid}); !ok || err == nil {
		t.Error("file_list 缺 path 必须报错")
	}
	if _, ok, err := env.s.planToolTask("exec", map[string]string{"session_id": env.sid}); !ok || err == nil {
		t.Error("exec 缺命令必须报错")
	}
	if _, ok, err := env.s.planToolTask("session_list", nil); ok || err != nil {
		t.Error("非任务类工具应返回 ok=false 且无错误")
	}
}

// TestLongTaskDecisionAgainstTimeoutTable 判定表 × 超时表的联合结论：
// 只有"分钟级"工具（≥150s）才挂起，短工具继续同步等——这就是本次改造的分工边界。
func TestLongTaskDecisionAgainstTimeoutTable(t *testing.T) {
	env := newAgentTaskTestEnv(t, false)
	policy := ai.LongTaskPolicy{}
	cases := []struct {
		tool        string
		params      map[string]string
		wantSuspend bool
	}{
		{"credentials", map[string]string{"session_id": env.sid}, true},
		{"file_download", map[string]string{"session_id": env.sid, "path": "/a"}, true},
		{"fileless_exec", map[string]string{"session_id": env.sid, "source": "x.bin"}, true},
		{"plugin_load", map[string]string{"session_id": env.sid, "plugin_id": "p"}, true},
		{"file_list", map[string]string{"session_id": env.sid, "path": "/"}, false},
		{"screenshot", map[string]string{"session_id": env.sid}, false},
		{"process_list", map[string]string{"session_id": env.sid}, false},
		{"exec", map[string]string{"session_id": env.sid, "command": "whoami"}, false},
		{"exec", map[string]string{"session_id": env.sid, "command": "long", "timeout_sec": "180"}, true},
		{"session_list", nil, false},
	}
	for _, tc := range cases {
		timeout, isTask := env.s.LongTaskPlan(tc.tool, tc.params)
		got, reason := ai.ShouldSuspendLongTask(policy, tc.tool, isTask, timeout)
		if got != tc.wantSuspend {
			t.Errorf("%s(timeout=%d, isTask=%v) 挂起判定 = %v (%s), want %v",
				tc.tool, timeout, isTask, got, reason, tc.wantSuspend)
		}
	}
}
