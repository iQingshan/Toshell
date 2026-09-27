package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toshell/internal/common/avops"
	"toshell/internal/server/mcp"
)

// ─── Agent/MCP 侧只暴露 L0（v1.4.0 S6）────────────────────────────────────────
//
// 这是本项最容易悄悄失守的地方：分级入口一旦被"顺手"接进工具面（MCP registry / AI
// function calling / 剧本），模型或外部 MCP 客户端就能直接触发 L1+ 的破坏性动作
// （失明 EDR、结束安全软件、加载内核驱动），而"分级 + 二次确认"的整套设计会被绕过。
//
// 因此这里用**源码扫描 + 注册表扫描**两条腿把它钉住（与 handlers_session_guard_scan_test.go
// 同一风格：把约定变成 CI 能跑的断言，而不是靠评审时的口头承诺）：
//
//	① 注册表扫描：不存在任何"名字等于分级入口 L1+ 动作"的新工具；
//	② 源码扫描：工具面的实现文件（api 的 invokeTool/tool_tasks + mcp + ai）里
//	   不出现任何对分级入口（avops 包 / avopsDispatch / 三个 handler）的引用。
//
// L0 侦察照旧走既有只读/确认级工具（check_av / system_info 等），不受本测试影响。

// frozenSameNameTools 冻结的"与分级入口动作同名、但先于分级入口存在"的工具面。
//
// 为什么允许它存在：`process_kill` 是 v1.4.0 S6 **之前**就有的 MCP 工具（LevelDanger，
// 默认不在白名单、调用需审批），它走的是既有 `DELETE /sessions/{id}/processes/{pid}` 链，
// 与分级入口无关。本次任务的要求是"既有工具面维持现状 + 不给工具面新增破坏性工具"，
// 因此这里把它显式冻结：**新增**任何同名工具都会被用例拦下。
var frozenSameNameTools = map[string]string{
	"process_kill": "既有 MCP 工具（LevelDanger，需审批），走既有 DELETE /processes/{pid} 链，不经过 av-ops 分级入口",
}

// TestAVOpsDestructiveActionsNotInToolRegistry 注册表扫描：L1+ 动作不得成为工具。
func TestAVOpsDestructiveActionsNotInToolRegistry(t *testing.T) {
	reg := mcp.Default()
	registered := map[string]bool{}
	for _, name := range reg.Names() {
		registered[name] = true
	}

	// 逐个 L1+ 动作核对
	for _, a := range avops.Actions() {
		meta := a.Meta()
		if meta.ReadOnly {
			continue // L0 侦察走既有只读工具，不在本测试范围
		}
		if !registered[a.Name] {
			continue
		}
		if why, frozen := frozenSameNameTools[a.Name]; frozen {
			t.Logf("已知既有同名工具 %s：%s", a.Name, why)
			continue
		}
		t.Errorf("工具面出现了与分级入口破坏性动作同名的工具 %q（等级 %s）："+
			"本项要求 Agent/MCP 只暴露 L0，不得让模型/外部客户端直接触发 L1+ 破坏性动作。"+
			"若确需暴露，必须先在此处显式登记并说明二次确认走哪条路径", a.Name, a.Tier)
	}

	// 冻结表本身也要核：写进去的名字必须真的在注册表里（否则冻结表会变成僵尸注释）；
	// 且必须确实对应一个 L1+ 动作（否则是误冻结）。
	for name := range frozenSameNameTools {
		if !registered[name] {
			t.Errorf("冻结表里的 %q 已不在注册表里：请同步删掉该条目（僵尸冻结会掩盖真实变化）", name)
		}
		a, ok := avops.Lookup(name)
		if !ok || a.Meta().ReadOnly {
			t.Errorf("冻结表里的 %q 不是分级入口的 L1+ 动作：冻结它没有意义", name)
		}
	}
}

// TestAVOpsToolFaceDoesNotReferenceTieredEntry 源码扫描：工具面不得引用分级入口。
//
// 扫的是"工具的**实现**文件"（不是 HTTP 层）：只要这些文件里没有任何 avops / av-ops
// 的引用，就不可能存在"某个工具偷偷调用分级入口"的路径。
func TestAVOpsToolFaceDoesNotReferenceTieredEntry(t *testing.T) {
	// 工具面的实现文件（相对本包目录 = internal/server/api）
	files := []string{
		"handlers_mcp.go", // invokeTool：所有工具的实现入口
		"tool_tasks.go",   // 工具 → 内部任务的唯一创建入口（planToolTask）
		"handlers_copilot.go",
		"agent_task_bridge.go",
	}
	// 另外两个包整目录扫描（不能用相对包路径 import，用文件路径扫）
	dirs := []string{
		filepath.Join("..", "mcp"), // 工具元数据唯一来源（注册表）
		filepath.Join("..", "ai"),  // 副驾驶 / Agent / 剧本
	}

	// 禁止出现的引用：分级入口的包名与三个 handler 名，以及 HTTP 路径字面量
	forbidden := []string{
		"internal/common/avops",
		"avops.",
		"avopsDispatch",
		"execAVOpsHandler",
		"sessionAVOpsHandler",
		"listAVOpsHandler",
		"/av-ops",
	}

	check := func(path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", path, err)
		}
		src := string(b)
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				t.Errorf("%s 引用了分级入口（命中 %q）：Agent/MCP 侧不得触达 av-ops，"+
					"否则模型/外部客户端可以绕过分级与二次确认直接下发破坏性动作", path, f)
			}
		}
	}

	scanned := 0
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("工具面源文件不存在：%s（清单过期了？）", f)
		}
		check(filepath.Clean(f))
		scanned++
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatalf("ReadDir %s: %v", d, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			check(filepath.Clean(filepath.Join(d, e.Name())))
			scanned++
		}
	}
	if scanned < 20 {
		t.Fatalf("只扫描到 %d 个源文件，守卫没起作用（目录清单不对？）", scanned)
	}
}

// TestAVOpsL0StaysInExistingReadOnlyTools 钉住"L0 侦察仍然走既有只读工具"这条文档口径：
// check_av / system_info 必须仍在注册表里（否则文档里写的"L0 走既有工具"就成了空话）。
func TestAVOpsL0StaysInExistingReadOnlyTools(t *testing.T) {
	reg := mcp.Default()
	for _, name := range []string{"check_av", "system_info", "process_list"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("既有工具 %q 不在注册表里：文档承诺的「L0 侦察走既有工具」失效", name)
		}
	}
	// check_av 只做检测、不做对抗：必须是 read/confirm 级，绝不能是 danger 级
	// （danger 意味着"不可逆或高风险"，与"只枚举"的语义不符）。
	if lv := reg.LevelOf("check_av"); lv == mcp.LevelDanger {
		t.Errorf("check_av 等级 = %v，但它只做检测（不绕过、不对抗），不应按高危处理", lv)
	}
}
