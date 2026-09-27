package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ─── 测试基础设施（不依赖真实服务端、不依赖植入端、不碰网络）────────────
//
// 全部用 httptest.NewRecorder + httptest.NewRequest 直接打 Handler，
// 执行能力用 fakeExecutor 注入，结果目录/审计文件用 t.TempDir()。

const testToken = "test-token-0123456789abcdef"

// fakeExecutor 记录调用与参数，返回固定输出。绝不做任何 IO。
type fakeExecutor struct {
	mu    sync.Mutex
	calls []string
	args  []map[string]string
	out   interface{}
	err   error
}

func (f *fakeExecutor) InvokeTool(name string, args map[string]string) (interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	cp := make(map[string]string, len(args))
	for k, v := range args {
		cp[k] = v
	}
	f.args = append(f.args, cp)
	if f.err != nil {
		return nil, f.err
	}
	if f.out == nil {
		return "fixed-output:" + name, nil
	}
	return f.out, nil
}

func (f *fakeExecutor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeExecutor) lastArgs() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.args) == 0 {
		return nil
	}
	return f.args[len(f.args)-1]
}

// testRegistry 覆盖三种风险等级 + 各种参数类型。
func testRegistry() *Registry {
	return NewRegistry([]ToolDef{
		{
			Name:        "sys_info",
			Description: "读取会话与主机基础信息",
			Level:       LevelRead,
			Params:      []Param{{Name: "target", Type: "string", Description: "会话 id"}},
		},
		{
			Name:        "typed_probe",
			Description: "参数类型转换探针",
			Level:       LevelRead,
			Params: []Param{
				{Name: "count", Type: "integer", Required: true, Description: "次数"},
				{Name: "verbose", Type: "boolean", Description: "是否详细"},
				{Name: "tags", Type: "array", Description: "标签列表"},
				{Name: "password", Type: "string", Description: "口令（敏感，用于审计脱敏验证）"},
			},
		},
		{
			Name:        "session_shell",
			Description: "在指定会话下发命令",
			Level:       LevelConfirm,
			Params: []Param{
				{Name: "target", Type: "string", Required: true, Description: "会话 id"},
				{Name: "cmd", Type: "string", Required: true, Description: "命令"},
			},
		},
		{
			Name:        "build_payload",
			Description: "构建载荷",
			Level:       LevelDanger,
			Params:      []Param{{Name: "arch", Type: "string", Required: true, Enum: []string{"x64", "x86"}}},
		},
	})
}

type testEnv struct {
	srv       *Server
	exec      *fakeExecutor
	auditPath string
	dir       string
}

func newTestEnv(t *testing.T, mutate func(*Config)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	exec := &fakeExecutor{}
	cfg := Config{
		Enabled:       true,
		Bind:          "127.0.0.1:0",
		Token:         testToken,
		AllowedTools:  []string{"sys_info", "typed_probe"},
		MaxRPM:        1000,
		MaxConcurrent: 8,
		InlineLimit:   4096,
		ResultDir:     filepath.Join(dir, "results"),
		ResultTTL:     "1h",
		AuditPath:     filepath.Join(dir, "audit.jsonl"),
		Registry:      testRegistry(),
		Logger:        log.New(io.Discard, "", 0),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg, exec)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &testEnv{srv: s, exec: exec, auditPath: cfg.AuditPath, dir: dir}
}

type callOpts struct {
	token     string
	session   string
	omitToken bool
	origin    string
	method    string
	params    interface{}
	id        interface{}
}

// doCall 直接打 Handler（httptest，无真实网络）。
func doCall(t *testing.T, s *Server, o callOpts) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	id := o.id
	if id == nil {
		id = 1
	}
	body := map[string]interface{}{"jsonrpc": "2.0", "method": o.method, "id": id}
	if o.params != nil {
		body["params"] = o.params
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if !o.omitToken {
		tok := o.token
		if tok == "" {
			tok = testToken
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if o.session != "" {
		req.Header.Set(SessionHeader, o.session)
	}
	if o.origin != "" {
		req.Header.Set("Origin", o.origin)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	var decoded map[string]interface{}
	if rr.Body.Len() > 0 {
		if err := json.Unmarshal(rr.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("响应不是合法 JSON: %v；原文=%s", err, rr.Body.String())
		}
	}
	return rr, decoded
}

// initialize 握手拿到会话 id。
func initialize(t *testing.T, s *Server) string {
	t.Helper()
	rr, resp := doCall(t, s, callOpts{
		method: "initialize",
		params: map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"clientInfo":      map[string]interface{}{"name": "claude-desktop", "version": "1.2.3"},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("initialize 期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	sid := rr.Header().Get(SessionHeader)
	if sid == "" {
		t.Fatalf("initialize 未下发 %s 响应头", SessionHeader)
	}
	if resp["error"] != nil {
		t.Fatalf("initialize 不应返回错误: %v", resp["error"])
	}
	return sid
}

func rpcErrObj(t *testing.T, resp map[string]interface{}) map[string]interface{} {
	t.Helper()
	e, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("响应里没有 JSON-RPC error 对象: %v", resp)
	}
	return e
}

// envCode 取 JSON-RPC error.data.code（= envelope.go 的稳定错误码）。
func envCode(t *testing.T, resp map[string]interface{}) string {
	t.Helper()
	e := rpcErrObj(t, resp)
	data, _ := e["data"].(map[string]interface{})
	code, _ := data["code"].(string)
	return code
}

// callTool 走完整 tools/call 流程（自动带会话）。
func callTool(t *testing.T, env *testEnv, sid, name string, args map[string]interface{}) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	params := map[string]interface{}{"name": name}
	if args != nil {
		params["arguments"] = args
	}
	return doCall(t, env.srv, callOpts{session: sid, method: "tools/call", params: params})
}

// envelopeOf 从成功的 tools/call 结果里取统一信封。
func envelopeOf(t *testing.T, resp map[string]interface{}) map[string]interface{} {
	t.Helper()
	if e := resp["error"]; e != nil {
		t.Fatalf("期望成功，实际错误: %v", e)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("响应缺少 result: %v", resp)
	}
	sc, ok := result["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("result 缺少 structuredContent 信封: %v", result)
	}
	return sc
}

func readAuditLines(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计文件失败: %v", err)
	}
	var out []map[string]interface{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("审计行不是合法 JSON: %v；原文=%s", err, line)
		}
		out = append(out, m)
	}
	return out
}

// ─── ① ② 鉴权 ───────────────────────────────────────────────────────

// TestNoTokenUnauthorized ① 未带 token → 401。
func TestNoTokenUnauthorized(t *testing.T) {
	env := newTestEnv(t, nil)
	rr, resp := doCall(t, env.srv, callOpts{omitToken: true, method: "tools/list"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeUnauthorized {
		t.Fatalf("期望信封码 %s，实际 %s", CodeUnauthorized, got)
	}
	// JSON-RPC 错误码也要给（-32001）。
	if code, _ := rpcErrObj(t, resp)["code"].(float64); int(code) != rpcCodeUnauth {
		t.Fatalf("期望 JSON-RPC code %d，实际 %v", rpcCodeUnauth, rpcErrObj(t, resp)["code"])
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("401 应带 WWW-Authenticate 头")
	}
	if len(env.exec.calls) != 0 {
		t.Fatalf("未鉴权请求不应触达 Executor")
	}
}

// TestWrongTokenUnauthorized ② token 错 → 401（且不泄漏"长度对不对"）。
func TestWrongTokenUnauthorized(t *testing.T) {
	env := newTestEnv(t, nil)
	for _, bad := range []string{"wrong-token", testToken + "x", strings.ToUpper(testToken)} {
		rr, resp := doCall(t, env.srv, callOpts{token: bad, method: "tools/list"})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("token=%q 期望 401，实际 %d", bad, rr.Code)
		}
		if got := envCode(t, resp); got != CodeUnauthorized {
			t.Fatalf("token=%q 期望信封码 %s，实际 %s", bad, CodeUnauthorized, got)
		}
	}
	// X-MCP-Token 也是合法通道。
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("X-MCP-Token", testToken)
	rr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("X-MCP-Token 通道期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
}

// TestEnvTokenIsNotACredentialSource 环境变量不是凭据来源（t.Setenv）。
func TestEnvTokenIsNotACredentialSource(t *testing.T) {
	t.Setenv("TOSHELL_MCP_TOKEN", testToken)
	env := newTestEnv(t, nil)
	rr, resp := doCall(t, env.srv, callOpts{omitToken: true, method: "tools/list"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("环境变量不应让请求通过鉴权：期望 401，实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeUnauthorized {
		t.Fatalf("期望 %s，实际 %s", CodeUnauthorized, got)
	}
}

// TestNewRefusesWithoutToken 未配置 token 时拒绝启动（fail-closed）。
func TestNewRefusesWithoutToken(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:   true,
		Token:     "",
		ResultDir: filepath.Join(dir, "r"),
		AuditPath: filepath.Join(dir, "a.jsonl"),
		Registry:  testRegistry(),
		Logger:    log.New(io.Discard, "", 0),
	}
	if _, err := New(cfg, &fakeExecutor{}); err == nil {
		t.Fatalf("enabled=true 且无 token 时必须拒绝启动")
	}
	// FailClosed=false 也不能放宽 token 必填。
	cfg.FailClosed = false
	if _, err := New(cfg, &fakeExecutor{}); err == nil {
		t.Fatalf("fail_closed=false 时同样不允许无 token 启动")
	}
}

// TestOriginAllowlist 默认拒绝跨域 Origin，放行同源/无 Origin。
func TestOriginAllowlist(t *testing.T) {
	env := newTestEnv(t, nil)

	rr, resp := doCall(t, env.srv, callOpts{method: "initialize", origin: "http://evil.example"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("跨域 Origin 期望 403，实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeForbidden {
		t.Fatalf("期望 %s，实际 %s", CodeForbidden, got)
	}

	// 同源：httptest.NewRequest 的 Host 是 example.com。
	if rr, _ := doCall(t, env.srv, callOpts{method: "initialize", origin: "http://example.com"}); rr.Code != http.StatusOK {
		t.Fatalf("同源 Origin 期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	// 显式白名单。
	env2 := newTestEnv(t, func(c *Config) { c.AllowedOrigins = []string{"https://console.example.com"} })
	if rr, _ := doCall(t, env2.srv, callOpts{method: "initialize", origin: "https://console.example.com"}); rr.Code != http.StatusOK {
		t.Fatalf("白名单 Origin 期望 200，实际 %d", rr.Code)
	}
	// Origin: null 默认拒绝。
	if rr, _ := doCall(t, env.srv, callOpts{method: "initialize", origin: "null"}); rr.Code != http.StatusForbidden {
		t.Fatalf("Origin: null 期望 403，实际 %d", rr.Code)
	}
}

// TestCIDRAllowlist allow_cidrs 生效：不在网段按未认证处理。
func TestCIDRAllowlist(t *testing.T) {
	env := newTestEnv(t, func(c *Config) { c.AllowedCIDRs = []string{"10.0.0.0/8"} })
	// httptest.NewRequest 的 RemoteAddr 是 192.0.2.1:1234。
	rr, resp := doCall(t, env.srv, callOpts{method: "initialize"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeUnauthorized {
		t.Fatalf("期望 %s，实际 %s", CodeUnauthorized, got)
	}
	// 合法网段内放行。
	env2 := newTestEnv(t, func(c *Config) { c.AllowedCIDRs = []string{"192.0.2.0/24"} })
	if rr, _ := doCall(t, env2.srv, callOpts{method: "initialize"}); rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rr.Code)
	}
}

// ─── ③ tools/list 与注册表一致 ──────────────────────────────────────

func TestToolsListMatchesRegistry(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	rr, resp := doCall(t, env.srv, callOpts{session: sid, method: "tools/list"})
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list 期望 200，实际 %d", rr.Code)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("tools/list 缺少 result: %v", resp)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("tools/list 缺少 tools 数组: %v", result)
	}

	reg := env.srv.Registry()
	if len(tools) != len(reg.All()) {
		t.Fatalf("工具数不一致：服务端 %d，注册表 %d", len(tools), len(reg.All()))
	}

	seen := map[string]bool{}
	for _, raw := range tools {
		tool := raw.(map[string]interface{})
		name, _ := tool["name"].(string)
		seen[name] = true
		def, ok := reg.Get(name)
		if !ok {
			t.Fatalf("tools/list 出现了注册表里没有的工具: %s", name)
		}
		// inputSchema 必须与注册表派生的 schema 逐字节一致（唯一来源校验）。
		wantSchema, _ := json.Marshal(def.JSONSchema())
		gotSchema, _ := json.Marshal(tool["inputSchema"])
		if string(wantSchema) != string(gotSchema) {
			t.Fatalf("工具 %s 的 inputSchema 与注册表不一致:\n got=%s\nwant=%s", name, gotSchema, wantSchema)
		}
		if desc, _ := tool["description"].(string); desc != def.Description {
			t.Fatalf("工具 %s 描述与注册表不一致", name)
		}
		meta, _ := tool["_meta"].(map[string]interface{})
		if lv, _ := meta["toshell/level"].(string); lv != def.Level.String() {
			t.Fatalf("工具 %s 分级不一致: got=%v want=%s", name, meta["toshell/level"], def.Level.String())
		}
	}
	for _, n := range reg.Names() {
		if !seen[n] {
			t.Fatalf("注册表里的工具 %s 没有出现在 tools/list", n)
		}
	}

	// 具体 schema 断言（避免"两边都调 JSONSchema 所以恒等"的空转）：
	// typed_probe.count 是必填 integer、additionalProperties=false。
	var probe map[string]interface{}
	for _, raw := range tools {
		if tool := raw.(map[string]interface{}); tool["name"] == "typed_probe" {
			probe = tool
		}
	}
	if probe == nil {
		t.Fatalf("tools/list 里缺少 typed_probe")
	}
	schema := probe["inputSchema"].(map[string]interface{})
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("inputSchema 基本形状不对: %v", schema)
	}
	required, _ := schema["required"].([]interface{})
	if len(required) != 1 || required[0] != "count" {
		t.Fatalf("typed_probe 的 required 应为 [count]，实际 %v", required)
	}
	props := schema["properties"].(map[string]interface{})
	if props["count"].(map[string]interface{})["type"] != "integer" {
		t.Fatalf("count 应为 integer: %v", props["count"])
	}
	if props["tags"].(map[string]interface{})["type"] != "array" {
		t.Fatalf("tags 应为 array: %v", props["tags"])
	}
	ann, _ := probe["annotations"].(map[string]interface{})
	if ann["readOnlyHint"] != true {
		t.Fatalf("LevelRead 工具应带 readOnlyHint=true: %v", ann)
	}
}

// ─── ④ 未注册工具 ───────────────────────────────────────────────────

func TestUnregisteredToolForbidden(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	rr, resp := callTool(t, env, sid, "totally_made_up_tool", map[string]interface{}{"x": "1"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("未注册工具期望 403，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if got := envCode(t, resp); got != CodeNotAllowed {
		t.Fatalf("期望信封码 %s，实际 %s", CodeNotAllowed, got)
	}
	if code, _ := rpcErrObj(t, resp)["code"].(float64); int(code) != rpcCodeForbidden {
		t.Fatalf("期望 JSON-RPC code %d，实际 %v", rpcCodeForbidden, rpcErrObj(t, resp)["code"])
	}
	// 错误响应必须能按 `error.data.envelope.error.code` 取值
	// （scripts/mcp_smoke.ps1 与前端都按这个路径读稳定错误码）。
	data, _ := rpcErrObj(t, resp)["data"].(map[string]interface{})
	envObj, ok := data["envelope"].(map[string]interface{})
	if !ok {
		t.Fatalf("error.data.envelope 缺失: %v", data)
	}
	errObj, _ := envObj["error"].(map[string]interface{})
	if errObj == nil || errObj["code"] != CodeNotAllowed {
		t.Fatalf("envelope.error.code 应为 %s，实际 %v", CodeNotAllowed, envObj["error"])
	}
	if env.exec.callCount() != 0 {
		t.Fatalf("未注册工具绝不能触达 Executor")
	}
}

// ─── ⑤ 未在白名单的工具 ─────────────────────────────────────────────

func TestToolNotWhitelistedNeedsConsent(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	for _, tc := range []struct {
		tool string
		args map[string]interface{}
		code string
	}{
		{"session_shell", map[string]interface{}{"target": "s1", "cmd": "whoami"}, CodeNeedsConsent},
		{"build_payload", map[string]interface{}{"arch": "x64"}, CodeNeedsConsent},
	} {
		rr, resp := callTool(t, env, sid, tc.tool, tc.args)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s 未在白名单期望 403，实际 %d（%s）", tc.tool, rr.Code, rr.Body.String())
		}
		if got := envCode(t, resp); got != tc.code {
			t.Fatalf("%s 期望 %s，实际 %s", tc.tool, tc.code, got)
		}
	}
	if env.exec.callCount() != 0 {
		t.Fatalf("未获审批的工具绝不能触达 Executor")
	}

	// 白名单 = 预授权：显式放行后同样的调用直接执行。
	env2 := newTestEnv(t, func(c *Config) {
		c.AllowedTools = []string{"sys_info", "typed_probe", "session_shell"}
	})
	sid2 := initialize(t, env2.srv)
	rr, resp := callTool(t, env2, sid2, "session_shell", map[string]interface{}{"target": "s1", "cmd": "whoami"})
	if rr.Code != http.StatusOK {
		t.Fatalf("白名单内工具期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if env2.exec.callCount() != 1 {
		t.Fatalf("白名单内工具应执行 1 次，实际 %d", env2.exec.callCount())
	}
	if got := envelopeOf(t, resp)["status"]; got != StatusOK {
		t.Fatalf("信封 status 应为 ok，实际 %v", got)
	}
}

// TestConsentGateExtension 审批门扩展点：注入放行门后，未白名单工具也能执行。
func TestConsentGateExtension(t *testing.T) {
	env := newTestEnv(t, nil)
	env.srv.SetConsentGate(allowAllGate{})
	sid := initialize(t, env.srv)

	rr, resp := callTool(t, env, sid, "build_payload", map[string]interface{}{"arch": "x64"})
	if rr.Code != http.StatusOK {
		t.Fatalf("审批门放行后期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if got := envelopeOf(t, resp)["status"]; got != StatusOK {
		t.Fatalf("信封 status 应为 ok，实际 %v", got)
	}
}

type allowAllGate struct{}

func (allowAllGate) Allow(context.Context, ConsentRequest) error { return nil }

// ─── ⑥ 限流 ─────────────────────────────────────────────────────────

// TestRateLimitRPM 闸 1：RPM 滑动窗口 → 429 + rate_limited。
//
// 注意：闸 1 是**请求级**的（每个 JSON-RPC 请求都计数，含 initialize/ping），
// 所以 MaxRPM=3 时配额被 initialize + 2 次 tools/call 用满。
func TestRateLimitRPM(t *testing.T) {
	env := newTestEnv(t, func(c *Config) { c.MaxRPM = 3; c.MaxConcurrent = 8 })
	sid := initialize(t, env.srv) // 消耗 1 次 RPM

	for i := 0; i < 2; i++ {
		rr, _ := callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})
		if rr.Code != http.StatusOK {
			t.Fatalf("第 %d 次调用期望 200，实际 %d", i+1, rr.Code)
		}
	}
	rr, resp := callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("超 RPM 期望 429，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if got := envCode(t, resp); got != CodeRateLimited {
		t.Fatalf("期望信封码 %s，实际 %s", CodeRateLimited, got)
	}
	if code, _ := rpcErrObj(t, resp)["code"].(float64); int(code) != rpcCodeRateLimit {
		t.Fatalf("期望 JSON-RPC code %d，实际 %v", rpcCodeRateLimit, rpcErrObj(t, resp)["code"])
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatalf("429 应带 Retry-After 头")
	}
	if env.exec.callCount() != 2 {
		t.Fatalf("被限流的调用不应触达 Executor：实际执行 %d 次", env.exec.callCount())
	}

	// 闸 1 覆盖所有 JSON-RPC 请求：ping 同样会被限流
	// （scripts/mcp_smoke.ps1 就是连打 ping 来验限流的）。
	prr, presp := doCall(t, env.srv, callOpts{method: "ping", session: sid})
	if prr.Code != http.StatusTooManyRequests {
		t.Fatalf("ping 超 RPM 期望 429，实际 %d", prr.Code)
	}
	if got := envCode(t, presp); got != CodeRateLimited {
		t.Fatalf("ping 期望 %s，实际 %s", CodeRateLimited, got)
	}
}

// TestRateLimitConcurrent 闸 2：最大并发（用阻塞 Executor 占住槽位）。
func TestRateLimitConcurrent(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	env := newTestEnv(t, func(c *Config) { c.MaxRPM = 100; c.MaxConcurrent = 1 })
	env.srv.exec = blockingExecutor{started: started, release: release}
	sid := initialize(t, env.srv)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{"target":"s1"}}}`))
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set(SessionHeader, sid)
		rr := httptest.NewRecorder()
		env.srv.Handler().ServeHTTP(rr, req)
		done <- rr
	}()
	<-started // 第一个调用已占住并发槽

	rr, resp := callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("并发超限期望 429，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if got := envCode(t, resp); got != CodeRateLimited {
		t.Fatalf("期望 %s，实际 %s", CodeRateLimited, got)
	}
	close(release)
	if first := <-done; first.Code != http.StatusOK {
		t.Fatalf("被占住的第一个调用期望 200，实际 %d", first.Code)
	}
}

type blockingExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (b blockingExecutor) InvokeTool(string, map[string]string) (interface{}, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	return "released", nil
}

// TestRateLimitPendingHandles 闸 3：挂起结果句柄数超限 → 429。
func TestRateLimitPendingHandles(t *testing.T) {
	big := strings.Repeat("A", 512)
	env := newTestEnv(t, func(c *Config) {
		c.MaxRPM = 100
		c.MaxConcurrent = 8
		c.InlineLimit = 32      // 结果一定被外置
		c.MaxPendingHandles = 2 // 闸 3 上限
	})
	env.exec.out = big
	sid := initialize(t, env.srv)

	for i := 0; i < 2; i++ {
		rr, resp := callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})
		if rr.Code != http.StatusOK {
			t.Fatalf("第 %d 次期望 200，实际 %d（%s）", i+1, rr.Code, rr.Body.String())
		}
		meta := envelopeOf(t, resp)["meta"].(map[string]interface{})
		if h, _ := meta["handle"].(string); h == "" {
			t.Fatalf("超限结果应外置并返回 handle: %v", meta)
		}
		if meta["truncated"] != true {
			t.Fatalf("外置结果必须显式标注 truncated: %v", meta)
		}
	}
	rr, resp := callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("挂起句柄超限期望 429，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if got := envCode(t, resp); got != CodeRateLimited {
		t.Fatalf("期望 %s，实际 %s", CodeRateLimited, got)
	}
	if env.exec.callCount() != 2 {
		t.Fatalf("被闸 3 拦下的调用不应触达 Executor：实际 %d", env.exec.callCount())
	}
}

// ─── ⑦ resources/read 非法句柄 ──────────────────────────────────────

func TestResourceReadRejectsBadHandles(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	badURIs := []string{
		"toshell://result/../../etc/passwd",          // 路径穿越
		"toshell://result/20260101/../../../secret",  // 路径穿越（带日期前缀）
		"toshell://result/20260101/..%2f..%2fsecret", // URL 编码穿越
		"toshell://result/20260101/short",            // 非 hex / 长度不足
		"toshell://result/20260101/ABCDEF0123456789", // 大写 hex 不在白名单
		"toshell://result/C:\\Windows\\win.ini",      // 绝对路径
		"toshell://result/",                          // 空句柄
		"http://evil.example/result/20260101/abcdef", // 非法 scheme
		"file:///etc/passwd",                         // 非法 scheme
	}
	for _, uri := range badURIs {
		rr, resp := doCall(t, env.srv, callOpts{
			session: sid, method: "resources/read",
			params: map[string]interface{}{"uri": uri},
		})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("uri=%q 期望 403，实际 %d（%s）", uri, rr.Code, rr.Body.String())
		}
		if got := envCode(t, resp); got != CodeForbidden {
			t.Fatalf("uri=%q 期望信封码 %s，实际 %s", uri, CodeForbidden, got)
		}
	}

	// 格式合法但不存在 → 200 + not_found（不是越权）。
	rr, resp := doCall(t, env.srv, callOpts{
		session: sid, method: "resources/read",
		params: map[string]interface{}{"uri": "toshell://result/20260101/0123456789abcdef"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("不存在的句柄期望 200（JSON-RPC 层承载 not_found），实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeNotFound {
		t.Fatalf("期望 %s，实际 %s", CodeNotFound, got)
	}
}

// TestResourceReadPagination 合法句柄分页回读 + 读完释放句柄配额。
func TestResourceReadPagination(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	payload := strings.Repeat("0123456789", 10) // 100 字节
	handle, _, err := env.srv.store.Put("test", []byte(payload))
	if err != nil {
		t.Fatalf("写入结果存储失败: %v", err)
	}
	env.srv.limit.NoteHandle(env.srv.auth.TokenID(), handle)

	uri := uriResultPrefix + handle
	rr, resp := doCall(t, env.srv, callOpts{
		session: sid, method: "resources/read",
		params: map[string]interface{}{"uri": uri, "limit": 30},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	result := resp["result"].(map[string]interface{})
	contents := result["contents"].([]interface{})
	first := contents[0].(map[string]interface{})["text"].(string)
	if first != payload[:30] {
		t.Fatalf("第一页内容不对: %q", first)
	}
	cursor, _ := result["nextCursor"].(string)
	if cursor == "" {
		t.Fatalf("未读完必须给 nextCursor: %v", result)
	}

	// 用 cursor 续读，直到读完。
	got := first
	for cursor != "" {
		rr, resp = doCall(t, env.srv, callOpts{
			session: sid, method: "resources/read",
			params: map[string]interface{}{"uri": uri, "cursor": cursor, "limit": 30},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("续读期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
		}
		result = resp["result"].(map[string]interface{})
		got += result["contents"].([]interface{})[0].(map[string]interface{})["text"].(string)
		cursor, _ = result["nextCursor"].(string)
	}
	if got != payload {
		t.Fatalf("分页拼接后内容不一致：got=%d bytes want=%d bytes", len(got), len(payload))
	}
	if n := env.srv.limit.PendingHandles(env.srv.auth.TokenID()); n != 0 {
		t.Fatalf("读完后应释放句柄配额，实际仍挂起 %d 个", n)
	}

	// 非法 cursor 也要拒绝。
	rr, resp = doCall(t, env.srv, callOpts{
		session: sid, method: "resources/read",
		params: map[string]interface{}{"uri": uri, "cursor": "!!!not-base64!!!"},
	})
	if rr.Code != http.StatusOK || envCode(t, resp) != CodeBadRequest {
		t.Fatalf("非法 cursor 期望 200+bad_request，实际 %d/%v", rr.Code, resp)
	}
}

// ─── ⑧ 会话头 ───────────────────────────────────────────────────────

func TestSessionRequired(t *testing.T) {
	env := newTestEnv(t, nil)

	// 缺失 → 400。
	rr, resp := doCall(t, env.srv, callOpts{method: "tools/list"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("缺会话期望 400，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	if code, _ := rpcErrObj(t, resp)["code"].(float64); int(code) != rpcCodeSession {
		t.Fatalf("期望 JSON-RPC code %d，实际 %v", rpcCodeSession, rpcErrObj(t, resp)["code"])
	}

	// 错误 → 400。
	rr, resp = doCall(t, env.srv, callOpts{method: "tools/list", session: "deadbeefdeadbeef"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("错误会话期望 400，实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeBadRequest {
		t.Fatalf("期望 %s，实际 %s", CodeBadRequest, got)
	}

	// 正确 → 200，且 initialize 本身不需要会话。
	sid := initialize(t, env.srv)
	if rr, _ := doCall(t, env.srv, callOpts{method: "tools/list", session: sid}); rr.Code != http.StatusOK {
		t.Fatalf("正确会话期望 200，实际 %d", rr.Code)
	}

	// ping 与 notifications/initialized。
	if _, resp := doCall(t, env.srv, callOpts{method: "ping", session: sid}); resp["result"] == nil {
		t.Fatalf("ping 应返回空 result: %v", resp)
	}
	note := map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"}
	raw, _ := json.Marshal(note)
	nreq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(raw))
	nreq.Header.Set("Authorization", "Bearer "+testToken)
	nreq.Header.Set(SessionHeader, sid)
	nrr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(nrr, nreq)
	if nrr.Code != http.StatusAccepted {
		t.Fatalf("通知期望 202，实际 %d", nrr.Code)
	}
	if nrr.Body.Len() != 0 {
		t.Fatalf("通知不得有响应体，实际 %q", nrr.Body.String())
	}

	// DELETE 结束会话 → 204，之后同一会话 400。
	dreq := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	dreq.Header.Set("Authorization", "Bearer "+testToken)
	dreq.Header.Set(SessionHeader, sid)
	drr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(drr, dreq)
	if drr.Code != http.StatusNoContent {
		t.Fatalf("DELETE 期望 204，实际 %d", drr.Code)
	}
	if rr, _ := doCall(t, env.srv, callOpts{method: "tools/list", session: sid}); rr.Code != http.StatusBadRequest {
		t.Fatalf("会话结束后期望 400，实际 %d", rr.Code)
	}
}

// TestInitializeCapabilities 握手结果形状。
func TestInitializeCapabilities(t *testing.T) {
	env := newTestEnv(t, nil)
	rr, resp := doCall(t, env.srv, callOpts{
		method: "initialize",
		params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"clientInfo":      map[string]interface{}{"name": "cursor", "version": "0.42"},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rr.Code)
	}
	result := resp["result"].(map[string]interface{})
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("应回显受支持的客户端版本，实际 %v", result["protocolVersion"])
	}
	caps := result["capabilities"].(map[string]interface{})
	tools := caps["tools"].(map[string]interface{})
	if tools["listChanged"] != false {
		t.Fatalf("tools.listChanged 应为 false: %v", tools)
	}
	if _, ok := caps["resources"].(map[string]interface{}); !ok {
		t.Fatalf("capabilities 必须包含 resources: %v", caps)
	}
	info := result["serverInfo"].(map[string]interface{})
	if info["name"] != ServerName || info["version"] != ServerVersion {
		t.Fatalf("serverInfo 不对: %v", info)
	}
	// 未支持的版本 → 回退到服务端最新版本。
	_, resp2 := doCall(t, env.srv, callOpts{method: "initialize", params: map[string]interface{}{"protocolVersion": "1999-01-01"}})
	if got := resp2["result"].(map[string]interface{})["protocolVersion"]; got != LatestProtocolVersion {
		t.Fatalf("未支持版本应回退 %s，实际 %v", LatestProtocolVersion, got)
	}
}

// ─── 参数转换 / 信封 / 审计 ─────────────────────────────────────────

func TestArgsTypeConversionAndEnvelope(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	rr, resp := callTool(t, env, sid, "typed_probe", map[string]interface{}{
		"count":    42,
		"verbose":  true,
		"tags":     []interface{}{"a", "b", "c"},
		"password": "s3cr3t-value",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	env0 := envelopeOf(t, resp)
	if env0["status"] != StatusOK {
		t.Fatalf("信封 status 应为 ok: %v", env0)
	}
	meta := env0["meta"].(map[string]interface{})
	if meta["untrusted"] != true {
		t.Fatalf("信封 meta.untrusted 必须为 true: %v", meta)
	}
	// result.envelope 别名（项目内约定字段名，scripts/mcp_smoke.ps1 读它）。
	result := resp["result"].(map[string]interface{})
	alias, ok := result["envelope"].(map[string]interface{})
	if !ok {
		t.Fatalf("result.envelope 缺失: %v", result)
	}
	if alias["status"] != StatusOK {
		t.Fatalf("result.envelope.status 应为 ok: %v", alias)
	}
	if _, ok := result["structuredContent"].(map[string]interface{}); !ok {
		t.Fatalf("result.structuredContent（MCP 规范字段）缺失: %v", result)
	}

	// integer/boolean/array → map[string]string（array 用逗号连接）。
	args := env.exec.lastArgs()
	if args["count"] != "42" {
		t.Fatalf("integer 转换错误: %q", args["count"])
	}
	if args["verbose"] != "true" {
		t.Fatalf("boolean 转换错误: %q", args["verbose"])
	}
	if args["tags"] != "a,b,c" {
		t.Fatalf("array 应逗号连接: %q", args["tags"])
	}
	if args["password"] != "s3cr3t-value" {
		t.Fatalf("string 应原样透传: %q", args["password"])
	}

	// 缺必填 / 未知参数 / 类型不符 → 200 + bad_request（业务错误走 JSON-RPC 层）。
	for name, tc := range map[string]map[string]interface{}{
		"缺必填":   {"verbose": true},
		"未知参数":  {"count": 1, "nope": "x"},
		"类型不符":  {"count": "not-a-number"},
		"小数当整数": {"count": 1.5},
	} {
		rr, resp := callTool(t, env, sid, "typed_probe", tc)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s 期望 200，实际 %d", name, rr.Code)
		}
		if got := envCode(t, resp); got != CodeBadRequest {
			t.Fatalf("%s 期望 %s，实际 %s", name, CodeBadRequest, got)
		}
	}
}

func TestExecutorErrorIsUpstreamError(t *testing.T) {
	env := newTestEnv(t, nil)
	env.exec.err = errFake("implant offline")
	sid := initialize(t, env.srv)

	rr, resp := callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("执行失败仍是业务错误，HTTP 期望 200，实际 %d", rr.Code)
	}
	if got := envCode(t, resp); got != CodeUpstream {
		t.Fatalf("期望信封码 %s，实际 %s", CodeUpstream, got)
	}
	// JSON-RPC 错误里也要能拿到 MCP 形状的结果。
	data := rpcErrObj(t, resp)["data"].(map[string]interface{})
	if _, ok := data["result"].(map[string]interface{}); !ok {
		t.Fatalf("error.data.result 应带 MCP 工具结果: %v", data)
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }

// TestAuditRedactsArgs 审计字段齐全、参数不落原文、敏感值完全脱敏。
func TestAuditRedactsArgs(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	if _, resp := callTool(t, env, sid, "typed_probe", map[string]interface{}{
		"count":    7,
		"verbose":  false,
		"tags":     []interface{}{"x"},
		"password": "SUPER-SECRET-PASSWORD",
	}); resp == nil {
		t.Fatalf("调用失败")
	}
	if _, resp := callTool(t, env, sid, "not_registered", nil); resp == nil {
		t.Fatalf("调用失败")
	}

	raw, err := os.ReadFile(env.auditPath)
	if err != nil {
		t.Fatalf("审计文件不存在: %v", err)
	}
	if strings.Contains(string(raw), "SUPER-SECRET-PASSWORD") {
		t.Fatalf("审计里出现了参数原文（凭据泄漏）")
	}
	lines := readAuditLines(t, env.auditPath)
	if len(lines) < 2 {
		t.Fatalf("期望至少 2 条审计，实际 %d", len(lines))
	}

	var okLine, denyLine map[string]interface{}
	for _, l := range lines {
		switch l["tool"] {
		case "typed_probe":
			okLine = l
		case "not_registered":
			denyLine = l
		}
	}
	if okLine == nil || denyLine == nil {
		t.Fatalf("审计缺少预期记录: %v", lines)
	}

	// 字段齐全（14 个）。
	for _, k := range []string{"ts", "call_id", "tool", "level", "args_digest", "args_keys",
		"status", "error_code", "duration_ms", "remote_addr", "client", "token_id",
		"result_bytes", "truncated"} {
		if _, ok := okLine[k]; !ok {
			t.Fatalf("审计缺字段 %q: %v", k, okLine)
		}
	}
	if okLine["level"] != "read" || okLine["status"] != "ok" {
		t.Fatalf("审计 level/status 不对: %v", okLine)
	}
	keys, _ := okLine["args_keys"].([]interface{})
	if len(keys) != 4 {
		t.Fatalf("args_keys 应记录参数名: %v", okLine["args_keys"])
	}
	digest, _ := okLine["args_digest"].(string)
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+16 {
		t.Fatalf("args_digest 形状不对: %q", digest)
	}
	if c, _ := okLine["client"].(string); c != "claude-desktop/1.2.3" {
		t.Fatalf("client 应为 initialize 上报的客户端: %q", c)
	}
	if tid, _ := okLine["token_id"].(string); !strings.HasPrefix(tid, "tok_") {
		t.Fatalf("token_id 应为令牌指纹: %q", tid)
	}
	if denyLine["error_code"] != CodeNotAllowed {
		t.Fatalf("被拒调用的审计 error_code 应为 %s: %v", CodeNotAllowed, denyLine)
	}
	if denyLine["status"] != StatusError {
		t.Fatalf("被拒调用审计 status 应为 error: %v", denyLine)
	}

	// 同一参数、只改敏感值 → 摘要不变（证明敏感值没进摘要）。
	before := ArgsDigest(map[string]string{"password": "a", "target": "s1"})
	after := ArgsDigest(map[string]string{"password": "b", "target": "s1"})
	if before != after {
		t.Fatalf("敏感参数值不应影响摘要: %s vs %s", before, after)
	}
	// 非敏感值不同 → 摘要不同。
	if ArgsDigest(map[string]string{"target": "s1"}) == ArgsDigest(map[string]string{"target": "s2"}) {
		t.Fatalf("非敏感参数变化必须改变摘要")
	}
}

// TestAuditSinkMirror 审计镜像回调（DB 由上层注入）。
func TestAuditSinkMirror(t *testing.T) {
	env := newTestEnv(t, nil)
	sink := &memSink{}
	env.srv.SetAuditSink(sink)
	sid := initialize(t, env.srv)
	callTool(t, env, sid, "sys_info", map[string]interface{}{"target": "s1"})

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.records) != 1 {
		t.Fatalf("期望镜像 1 条审计，实际 %d", len(sink.records))
	}
	if sink.records[0].Tool != "sys_info" {
		t.Fatalf("镜像记录工具名不对: %+v", sink.records[0])
	}
}

type memSink struct {
	mu      sync.Mutex
	records []AuditRecord
}

func (m *memSink) WriteMCPAudit(rec AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	return nil
}

// ─── 端点杂项 ───────────────────────────────────────────────────────

func TestEndpointRouting(t *testing.T) {
	env := newTestEnv(t, nil)

	// 非 /mcp 路径 → 404（不暴露别的入口）。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tools", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("非 MCP 路径期望 404，实际 %d", rr.Code)
	}

	// 不支持的方法 → 405。
	patch := httptest.NewRequest(http.MethodPatch, "/mcp", nil)
	patch.Header.Set("Authorization", "Bearer "+testToken)
	prr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(prr, patch)
	if prr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH 期望 405，实际 %d", prr.Code)
	}

	// 非法 JSON → 400（协议层错误）。
	bad := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{not json"))
	bad.Header.Set("Authorization", "Bearer "+testToken)
	brr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(brr, bad)
	if brr.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 期望 400，实际 %d", brr.Code)
	}

	// 未知方法（已初始化会话）→ JSON-RPC -32601，HTTP 200。
	sid := initialize(t, env.srv)
	rr, resp := doCall(t, env.srv, callOpts{method: "logging/setLevel", session: sid})
	if rr.Code != http.StatusOK {
		t.Fatalf("未知方法期望 HTTP 200，实际 %d", rr.Code)
	}
	if code, _ := rpcErrObj(t, resp)["code"].(float64); int(code) != rpcCodeMethodNotFound {
		t.Fatalf("期望 -32601，实际 %v", rpcErrObj(t, resp)["code"])
	}
}

func TestBatchRequest(t *testing.T) {
	env := newTestEnv(t, nil)
	sid := initialize(t, env.srv)

	body := `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sys_info","arguments":{"target":"s1"}}}]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set(SessionHeader, sid)
	rr := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("批处理期望 200，实际 %d（%s）", rr.Code, rr.Body.String())
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("批处理响应应为数组: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("期望 2 条响应，实际 %d", len(list))
	}
}

func TestStoreDirCreated(t *testing.T) {
	env := newTestEnv(t, nil)
	if _, err := os.Stat(filepath.Join(env.dir, "results")); err != nil {
		t.Fatalf("结果目录应已创建: %v", err)
	}
	if _, err := os.Stat(env.auditPath); err != nil {
		t.Fatalf("审计文件应已创建: %v", err)
	}
	// 未配置 CIDR / Origin 白名单时不限制来源。
	if env.srv.auth.TokenID() == "" {
		t.Fatalf("token_id 不应为空")
	}
}
