package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"toshell/internal/common/features"
	"toshell/internal/common/moduleabi"
	"toshell/internal/common/types"
	"toshell/internal/server/builder"
	"toshell/internal/server/modules"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── exec_module 接口层用例（v1.4.0 S4）─────────────────────────────────────
//
// 全部**不联网、不需要真实植入端**：会话是进程内注册的假会话，任务是隔离的任务
// 管理器，下发用假 TaskPusher（记录模块二进制帧），模块是内存里手工拼的 PE
// （带真实导出表）。因此这些用例能在 CI 上跑，并且能精确断言"哪一步拒绝、错误码
// 是什么、审计写了什么"。

// ─── 合成模块 PE（带导出表）──────────────────────────────────────────────────

const (
	tpeELfanew    = 0x80
	tpeOptSize    = 224
	tpeDataDirOff = 96
	tpeSecTable   = tpeELfanew + 4 + 20 + tpeOptSize
	tpeSecRawOff  = 0x400
	tpeSecRVA     = 0x1000
	tpeSecRawSize = 0x400

	tpeMachineI386  = 0x014C
	tpeMachineAMD64 = 0x8664
)

// syntheticModulePE 造一个合法的 PE32/PE32+ DLL：可指定 Machine、导出名、是否带
// Go 构建信息魔数（用于覆盖"Go 模块必须被拒"这条硬边界）。
//
// 为什么在测试里拼 PE 而不是用真实产物：CI 上不一定有 mingw gcc，而"校验链"的
// 判定逻辑只依赖 PE 头/导出表，手工构造既确定又快，还能精确构造**畸形/不合规**的样本
// （真实编译器不会给你产出这种文件）。
func syntheticModulePE(t *testing.T, machine uint16, exports []string, goMarker bool) []byte {
	t.Helper()
	is64 := machine == tpeMachineAMD64
	optSize, dataDirOff := tpeOptSize, tpeDataDirOff
	var magic uint16 = 0x010B
	if is64 {
		optSize, dataDirOff = 240, 112
		magic = 0x020B
	}
	secTable := tpeELfanew + 4 + 20 + optSize

	n := len(exports)
	funcsOff := 40
	namesOff := funcsOff + 4*n
	ordsOff := namesOff + 4*n
	strOff := ordsOff + 2*n

	namesRVAs := make([]uint32, n)
	nameBytes := make([][]byte, n)
	acc := strOff
	for i, e := range exports {
		nameBytes[i] = append([]byte(e), 0)
		namesRVAs[i] = uint32(tpeSecRVA + acc)
		acc += len(e) + 1
	}
	secLen := acc
	if goMarker {
		secLen += len("\xff Go buildinf:") + 4
	}
	if secLen < 0x40 {
		secLen = 0x40
	}
	sec := make([]byte, secLen)

	hasExportDir := n > 0
	if hasExportDir {
		le32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(sec[off:off+4], v) }
		le16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(sec[off:off+2], v) }
		le32(16, 1)                          // Base
		le32(20, uint32(n))                  // NumberOfFunctions
		le32(24, uint32(n))                  // NumberOfNames
		le32(28, uint32(tpeSecRVA+funcsOff)) // AddressOfFunctions
		le32(32, uint32(tpeSecRVA+namesOff)) // AddressOfNames
		le32(36, uint32(tpeSecRVA+ordsOff))  // AddressOfNameOrdinals
		le32(12, uint32(tpeSecRVA+strOff))   // Name（DLL 名，指向第一个名字，解析器不依赖）
		for i := 0; i < n; i++ {
			le32(funcsOff+4*i, uint32(0x2000+i*16))
			le32(namesOff+4*i, namesRVAs[i])
			le16(ordsOff+2*i, uint16(i))
			copy(sec[namesRVAs[i]-tpeSecRVA:], nameBytes[i])
		}
	}
	if goMarker {
		copy(sec[acc:], []byte("\xff Go buildinf:"))
	}

	total := tpeSecRawOff + tpeSecRawSize
	buf := make([]byte, total)

	// DOS 头
	binary.LittleEndian.PutUint16(buf[0:2], 0x5A4D)
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], tpeELfanew)
	// PE 签名 + 文件头
	binary.LittleEndian.PutUint32(buf[tpeELfanew:tpeELfanew+4], 0x00004550)
	fileHdr := tpeELfanew + 4
	binary.LittleEndian.PutUint16(buf[fileHdr:fileHdr+2], machine)
	binary.LittleEndian.PutUint16(buf[fileHdr+2:fileHdr+4], 1) // NumberOfSections
	binary.LittleEndian.PutUint16(buf[fileHdr+16:fileHdr+18], uint16(optSize))
	binary.LittleEndian.PutUint16(buf[fileHdr+18:fileHdr+20], 0x2102) // EXECUTABLE|32BIT|DLL

	// 可选头
	optHdr := fileHdr + 20
	binary.LittleEndian.PutUint16(buf[optHdr:optHdr+2], magic)
	binary.LittleEndian.PutUint32(buf[optHdr+16:optHdr+20], 0x1000) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(buf[optHdr+56:optHdr+60], 0x2000) // SizeOfImage
	binary.LittleEndian.PutUint32(buf[optHdr+60:optHdr+64], 0x400)  // SizeOfHeaders
	binary.LittleEndian.PutUint16(buf[optHdr+68:optHdr+70], 3)      // Subsystem = console
	binary.LittleEndian.PutUint32(buf[optHdr+dataDirOff-4:], 16)    // NumberOfRvaAndSizes
	if hasExportDir {
		dd := optHdr + dataDirOff
		binary.LittleEndian.PutUint32(buf[dd:dd+4], tpeSecRVA)
		binary.LittleEndian.PutUint32(buf[dd+4:dd+8], uint32(len(sec)))
	}

	// 节表（.edata）
	so := secTable
	copy(buf[so:so+8], ".edata\x00\x00")
	binary.LittleEndian.PutUint32(buf[so+8:so+12], uint32(len(sec)))
	binary.LittleEndian.PutUint32(buf[so+12:so+16], tpeSecRVA)
	binary.LittleEndian.PutUint32(buf[so+16:so+20], tpeSecRawSize)
	binary.LittleEndian.PutUint32(buf[so+20:so+24], tpeSecRawOff)
	binary.LittleEndian.PutUint32(buf[so+36:so+40], 0x40000040) // 只读已初始化数据
	copy(buf[tpeSecRawOff:], sec)
	return buf
}

// assertSyntheticPEIsWellFormed 先自检"测试替身本身是合法的"，避免用例挂了却
// 以为是处理器的问题（这类自检在手工构造二进制的测试里很值）。
func assertSyntheticPEIsWellFormed(t *testing.T, raw []byte, wantExports ...string) {
	t.Helper()
	info, err := builder.InspectPE(raw)
	if err != nil {
		t.Fatalf("合成 PE 不合法：%v", err)
	}
	names, err := builder.ExportedNames(raw)
	if err != nil {
		t.Fatalf("合成 PE 的导出表不可解析：%v", err)
	}
	if okExp, missing := builder.HasExports(names, wantExports...); !okExp {
		t.Fatalf("合成 PE 缺导出 %v（实际 %v）；info=%+v", missing, names, info)
	}
}

// ─── 测试环境 ────────────────────────────────────────────────────────────────

type moduleTestEnv struct {
	s      *Server
	sess   *session.Manager
	tm     *task.Manager
	pusher *fakePusher
	dir    string
	sid    string

	mu     sync.Mutex
	audits []moduleAuditEvent
}

// newModuleTestEnv 构造最小可用的 Server（会话 + 隔离任务管理器 + 假推送 + 临时模块目录）。
// execModule=true 时会话上报 exec_module 能力位（模拟用 -tags execmodule 构建的载荷）。
func newModuleTestEnv(t *testing.T, execModule bool) *moduleTestEnv {
	t.Helper()
	mgr := session.New()
	sid := fmt.Sprintf("mod-%d", time.Now().UnixNano())

	mods := []string{}
	if execModule {
		mods = []string{features.EncodeToken(features.Input{
			Profile: features.ProfileLight, Transport: "tcp", Protocol: "tcp",
			ExecModule: true, OS: "windows", Arch: "386",
		})}
	}
	if err := mgr.Add(&types.SessionInfo{
		ID: sid, Hostname: "host", Username: "user",
		OS: "windows", Arch: "386", Status: "active", ActiveModules: mods,
	}); err != nil {
		t.Fatalf("session Add: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Remove(sid) })

	pusher := &fakePusher{}
	dir := t.TempDir()
	env := &moduleTestEnv{
		s: &Server{
			sessionMgr:  mgr,
			taskMgr:     task.NewIsolated(mgr),
			listener:    pusher,
			moduleStore: modules.NewStore(dir),
		},
		sess: mgr, tm: task.NewIsolated(mgr), pusher: pusher, dir: dir, sid: sid,
	}
	// 注意：Server.taskMgr 与 env.tm 必须是同一个实例，否则读任务数据会读不到。
	env.tm = env.s.taskMgr
	env.s.moduleAuditHook = func(ev moduleAuditEvent) {
		env.mu.Lock()
		env.audits = append(env.audits, ev)
		env.mu.Unlock()
	}
	return env
}

// registerModule 把一个模块（文件 + 清单条目）写进临时模块目录。
func (e *moduleTestEnv) registerModule(t *testing.T, id, arch string, raw []byte, opts ...func(*modules.Entry)) modules.Entry {
	t.Helper()
	sum := sha256.Sum256(raw)
	entry := modules.Entry{
		ID: id, Name: id, File: id + ".dll",
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw)),
		ABI: moduleabi.Version, OS: "windows", Arch: arch,
		Entry: moduleabi.ExportMain,
	}
	for _, o := range opts {
		o(&entry)
	}
	if err := os.WriteFile(filepath.Join(e.dir, entry.File), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := modules.LoadManifestFile(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	m.Modules = append(m.Modules, entry)
	if err := modules.WriteManifestFile(e.dir, m); err != nil {
		t.Fatal(err)
	}
	return entry
}

// post 调用 POST /sessions/{id}/module。
func (e *moduleTestEnv) post(t *testing.T, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+e.sid+"/module", strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": e.sid})
	rec := httptest.NewRecorder()
	e.s.execModuleHandler(rec, req)
	return rec.Code, decodeJSON(t, rec)
}

// get 调用 GET /sessions/{id}/module。
func (e *moduleTestEnv) get(t *testing.T) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+e.sid+"/module", nil)
	req = mux.SetURLVars(req, map[string]string{"id": e.sid})
	rec := httptest.NewRecorder()
	e.s.listSessionModulesHandler(rec, req)
	return rec.Code, decodeJSON(t, rec)
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON（code=%d）：%s", rec.Code, rec.Body.String())
	}
	return body
}

// auditEvents 返回记录到的审计事件名（按顺序）。
func (e *moduleTestEnv) auditEvents() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.audits))
	for _, a := range e.audits {
		out = append(out, a.Event)
	}
	return out
}

// lastAudit 返回最后一条审计事件。
func (e *moduleTestEnv) lastAudit() (moduleAuditEvent, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.audits) == 0 {
		return moduleAuditEvent{}, false
	}
	return e.audits[len(e.audits)-1], true
}

// checksOf 把响应里的 checks 数组转成 step→(ok, detail)。
func checksOf(t *testing.T, body map[string]interface{}) map[int]moduleCheck {
	t.Helper()
	raw, ok := body["checks"].([]interface{})
	if !ok {
		t.Fatalf("响应缺少 checks：%v", body)
	}
	out := make(map[int]moduleCheck, len(raw))
	for _, v := range raw {
		m, _ := v.(map[string]interface{})
		if m == nil {
			continue
		}
		step := int(m["step"].(float64))
		out[step] = moduleCheck{
			Step:   step,
			Name:   fmt.Sprint(m["name"]),
			OK:     m["ok"] == true,
			Detail: fmt.Sprint(m["detail"]),
		}
	}
	return out
}

// ─── 成功路径 ────────────────────────────────────────────────────────────────

func TestExecModuleSuccessFullChain(t *testing.T) {
	env := newModuleTestEnv(t, true)
	raw := syntheticModulePE(t, tpeMachineI386, []string{
		moduleabi.ExportName, moduleabi.ExportABI, moduleabi.ExportError, moduleabi.ExportMain,
	}, false)
	assertSyntheticPEIsWellFormed(t, raw, moduleabi.ExportABI, moduleabi.ExportMain)
	env.registerModule(t, "cred_probe", "386", raw)

	code, body := env.post(t, `{"module":"cred_probe","args":"reg:SOFTWARE\\Foo|Bar"}`)
	if code != 200 {
		t.Fatalf("期望 200，实际 %d：%v", code, body)
	}
	if body["ok"] != true {
		t.Fatalf("ok 不为 true：%v", body)
	}
	taskID := uint64(body["task_id"].(float64))
	if taskID == 0 {
		t.Fatal("响应没有 task_id")
	}
	token, _ := body["token"].(string)
	if len(token) != 32 {
		t.Fatalf("token 异常：%q", token)
	}

	// 9 步校验链全部通过（步骤号与实现里的注释一一对应）。
	checks := checksOf(t, body)
	for step := 1; step <= 9; step++ {
		c, ok := checks[step]
		if !ok {
			t.Fatalf("缺少第 %d 步校验结论：%v", step, checks)
		}
		if !c.OK {
			t.Fatalf("第 %d 步（%s）失败：%s", step, c.Name, c.Detail)
		}
	}

	// ⑧ 任务复用既有体系：任务里只有 token 与元信息，**没有模块字节**。
	ti, err := env.tm.Get(taskID)
	if err != nil || ti == nil {
		t.Fatalf("任务不存在：%v", err)
	}
	if ti.TaskType != task.TaskTypeExecModule {
		t.Fatalf("任务类型 = %q", ti.TaskType)
	}
	if strings.Contains(ti.Data, "payload_b64") || len(ti.Data) > 4096 {
		t.Fatalf("任务数据里疑似内联了模块字节（长度 %d）：%s", len(ti.Data), ti.Data)
	}
	var header moduleabi.ArgumentHeader
	if err := json.Unmarshal([]byte(ti.Data), &header); err != nil {
		t.Fatalf("任务数据不是合法 ArgumentHeader：%v", err)
	}
	if header.Token != token || header.ModuleID != "cred_probe" || header.ABI != moduleabi.Version {
		t.Fatalf("任务数据与响应不一致：%+v", header)
	}
	if header.ArgsJSON != `reg:SOFTWARE\Foo|Bar` {
		t.Fatalf("参数没有原样透传：%q", header.ArgsJSON)
	}
	if header.SHA256 != hex.EncodeToString(sha256Sum(raw)) {
		t.Fatalf("任务里的哈希不对：%s", header.SHA256)
	}

	// ⑧ 二进制帧：先于任务下发，帧内就是模块裸字节（不是 base64）。
	pushedToken, frame := env.pusher.lastModuleBlob()
	if pushedToken != token {
		t.Fatalf("下发的 token = %q，期望 %q", pushedToken, token)
	}
	if len(frame) == 0 {
		t.Fatal("没有下发模块二进制帧")
	}
	frameHeader, blob, err := moduleabi.DecodeBlobFrame(frame)
	if err != nil {
		t.Fatalf("下发的帧解不开：%v", err)
	}
	if frameHeader.SHA256 != header.SHA256 || len(blob) != len(raw) {
		t.Fatalf("帧头与字节不符：%+v len=%d", frameHeader, len(blob))
	}
	if string(blob) != string(raw) {
		t.Fatal("帧内字节与登记字节不一致")
	}
	// 帧里不应出现 base64 特征（长度应与裸字节几乎相同）。
	if len(frame) > len(raw)+4096 {
		t.Fatalf("帧长度 %d 远大于裸字节 %d：疑似又用 base64 包了一层", len(frame), len(raw))
	}

	// ⑨ 审计：成功路径必须留痕（blob_pushed + exec_ok）。
	events := env.auditEvents()
	if len(events) < 2 || events[len(events)-1] != "module_exec_ok" {
		t.Fatalf("审计事件序列不对：%v", events)
	}
	if last, _ := env.lastAudit(); last.SessionID != env.sid || last.ModuleID != "cred_probe" || last.TaskID != taskID {
		t.Fatalf("审计字段不全：%+v", last)
	}
}

func TestListSessionModules(t *testing.T) {
	env := newModuleTestEnv(t, true)
	good := syntheticModulePE(t, tpeMachineI386, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
	env.registerModule(t, "ok_mod", "386", good)
	bad := syntheticModulePE(t, tpeMachineAMD64, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
	env.registerModule(t, "arch_mod", "amd64", bad)

	code, body := env.get(t)
	if code != 200 {
		t.Fatalf("期望 200，实际 %d：%v", code, body)
	}
	if body["exec_module"] != true {
		t.Fatalf("会话应上报 exec_module：%v", body)
	}
	list, _ := body["modules"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("模块数 = %d，期望 2：%v", len(list), body["modules"])
	}
	for _, v := range list {
		m := v.(map[string]interface{})
		usable := m["usable"] == true
		switch m["id"] {
		case "ok_mod":
			if !usable {
				t.Errorf("ok_mod 应可用：%v", m["problems"])
			}
		case "arch_mod":
			if usable {
				t.Errorf("arch_mod（amd64 模块 + 386 宿主）不该可用")
			}
			probs := fmt.Sprint(m["problems"])
			if !strings.Contains(probs, "架构不符") {
				t.Errorf("问题描述应说明架构不符：%s", probs)
			}
		}
	}

	// 未上报能力位的会话：所有模块都标不可用（fail-closed）
	env2 := newModuleTestEnv(t, false)
	env2.registerModule(t, "ok_mod", "386", good)
	code2, body2 := env2.get(t)
	if code2 != 200 || body2["exec_module"] != false {
		t.Fatalf("未上报能力位时应为 false：%v", body2)
	}
	for _, v := range body2["modules"].([]interface{}) {
		if v.(map[string]interface{})["usable"] == true {
			t.Error("未上报 exec_module 时不该有可用模块")
		}
	}
}

// ─── 失败路径（每种都必须有明确的错误码/文案）────────────────────────────────

func TestExecModuleFailurePaths(t *testing.T) {
	// 各用例共用一套"合法模块 + 合法会话"，逐条把某一个前提弄坏。
	newGood := func(t *testing.T) (*moduleTestEnv, []byte) {
		env := newModuleTestEnv(t, true)
		raw := syntheticModulePE(t, tpeMachineI386, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
		env.registerModule(t, "cred_probe", "386", raw)
		return env, raw
	}

	t.Run("会话不存在", func(t *testing.T) {
		env, _ := newGood(t)
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"module":"cred_probe"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "no-such-session"})
		rec := httptest.NewRecorder()
		env.s.execModuleHandler(rec, req)
		code, body := rec.Code, decodeJSON(t, rec)
		if code != 404 || body["code"] != modules.CodeSessionNotFound {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("会话非 active", func(t *testing.T) {
		env, _ := newGood(t)
		sess, _ := env.sess.Get(env.sid)
		sess.Info.Status = "dead"
		sess.LastSeen = time.Now().Add(-24 * time.Hour)
		code, body := env.post(t, `{"module":"cred_probe"}`)
		if code != 409 || body["code"] != modules.CodeSessionInactive {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if last, ok := env.lastAudit(); !ok || last.Code != modules.CodeSessionInactive || last.Step != 1 {
			t.Fatalf("失败审计不对：%+v", last)
		}
	})

	t.Run("载荷不支持 exec_module", func(t *testing.T) {
		env := newModuleTestEnv(t, false) // 未上报能力位 = light 默认构建
		raw := syntheticModulePE(t, tpeMachineI386, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
		env.registerModule(t, "cred_probe", "386", raw)
		code, body := env.post(t, `{"module":"cred_probe"}`)
		if code != 409 || body["code"] != modules.CodeImplantUnsupported {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "execmodule") {
			t.Errorf("文案应告诉操作员要用 -tags execmodule：%v", body["error"])
		}
	})

	t.Run("模块未登记", func(t *testing.T) {
		env, _ := newGood(t)
		code, body := env.post(t, `{"module":"ghost"}`)
		if code != 404 || body["code"] != modules.CodeModuleNotRegistered {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if c := checksOf(t, body)[2]; c.OK {
			t.Error("第 2 步应标失败")
		}
	})

	t.Run("缺少 module 字段", func(t *testing.T) {
		env, _ := newGood(t)
		code, body := env.post(t, `{}`)
		if code != 400 || body["code"] != modules.CodeBadRequest {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("哈希不符（硬拦）", func(t *testing.T) {
		env, raw := newGood(t)
		// 把文件换成同长度、不同内容的另一份；清单还是旧的哈希。
		tampered := append([]byte(nil), raw...)
		tampered[tpeSecRawOff+8] ^= 0xFF
		if err := os.WriteFile(filepath.Join(env.dir, "cred_probe.dll"), tampered, 0o644); err != nil {
			t.Fatal(err)
		}
		code, body := env.post(t, `{"module":"cred_probe"}`)
		if code != 409 || body["code"] != modules.CodeHashMismatch {
			t.Fatalf("哈希不符必须 409 module_hash_mismatch，实际 code=%d body=%v", code, body)
		}
		if c := checksOf(t, body)[3]; c.OK {
			t.Error("第 3 步应标失败")
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "sha256 不符") {
			t.Errorf("文案应说明哈希不符：%v", body["error"])
		}
		// 绝不能下发任何东西
		if tok, _ := env.pusher.lastModuleBlob(); tok != "" {
			t.Error("哈希不符时仍下发了模块二进制")
		}
		if last, _ := env.lastAudit(); last.Code != modules.CodeHashMismatch || last.Step != 3 {
			t.Fatalf("失败审计不对：%+v", last)
		}
	})

	t.Run("大小不符", func(t *testing.T) {
		env, raw := newGood(t)
		if err := os.WriteFile(filepath.Join(env.dir, "cred_probe.dll"), append(raw, 0), 0o644); err != nil {
			t.Fatal(err)
		}
		code, body := env.post(t, `{"module":"cred_probe"}`)
		if code != 409 || body["code"] != modules.CodeSizeMismatch {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("架构不符（清单声明 amd64，宿主 386）", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		raw := syntheticModulePE(t, tpeMachineAMD64, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
		env.registerModule(t, "amd_mod", "amd64", raw)
		code, body := env.post(t, `{"module":"amd_mod"}`)
		if code != 409 || body["code"] != modules.CodeArchMismatch {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "指令集翻译") {
			t.Errorf("文案应解释崩宿主原因：%v", body["error"])
		}
	})

	t.Run("清单声明与 PE 实际架构不一致", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		// 用 amd64 的 PE，却登记成 386（宿主也是 386）：只比"声明 vs 宿主"会放过，
		// 必须靠"PE 实际 vs 声明"拦下 —— 这正是"清单被写错/改过"的现实形态。
		raw := syntheticModulePE(t, tpeMachineAMD64, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
		env.registerModule(t, "lie_mod", "386", raw)
		code, body := env.post(t, `{"module":"lie_mod"}`)
		if code != 409 || body["code"] != modules.CodeArchMismatch {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "清单与实际文件不一致") {
			t.Errorf("文案应指出清单与实际不一致：%v", body["error"])
		}
	})

	t.Run("OS 不符（非 windows 模块）", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		raw := syntheticModulePE(t, tpeMachineI386, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
		env.registerModule(t, "lin_mod", "386", raw, func(e *modules.Entry) { e.OS = "linux" })
		code, body := env.post(t, `{"module":"lin_mod"}`)
		if code != 409 || body["code"] != modules.CodeOSMismatch {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("缺 ABI 导出", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		// 有导出表但只有无关导出
		raw := syntheticModulePE(t, tpeMachineI386, []string{"SomeOtherExport"}, false)
		env.registerModule(t, "noabi", "386", raw)
		code, body := env.post(t, `{"module":"noabi"}`)
		if code != 409 || body["code"] != modules.CodeABIExportsAbsent {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), moduleabi.ExportMain) {
			t.Errorf("文案应指出缺哪个导出：%v", body["error"])
		}
		if c := checksOf(t, body)[5]; c.OK {
			t.Error("第 5 步应标失败")
		}
	})

	t.Run("完全没有导出表", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		raw := syntheticModulePE(t, tpeMachineI386, nil, false)
		env.registerModule(t, "noexp", "386", raw)
		code, body := env.post(t, `{"module":"noexp"}`)
		if code != 409 || body["code"] != modules.CodeABIExportsAbsent {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("Go 编译的模块", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		raw := syntheticModulePE(t, tpeMachineI386, []string{moduleabi.ExportABI, moduleabi.ExportMain}, true)
		env.registerModule(t, "gomod", "386", raw)
		code, body := env.post(t, `{"module":"gomod"}`)
		if code != 409 || body["code"] != modules.CodeNotNative {
			t.Fatalf("code=%d body=%v", code, body)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "两个 Go runtime") {
			t.Errorf("文案应解释双 runtime 硬边界：%v", body["error"])
		}
	})

	t.Run("ABI 版本不符", func(t *testing.T) {
		env := newModuleTestEnv(t, true)
		raw := syntheticModulePE(t, tpeMachineI386, []string{moduleabi.ExportABI, moduleabi.ExportMain}, false)
		// 清单声明 ABI=99：必须在第 2 步（清单校验）就被拒 —— 条目本身自相矛盾，
		// 连字节都不用读。这里同时验证"版本握手不是只在植入端做"。
		env.registerModule(t, "abi99", "386", raw, func(e *modules.Entry) { e.ABI = 99 })
		code, body := env.post(t, `{"module":"abi99"}`)
		if code != 409 || body["code"] != modules.CodeABIMismatch {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("token 复用被拒", func(t *testing.T) {
		env, _ := newGood(t)
		code, body := env.post(t, `{"module":"cred_probe"}`)
		if code != 200 {
			t.Fatalf("首次下发应成功：%d %v", code, body)
		}
		token := body["token"].(string)
		code2, body2 := env.post(t, fmt.Sprintf(`{"module":"cred_probe","token":%q}`, token))
		if code2 != 409 || body2["code"] != modules.CodeTokenReused {
			t.Fatalf("复用必须是 409 token_reused，实际 code=%d body=%v", code2, body2)
		}
		if last, _ := env.lastAudit(); last.Code != modules.CodeTokenReused || last.Step != 7 {
			t.Fatalf("失败审计不对：%+v", last)
		}
	})

	t.Run("token 过期被拒", func(t *testing.T) {
		env, raw := newGood(t)
		// 用可控时钟：签发 → 推进 10 分钟 → 必然过期。
		now := time.Unix(1700000000, 0)
		store := modules.NewStore(env.dir)
		store.SetClock(func() time.Time { return now })
		if err := store.Reload(); err != nil {
			t.Fatal(err)
		}
		env.s.moduleStore = store
		sum := sha256.Sum256(raw)
		tok, err := store.IssueTokenFor(env.sid, modules.Entry{
			ID: "cred_probe", File: "cred_probe.dll",
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw)),
			ABI: moduleabi.Version, OS: "windows", Arch: "386",
		})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(10 * time.Minute)
		code, body := env.post(t, fmt.Sprintf(`{"module":"cred_probe","token":%q}`, tok.Value))
		if code != 409 || body["code"] != modules.CodeTokenExpired {
			t.Fatalf("过期必须是 409 token_expired，实际 code=%d body=%v", code, body)
		}
	})

	t.Run("token 不存在", func(t *testing.T) {
		env, _ := newGood(t)
		code, body := env.post(t, `{"module":"cred_probe","token":"deadbeef"}`)
		if code != 409 || body["code"] != modules.CodeTokenNotFound {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})

	t.Run("token 跨会话越权", func(t *testing.T) {
		env, raw := newGood(t)
		// 用 A 会话签发的凭据去下发到 B 会话（B 也必须支持 exec_module，
		// 否则会在第 1 步就被拦下，测不到 token 的会话绑定）。
		other := newModuleTestEnv(t, true)
		other.s.moduleStore = env.s.moduleStore // 共用同一份凭据表
		sum := sha256.Sum256(raw)
		tok, err := env.s.moduleStore.IssueTokenFor(env.sid, modules.Entry{
			ID: "cred_probe", File: "cred_probe.dll",
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw)),
			ABI: moduleabi.Version, OS: "windows", Arch: "386",
		})
		if err != nil {
			t.Fatal(err)
		}
		code, body := other.post(t, fmt.Sprintf(`{"module":"cred_probe","token":%q}`, tok.Value))
		if code != 409 || body["code"] != modules.CodeTokenSessionWrong {
			t.Fatalf("跨会话必须 409 token_session_mismatch，实际 code=%d body=%v", code, body)
		}
		// 被拒的越权尝试不该消耗掉凭据（合法会话随后仍能用它）
		if _, err := env.s.moduleStore.ConsumeToken(tok.Value, env.sid, "cred_probe"); err != nil {
			t.Fatalf("越权尝试不应消耗凭据：%v", err)
		}
	})

	t.Run("任务下发失败", func(t *testing.T) {
		env, _ := newGood(t)
		env.pusher.moduleErr = fmt.Errorf("链路断了")
		code, body := env.post(t, `{"module":"cred_probe"}`)
		if code != 503 || body["code"] != modules.CodePushFailed {
			t.Fatalf("code=%d body=%v", code, body)
		}
	})
}

// ─── 模块加载桩：不依赖真实植入端，把"植入端一侧的校验"跑一遍 ─────────────────

// TestModuleLoadStub 用"假植入端"验证下发的帧真的可加载：
//   - 解帧（[4B 头长][头 JSON][裸字节]）；
//   - 头部 sha256/大小与字节一致（植入端的第一道硬校验）；
//   - PE 可解析、导出齐全、ABI 版本可握手（这里用导出表存在性代替"调 tsh_module_abi"，
//     因为桩不执行代码）；
//   - 同一 token 只能取出一次（植入端的"取出即删"语义）。
//
// 这是"端到端"在 CI 上的替身：真机执行在临时 e2e 脚本里做，这里保证**协议与校验**
// 这一层不出错（历史上最容易出的就是"帧格式两边不一致"却没人发现）。
func TestModuleLoadStub(t *testing.T) {
	env := newModuleTestEnv(t, true)
	raw := syntheticModulePE(t, tpeMachineI386, []string{
		moduleabi.ExportABI, moduleabi.ExportMain, moduleabi.ExportError, moduleabi.ExportName,
	}, false)
	env.registerModule(t, "cred_probe", "386", raw)

	code, body := env.post(t, `{"module":"cred_probe"}`)
	if code != 200 {
		t.Fatalf("下发失败：%d %v", code, body)
	}
	token := body["token"].(string)
	_, frame := env.pusher.lastModuleBlob()

	// ── 假植入端：按 token 暂存（一次性）──
	type pending struct {
		header *moduleabi.ArgumentHeader
		raw    []byte
	}
	store := map[string]pending{}
	h, blob, err := moduleabi.DecodeBlobFrame(frame)
	if err != nil {
		t.Fatalf("假植入端解帧失败：%v", err)
	}
	sum := sha256.Sum256(blob)
	if hex.EncodeToString(sum[:]) != h.SHA256 {
		t.Fatalf("假植入端哈希校验失败：帧头 %s 实际 %s", h.SHA256, hex.EncodeToString(sum[:]))
	}
	if h.ABI != moduleabi.Version {
		t.Fatalf("假植入端版本握手失败：帧头 %d，宿主 %d", h.ABI, moduleabi.Version)
	}
	store[h.Token] = pending{header: h, raw: blob}

	// 取出即删（一次性）
	take := func(tok string) (pending, bool) {
		p, ok := store[tok]
		if ok {
			delete(store, tok)
		}
		return p, ok
	}
	p, ok := take(token)
	if !ok {
		t.Fatal("按 token 取不到模块")
	}
	if _, again := take(token); again {
		t.Fatal("同一 token 被取出了两次（植入端一次性语义失效）")
	}

	// ── 假植入端的加载前检查（与 exec_module_windows.go 同一口径）──
	info, err := builder.InspectPE(p.raw)
	if err != nil {
		t.Fatalf("映射前 PE 解析失败：%v", err)
	}
	if info.Machine != "386" {
		t.Fatalf("架构不对：%s", info.Machine)
	}
	x := make([]byte, len(p.raw))
	copy(x, p.raw)
	if isGo, ev := builder.DetectGoBinary(x); isGo {
		t.Fatalf("桩载荷被判成 Go 模块：%s", ev)
	}
	names, err := builder.ExportedNames(p.raw)
	if err != nil {
		t.Fatalf("导出表解析失败：%v", err)
	}
	if ok, missing := builder.HasExports(names, moduleabi.ExportABI, moduleabi.ExportMain); !ok {
		t.Fatalf("桩载荷缺导出 %v", missing)
	}
	// 上下文契约里的会话 id/token 摘要必须能独立算出来（植入端与模块两侧同名同算法）。
	if moduleabi.FNV1a32(token) == 0 {
		t.Error("token 摘要不该为 0（会与'未设置'无法区分）")
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
