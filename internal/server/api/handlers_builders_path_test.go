package api

// handlers_builders_path_test.go —— 审计 Toshell_AUDIT_2026-10-24 H2/H3/M9 的
// HTTP 层回归测试。这些用例直接调用 handler（不起真实服务端、不编译植入端），
// 用临时目录构造"目录外的受害者文件"，断言：
//   - 恶意请求被 4xx 拒绝；
//   - 目标文件**仍然存在** / 内容**没有**被回传（即修复前必定失败的断言）；
//   - 合法的构建名与下载路径仍然工作（证明修复没有把正常功能弄坏）。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"toshell/internal/server/config"
	"toshell/internal/server/database"
)

// newBuildersPathServer 造一个只带配置的最小 Server：这些 handler 的路径安全
// 校验发生在任何 builder/DB 调用之前，因此不需要真实 builder。
func newBuildersPathServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	root := t.TempDir()
	implantDir := filepath.Join(root, "implants")
	if err := os.MkdirAll(implantDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Implant.OutputDir = implantDir
	s := &Server{cfg: cfg}
	return s, root, implantDir
}

// ─── H2：认证后任意文件删除 ─────────────────────────────────────────────────

func TestCreateBuilderRejectsTraversalNameH2(t *testing.T) {
	s, root, _ := newBuildersPathServer(t)

	// 审计 PoC：implants/../victim.txt 就是 root/victim.txt（目录外）
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("must survive"), 0644); err != nil {
		t.Fatal(err)
	}

	body := `{"name":"../victim.txt","format":"bin","os":"linux"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/builders", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.createBuilderHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("穿越 name 应返回 400，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "载荷名只允许") {
		t.Errorf("400 响应应给出中文原因，实际: %s", rec.Body.String())
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("目录外文件被删除了！H2 未修复: %v", err)
	}
}

// 对照组：服务端生成的合法名（implant-<unix>）不受影响 —— 用 safePayloadName
// 直接断言，避免触发真实构建。
func TestLegitBuildNamesStillAccepted(t *testing.T) {
	for _, name := range []string{
		"implant-1792144113",
		"build-1792144113714300000",
	} {
		if _, err := safePayloadName(name); err != nil {
			t.Fatalf("合法构建名 %q 被拒: %v", name, err)
		}
	}
}

// ─── H3：认证后任意文件读（按名下载）────────────────────────────────────────

func TestDownloadPayloadRejectsTraversalNameH3(t *testing.T) {
	s, root, implantDir := newBuildersPathServer(t)

	// 审计 PoC 1：name="../configs/server" + format="yaml" -> configs/server.yaml
	confDir := filepath.Join(root, "configs")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(confDir, "server.yaml")
	if err := os.WriteFile(conf, []byte("SECRET-CONFIG-LEAK"), 0644); err != nil {
		t.Fatal(err)
	}
	// 审计 PoC 2/3：折叠型 payload（format 里藏 ..）与数据库文件
	dbFile := filepath.Join(root, "data", "toshell.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbFile, []byte("SECRET-DB-LEAK"), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		desc string
		body string
	}{
		{"configs/server.yaml", `{"name":"../configs/server","format":"yaml"}`},
		{"data/toshell.db", `{"name":"../data/toshell","format":"db"}`},
		{"折叠型 /etc/passwd 等价物", `{"name":"../../x","format":"y/../../etc/passwd"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builders/download", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.downloadPayloadHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: 应返回 400，实际 %d: %s", tc.desc, rec.Code, rec.Body.String())
		}
		if cd := rec.Header().Get("Content-Disposition"); cd != "" {
			t.Errorf("%s: 不应回传文件（Content-Disposition=%q）", tc.desc, cd)
		}
		for _, leak := range []string{"SECRET-CONFIG-LEAK", "SECRET-DB-LEAK", "root:x:", "root:.*:0:0"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: 响应泄露了目录外内容 %q", tc.desc, leak)
			}
		}
	}

	// format 白名单：即使 name 合法，也不允许用 .yaml 当后缀去命中目录外文件
	yamlInDir := filepath.Join(implantDir, "build-1.yaml")
	if err := os.WriteFile(yamlInDir, []byte("SECRET-YAML-LEAK"), 0644); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/builders/download", strings.NewReader(`{"name":"build-1","format":"yaml"}`))
	rec := httptest.NewRecorder()
	s.downloadPayloadHandler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("非白名单 format 应 404，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SECRET-YAML-LEAK") {
		t.Error("non-whitelisted format 仍读到了 .yaml 文件")
	}
}

// 对照组：合法 name + 白名单 format 仍能正常下载。
func TestDownloadPayloadByNameStillWorks(t *testing.T) {
	s, _, implantDir := newBuildersPathServer(t)
	target := filepath.Join(implantDir, "build-2.raw")
	if err := os.WriteFile(target, []byte("RAW-OK"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/builders/download", strings.NewReader(`{"name":"build-2","format":"raw"}`))
	rec := httptest.NewRecorder()
	s.downloadPayloadHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("合法按名下载应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "RAW-OK" {
		t.Fatalf("下载内容 = %q, want RAW-OK", got)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "build-2.raw") {
		t.Errorf("Content-Disposition = %q, want 含 build-2.raw", cd)
	}
}

// ─── M9：未认证 /payload/{id} 回退候选拼接 DB 里的 name ─────────────────────

func TestServeStoredImplantSkipsEscapingNameM9(t *testing.T) {
	s, root, implantDir := newBuildersPathServer(t)

	// 让 "../../root.txt" 从 implants 目录折到 root/root.txt（旧实现会命中它）
	// implantDir = <root>/a/implants → ../../root.txt = <root>/root.txt
	s.cfg.Implant.OutputDir = filepath.Join(root, "a", "implants")
	implantDir = s.cfg.Implant.OutputDir
	if err := os.MkdirAll(implantDir, 0755); err != nil {
		t.Fatal(err)
	}
	leak := filepath.Join(root, "root.txt")
	if err := os.WriteFile(leak, []byte("SECRET-ROOT-TXT"), 0644); err != nil {
		t.Fatal(err)
	}

	imp := &database.StoredImplant{
		ID:       "build-a",
		Name:     "../../root",
		Format:   "raw",
		OS:       "linux",
		Filename: "build-a.raw", // 产物已被 H2 的清理逻辑删掉 -> 候选 1 不存在
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/build-a", nil)
	rec := httptest.NewRecorder()
	s.serveStoredImplant(rec, req, imp)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("越界候选应 404，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SECRET-ROOT-TXT") {
		t.Fatal("未认证端点读到了目录外文件！M9 未修复")
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("越界请求不应回传文件（Content-Disposition=%q）", cd)
	}

	// 同一 DB 行，但 Filename 也越界：同样必须 404
	impBadFile := &database.StoredImplant{
		ID:       "build-b",
		Name:     "whatever",
		Format:   "raw",
		OS:       "linux",
		Filename: "../../root.txt",
	}
	rec2 := httptest.NewRecorder()
	s.serveStoredImplant(rec2, httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/build-b", nil), impBadFile)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("Filename 越界应 404，实际 %d: %s", rec2.Code, rec2.Body.String())
	}
	if strings.Contains(rec2.Body.String(), "SECRET-ROOT-TXT") {
		t.Fatal("Filename 越界仍读到了目录外文件")
	}
}

// 对照组：DB 里的合法记录（Filename=build-ok.raw）仍能下载；即使历史 Name
// 非法，Content-Disposition 也必须回落成磁盘文件名（不把 ../ 写进响应头）。
func TestServeStoredImplantLegitRecordStillWorks(t *testing.T) {
	s, _, implantDir := newBuildersPathServer(t)
	target := filepath.Join(implantDir, "build-ok.raw")
	if err := os.WriteFile(target, []byte("PAYLOAD-OK"), 0644); err != nil {
		t.Fatal(err)
	}

	imp := &database.StoredImplant{
		ID:       "build-ok",
		Name:     "implant-1792",
		Format:   "raw",
		OS:       "linux",
		Filename: "build-ok.raw",
	}
	rec := httptest.NewRecorder()
	s.serveStoredImplant(rec, httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/build-ok", nil), imp)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法记录应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "PAYLOAD-OK" {
		t.Fatalf("载荷内容 = %q, want PAYLOAD-OK", got)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "implant-1792.raw") {
		t.Errorf("Content-Disposition = %q, want 含 implant-1792.raw", cd)
	}

	// 历史脏数据：Name 含 ../ —— 文件本身合法，但响应头不允许带路径
	impDirty := *imp
	impDirty.Name = "../../etc/passwd"
	rec2 := httptest.NewRecorder()
	s.serveStoredImplant(rec2, httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/build-ok", nil), &impDirty)
	if rec2.Code != http.StatusOK {
		t.Fatalf("Filename 合法的记录应仍可下载，实际 %d", rec2.Code)
	}
	cd := rec2.Header().Get("Content-Disposition")
	if strings.Contains(cd, "..") || strings.ContainsAny(cd, `/\`) {
		t.Errorf("Content-Disposition 带出了路径成分: %q", cd)
	}
}

// ─── 其余路径拼接点：file: 合成 ID 与 {name} 路由 ───────────────────────────

func TestFilePrefixedIDRejectsEscape(t *testing.T) {
	s, root, _ := newBuildersPathServer(t)
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	// GET /api/v1/implant/payload/file:../../outside.txt
	req := httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/file:x", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "file:../outside.txt"})
	rec := httptest.NewRecorder()
	s.downloadStoredImplantHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("file: 穿越下载应 400，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("file: 分支读到了目录外文件")
	}

	// DELETE /api/v1/implants/file:../outside.txt
	dreq := httptest.NewRequest(http.MethodDelete, "/api/v1/implants/file:x", nil)
	dreq = mux.SetURLVars(dreq, map[string]string{"id": "file:../outside.txt"})
	drec := httptest.NewRecorder()
	s.deleteStoredImplantHandler(drec, dreq)
	if drec.Code != http.StatusBadRequest {
		t.Fatalf("file: 穿越删除应 400，实际 %d: %s", drec.Code, drec.Body.String())
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("目录外文件被删除！: %v", err)
	}
}

func TestDownloadImplantHandlerRejectsEscape(t *testing.T) {
	s, root, implantDir := newBuildersPathServer(t)
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/implants/download/x", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "../outside.txt"})
	rec := httptest.NewRecorder()
	s.downloadImplantHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("越界 name 应 400，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("{name} 分支读到了目录外文件")
	}

	// 对照组：目录内文件仍可下载
	ok := filepath.Join(implantDir, "build-9.exe")
	if err := os.WriteFile(ok, []byte("EXE-OK"), 0755); err != nil {
		t.Fatal(err)
	}
	okReq := httptest.NewRequest(http.MethodGet, "/api/v1/implants/download/build-9.exe", nil)
	okReq = mux.SetURLVars(okReq, map[string]string{"name": "build-9.exe"})
	okRec := httptest.NewRecorder()
	s.downloadImplantHandler(okRec, okReq)
	if okRec.Code != http.StatusOK || okRec.Body.String() != "EXE-OK" {
		t.Fatalf("合法下载失败: %d %q", okRec.Code, okRec.Body.String())
	}
}

// ─── 复审计 N1：file: 合成 ID 只允许单段文件名 ─────────────────────────────

// TestFilePrefixIDRequiresSingleSegment 守护 N1 的修复面：旧实现允许
// "file:子目录/文件"（反斜杠在 Windows 的 {id} 里是合法分隔符），这让
// "中间某段是 junction" 有了入口。现在含 / 或 \ 一律 400。
func TestFilePrefixIDRequiresSingleSegment(t *testing.T) {
	s, root, _ := newBuildersPathServer(t)
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("SECRET-VICTIM"), 0644); err != nil {
		t.Fatal(err)
	}

	badIDs := []string{
		"file:../victim.txt",  // 父目录穿越（旧用例，保持不回归）
		"file:sub/victim.txt", // 正斜杠子路径
		`file:sub\victim.txt`, // 反斜杠子路径（Windows）
		`file:..\victim.txt`,
		"file:a/b/c",
		"file:",
	}
	for _, id := range badIDs {
		// GET 下载
		req := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/x", nil),
			map[string]string{"id": id})
		rec := httptest.NewRecorder()
		s.downloadStoredImplantHandler(rec, req)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("GET %q 应 400/404，实际 %d: %s", id, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "SECRET-VICTIM") {
			t.Errorf("GET %q 回传了目录外内容", id)
		}

		// DELETE 删除（不可逆操作）
		dreq := mux.SetURLVars(
			httptest.NewRequest(http.MethodDelete, "/api/v1/implants/x", nil),
			map[string]string{"id": id})
		drec := httptest.NewRecorder()
		s.deleteStoredImplantHandler(drec, dreq)
		if drec.Code != http.StatusBadRequest && drec.Code != http.StatusNotFound {
			t.Errorf("DELETE %q 应 400/404，实际 %d: %s", id, drec.Code, drec.Body.String())
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("目录外文件被删除！N1 回归: %v", err)
	}
}

// TestFilePrefixIDLegitDownloadStillWorks 对照：合法的 "file:<单段名>" 仍可下载/删除。
func TestFilePrefixIDLegitDownloadStillWorks(t *testing.T) {
	s, _, implantDir := newBuildersPathServer(t)
	payload := filepath.Join(implantDir, "build-1792.bin")
	if err := os.WriteFile(payload, []byte("BIN-OK"), 0644); err != nil {
		t.Fatal(err)
	}
	req := mux.SetURLVars(
		httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/file:build-1792.bin", nil),
		map[string]string{"id": "file:build-1792.bin"})
	rec := httptest.NewRecorder()
	s.downloadStoredImplantHandler(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "BIN-OK" {
		t.Fatalf("合法 file: 下载失败: %d %q", rec.Code, rec.Body.String())
	}

	// 删除合法单段文件仍生效。
	del := filepath.Join(implantDir, "build-1793.bin")
	if err := os.WriteFile(del, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	dreq := mux.SetURLVars(
		httptest.NewRequest(http.MethodDelete, "/api/v1/implants/file:build-1793.bin", nil),
		map[string]string{"id": "file:build-1793.bin"})
	drec := httptest.NewRecorder()
	s.deleteStoredImplantHandler(drec, dreq)
	if drec.Code != http.StatusOK {
		t.Fatalf("合法 file: 删除失败: %d %s", drec.Code, drec.Body.String())
	}
	if _, err := os.Stat(del); !os.IsNotExist(err) {
		t.Fatalf("合法文件应被删除，Stat err=%v", err)
	}
}

// TestFilePrefixIDRejectsJunctionSubpath 是 N1 在 HTTP handler 层的复现：
// implants/ 下放一个指向目录外的 junction，file:<junction>\<文件> 必须 400，
// 且 DELETE 不得删掉目录外文件。
func TestFilePrefixIDRejectsJunctionSubpath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction 仅 Windows")
	}
	s, root, implantDir := newBuildersPathServer(t)
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(victim, []byte("SECRET-VICTIM"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(implantDir, "link")
	makeJunctionOrSkip(t, link, outsideDir)

	for _, id := range []string{`file:link\victim.txt`, "file:link/victim.txt"} {
		req := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/api/v1/implant/payload/x", nil),
			map[string]string{"id": id})
		rec := httptest.NewRecorder()
		s.downloadStoredImplantHandler(rec, req)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("GET %q 应 400/404，实际 %d: %s", id, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "SECRET-VICTIM") {
			t.Errorf("GET %q 读到了 junction 目标内容", id)
		}

		dreq := mux.SetURLVars(
			httptest.NewRequest(http.MethodDelete, "/api/v1/implants/x", nil),
			map[string]string{"id": id})
		drec := httptest.NewRecorder()
		s.deleteStoredImplantHandler(drec, dreq)
		if drec.Code != http.StatusBadRequest && drec.Code != http.StatusNotFound {
			t.Errorf("DELETE %q 应 400/404，实际 %d: %s", id, drec.Code, drec.Body.String())
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("junction 目标文件被删除！N1 回归: %v", err)
	}
}
