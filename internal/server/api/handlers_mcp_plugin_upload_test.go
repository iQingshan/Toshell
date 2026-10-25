package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toshell/internal/server/plugin"
)

// buildMultipart 构造一个 multipart/form-data 请求体（字段 file + 可选 description）。
func buildMultipart(t *testing.T, filename, description string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if description != "" {
		if err := mw.WriteField("description", description); err != nil {
			t.Fatalf("写 description 字段失败: %v", err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("创建 file 表单字段失败: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("写入表单文件失败: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("关闭 multipart writer 失败: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// TestMCPPluginUploadRejectsTraversalName 是审计 H4 的 handler 级回归：
//
//	POST /api/v1/mcp/tools/plugin_upload {"source":"evil.txt","name":"../../victim-out.exe"}
//
// 必须返回 4xx，且不能有文件被写出；随后验证：
//   - 未知扩展名的 name 同样被拒（不静默当某种类型处理）；
//   - 合法名（demo_plugin.exe）仍然上传成功，且 GET /api/v1/plugins 能看到；
//   - name 缺省时用 source 的纯文件名（source 允许 data/tools 下的相对子路径）。
func TestMCPPluginUploadRejectsTraversalName(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(filepath.Join(work, "data", "tools"), 0o755); err != nil {
		t.Fatalf("创建 data/tools 失败: %v", err)
	}
	// handler 里的 resolveToolPath 以进程 CWD 为基准拼 data/tools，故切到临时目录。
	t.Chdir(work)

	if err := os.WriteFile(filepath.Join("data", "tools", "evil.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatalf("写入 data/tools/evil.txt 失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Join("data", "tools", "sub"), 0o755); err != nil {
		t.Fatalf("创建 data/tools/sub 失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join("data", "tools", "sub", "nested_plugin.bin"), []byte("nested"), 0o644); err != nil {
		t.Fatalf("写入 data/tools/sub/nested_plugin.bin 失败: %v", err)
	}

	pluginDir := filepath.Join(work, "plugins")
	mgr, ierr := plugin.Init(pluginDir)
	if ierr != nil {
		t.Fatalf("初始化 plugin manager 失败: %v", ierr)
	}
	// plugin.Init 是进程级单例（sync.Once）：若本次进程已被其它用例初始化到别的目录，
	// 不强行改全局状态，明确跳过而不是给出假结果。
	if dir, _ := mgr.GetPluginInfo()["dir"].(string); dir != pluginDir {
		t.Skipf("plugin 包全局单例已被初始化为 %q（-count>1 或其它用例），无法为本次测试重设目录", dir)
	}

	s := &Server{}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tools/plugin_upload", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.mcpToolInvokeHandler(rec, req)
		return rec
	}

	// 1) 审计 PoC 等价形式：穿越 name 必须是 4xx，且没有任何文件写出。
	rec := post(`{"source":"evil.txt","name":"../../victim-out.exe"}`)
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
		t.Fatalf("穿越 name 状态码 = %d，期望 400/403；body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "插件名") {
		t.Fatalf("错误消息不明确（期望中文插件名错误）：%s", rec.Body.String())
	}
	for _, p := range []string{
		filepath.Join(base, "victim-out.exe"),
		filepath.Join(work, "victim-out.exe"),
	} {
		if _, serr := os.Stat(p); !os.IsNotExist(serr) {
			t.Fatalf("穿越写入发生了：%s 存在 (stat err=%v)", p, serr)
		}
	}
	if entries, _ := os.ReadDir(pluginDir); len(entries) != 0 {
		t.Fatalf("插件目录不应有文件，实际 %d 个", len(entries))
	}

	// 2) 未知扩展名（.txt 不在白名单）同样 4xx，不落盘。
	rec = post(`{"source":"evil.txt","name":"demo_plugin.txt"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知扩展名状态码 = %d，期望 400；body=%s", rec.Code, rec.Body.String())
	}
	if _, serr := os.Stat(filepath.Join(pluginDir, "demo_plugin.txt")); !os.IsNotExist(serr) {
		t.Fatal("未知扩展名的文件被写出")
	}

	// 3) 正常路径：合法名仍必须上传成功，并能被 GET /api/v1/plugins 列出。
	rec = post(`{"source":"evil.txt","name":"demo_plugin.exe"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法插件上传状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	if _, serr := os.Stat(filepath.Join(pluginDir, "demo_plugin.exe")); serr != nil {
		t.Fatalf("plugins/demo_plugin.exe 未写出: %v", serr)
	}
	lrec := httptest.NewRecorder()
	s.listPluginsHandler(lrec, httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil))
	if !strings.Contains(lrec.Body.String(), "demo_plugin.exe") {
		t.Fatalf("GET /api/v1/plugins 未列出 demo_plugin.exe：%s", lrec.Body.String())
	}

	// 4) name 缺省：用 source 的纯文件名（source 可带子目录）。
	rec = post(`{"source":"sub/nested_plugin.bin"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("name 缺省上传状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	if _, serr := os.Stat(filepath.Join(pluginDir, "nested_plugin.bin")); serr != nil {
		t.Fatalf("name 缺省时未按 basename 落盘: %v", serr)
	}

	// 5) 预置符号链接指向 plugins 内的 victim：handler 必须 4xx 且不写链接目标。
	//    Windows 无创建符号链接权限时跳过（真机验证脚本里另行说明）。
	victim := filepath.Join(pluginDir, "victim.txt")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil {
		t.Fatalf("写入 victim 失败: %v", err)
	}
	link := filepath.Join(pluginDir, "symlink_attack.exe")
	if serr := os.Symlink(victim, link); serr != nil {
		t.Logf("跳过符号链接用例：当前环境无法创建符号链接（%v）", serr)
	} else {
		rec = post(`{"source":"evil.txt","name":"symlink_attack.exe"}`)
		if rec.Code < 400 || rec.Code >= 500 {
			t.Fatalf("符号链接目标状态码 = %d，期望 4xx；body=%s", rec.Code, rec.Body.String())
		}
		if got, _ := os.ReadFile(victim); string(got) != "original" {
			t.Fatalf("符号链接目标被写入！内容 = %q", got)
		}
	}

	// 6) multipart 上传（POST /api/v1/plugins）：中文名必须成功（200，不是 500）。
	upload := func(filename string) *httptest.ResponseRecorder {
		body, ct := buildMultipart(t, filename, "上传用例", []byte("multipart-payload"))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.uploadPluginHandler(rec, req)
		return rec
	}

	rec = upload("我的插件.exe")
	if rec.Code != http.StatusOK {
		t.Fatalf("multipart 中文名状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	if _, serr := os.Stat(filepath.Join(pluginDir, "我的插件.exe")); serr != nil {
		t.Fatalf("multipart 中文名未落盘: %v", serr)
	}

	// 7) multipart 带 ".." 的 filename：必须 400，且不得写出任何文件（含归一后的 x.exe）。
	rec = upload("../x.exe")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multipart 穿越名状态码 = %d，期望 400；body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "穿越") {
		t.Fatalf("multipart 穿越名错误消息不明确：%s", rec.Body.String())
	}
	for _, p := range []string{
		filepath.Join(pluginDir, "x.exe"),
		filepath.Join(work, "x.exe"),
	} {
		if _, serr := os.Stat(p); !os.IsNotExist(serr) {
			t.Fatalf("multipart 穿越写入了 %s (stat err=%v)", p, serr)
		}
	}

	// 8) multipart 未知扩展名：400（不是 500），且不落盘。
	rec = upload("evil.txt")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multipart 未知扩展名状态码 = %d，期望 400；body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "扩展名") {
		t.Fatalf("multipart 未知扩展名错误消息不明确：%s", rec.Body.String())
	}
	if _, serr := os.Stat(filepath.Join(pluginDir, "evil.txt")); !os.IsNotExist(serr) {
		t.Fatal("multipart 未知扩展名的文件被写出")
	}

	// 9) multipart 带空格文件名：正常字符集放宽后必须成功。
	rec = upload("cred probe.exe")
	if rec.Code != http.StatusOK {
		t.Fatalf("multipart 空格名状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	if _, serr := os.Stat(filepath.Join(pluginDir, "cred probe.exe")); serr != nil {
		t.Fatalf("multipart 空格名未落盘: %v", serr)
	}
}
