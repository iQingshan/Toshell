//go:build webui

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEmbeddedWebdistAssetsExist 守住"内嵌前端能真的加载起来"。
//
// 背景（v1.4.2 实测事故）：`cmd/server/webdist` 是在构建前从 `web/dist` 同步过来的
// （该目录被 gitignore）。用 PowerShell 的
// `Copy-Item web\dist\* cmd\server\webdist\ -Recurse`
// 在**目标目录不存在**时会把 `assets/` 的内容**摊平**到 webdist 根目录，于是
// index.html 里引用的 `assets/index-xxx.js` 全部 404 → SPA 回退把 index.html 当 JS 返回
// → 浏览器报 "Expected a JavaScript-or-Wasm module script but the server responded with
// a MIME type of text/html" → **白屏**。
//
// 这类问题编译期完全看不出来（embed 不校验引用），只能靠"引用 ↔ 实际文件"的断言兜住。
func TestEmbeddedWebdistAssetsExist(t *testing.T) {
	const dir = "webdist"
	indexPath := filepath.Join(dir, "index.html")
	body, err := os.ReadFile(indexPath)
	if err != nil {
		t.Skipf("没有内嵌前端（%s 不存在，属正常：本地未同步 web/dist；CI 会先构建前端）", indexPath)
	}
	html := string(body)

	// 抓 index.html 里所有 assets/xxx 引用（js + css）
	re := regexp.MustCompile(`assets/[A-Za-z0-9_.-]+\.(?:js|css)`)
	refs := re.FindAllString(html, -1)
	if len(refs) == 0 {
		t.Fatalf("index.html 里没有任何 assets/ 引用，构建产物异常：%s", indexPath)
	}
	for _, ref := range refs {
		p := filepath.Join(dir, filepath.FromSlash(ref))
		fi, err := os.Stat(p)
		if err != nil {
			t.Errorf("index.html 引用了 %s，但 %s 不存在（同步 web/dist 时 assets 目录被摊平了？）", ref, p)
			continue
		}
		if fi.Size() == 0 {
			t.Errorf("%s 是空文件，前端必然白屏", p)
		}
	}

	// 反向断言：webdist 根目录不该出现被打散的 assets 文件（唯一例外是 favicon.svg）
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取 %s 失败：%v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "index.html" || name == "favicon.svg" || name == "robots.txt" {
			continue
		}
		if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css") {
			t.Errorf("webdist 根目录出现了被打散的 %s —— 应该在 assets/ 下；用 `New-Item webdist; Copy-Item web\\dist\\* webdist -Recurse` 重新同步", name)
		}
	}
}
