package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoListenerUnavailableAs500 源码级守卫：不允许再把"listener 未就绪"报成 500。
//
// 为什么用源码扫描而不是行为断言：这类问题是**散落在十几个 handler 里的同一个错误码**，
// 行为用例只能覆盖被点名的那几个路由，新写的 handler 照样会再犯（v1.4.0 之前就是这样：
// e2e 探针只打了 screen-stream 一个点，其余下发类 handler 一直把会话不存在报成 500）。
// 扫描源码能把"整个类"钉住：要么用 helpers（requireListener / requireSessionFromPath），
// 要么明确写 4xx/503。
//
// 与 builder 的 gate_scan_test.go 同一思路：把"约定"变成 CI 能跑的断言。
func TestNoListenerUnavailableAs500(t *testing.T) {
	bad := []struct {
		name string
		re   *regexp.Regexp
		hint string
	}{
		{
			name: "listener 未就绪被报成 500",
			re:   regexp.MustCompile(`(?s)http\.Error\(w,\s*` + "`" + `\{"error":"Listener not available"\}` + "`" + `\s*,\s*http\.StatusInternalServerError\)`),
			hint: "请改用 s.requireListener(w)（503 listener_unavailable）",
		},
		{
			name: "会话不存在被报成 500",
			re:   regexp.MustCompile(`(?s)http\.Error\(w,.*?session not found.*?http\.StatusInternalServerError\)`),
			hint: "请改用 s.requireSession/requireSessionFromPath（404 session_not_found）",
		},
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// 守卫实现自身当然会提到这些字符串（它负责写 404/503），跳过。
		if name == "handlers_session_guard.go" {
			continue
		}
		b, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			t.Fatalf("ReadFile %s: %v", name, rerr)
		}
		src := string(b)
		scanned++
		for _, c := range bad {
			if c.re.MatchString(src) {
				t.Errorf("%s：%s（%s）", name, c.name, c.hint)
			}
		}
	}
	if scanned < 10 {
		t.Fatalf("只扫描到 %d 个源文件，守卫没起作用（目录不对？）", scanned)
	}
}
