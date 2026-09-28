package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// 本文件守护 v1.4.0 S6 的附带修复：**配置热重载失败必须显式可见**。
//
// 修的既有缺陷：viper 热重载回调只检查 Apply() 的返回值，而 Apply 只是把 viper
// 内存里的旧值再解一遍 —— 配置文件被写坏时它照样"成功"，于是服务端静默沿用旧配置，
// 日志却照旧打"已自动热重载"。操作员以为配置生效了，实际没有。
//
// 这里不去 sleep 等 fsnotify 事件（不可靠也慢），而是直接调"读取+解析+应用+记录"
// 那个可直接调用的函数 Reload()。

// brokenYAML 是一份**确定非法**的 YAML：先用 yaml.Unmarshal 自检，
// 避免哪天 yaml 库放宽了语法导致"测试用例本身失效"（那时它测的就不是坏文件了）。
const brokenYAML = "listener:\n    port: 19999\n  bad: \"unterminated\n"

func TestReloadRejectsBrokenYAMLAndKeepsOldConfig(t *testing.T) {
	// 先自检 fixture：这份内容必须是坏 YAML
	var probe interface{}
	if yaml.Unmarshal([]byte(brokenYAML), &probe) == nil {
		t.Fatalf("测试用例自身有问题：brokenYAML 竟然能被解析，请换一份非法 YAML")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	valid := "server:\n    api_port: 18581\nlistener:\n    port: 18777\n    heartbeat_timeout: 60s\n"
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := Get().Listener.Port; got != 18777 {
		t.Fatalf("初始配置未生效：listener.port=%d", got)
	}
	failuresBefore := LastReload().Failures

	// 把配置文件写坏（模拟操作员手改配置改错、或写入过程被中断）
	if err := os.WriteFile(path, []byte(brokenYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) 必须返回错误 —— 历史缺陷下这里是"静默成功"
	if err := Reload(); err == nil {
		t.Fatal("配置文件是非法 YAML 时 Reload 必须返回错误（历史缺陷：静默沿用旧配置）")
	}

	// 2) 必须是 error 级可见状态，且带原始错误
	st := LastReload()
	if st.OK {
		t.Error("重载失败后 LastReload().OK 必须为 false")
	}
	if st.Error == "" {
		t.Error("重载失败后 LastReload().Error 必须是原始错误文本（不能只给布尔）")
	}
	if st.Failures <= failuresBefore {
		t.Errorf("重载失败次数没有增加：before=%d after=%d", failuresBefore, st.Failures)
	}
	if st.At.IsZero() {
		t.Error("重载失败也必须记录时间，否则无法判断「最后一次生效是什么时候」")
	}

	// 3) 旧配置必须保持不变（服务端还能继续用旧值跑）
	if got := Get().Listener.Port; got != 18777 {
		t.Errorf("重载失败后配置被改动了：listener.port=%d，期望仍是 18777", got)
	}
	if got := Get().Listener.HeartbeatTimeout; got != 60*time.Second {
		t.Errorf("重载失败后配置被改动了：heartbeat_timeout=%v，期望仍是 60s", got)
	}
	// viper 内存态同样不能被坏文件污染（这才是"静默"的本质：坏文件根本没进 viper）
	if got := viper.GetInt("listener.port"); got != 18777 {
		t.Errorf("重载失败后 viper 内存态被污染：listener.port=%d，期望 18777", got)
	}

	// 4) 修好文件后必须能恢复：新的合法配置要真的生效
	fixed := "server:\n    api_port: 18581\nlistener:\n    port: 19001\n    heartbeat_timeout: 30s\n"
	if err := os.WriteFile(path, []byte(fixed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Reload(); err != nil {
		t.Fatalf("修好配置文件后 Reload 仍失败：%v", err)
	}
	st = LastReload()
	if !st.OK || st.Error != "" {
		t.Errorf("恢复后状态应为成功且无错误：ok=%v err=%q", st.OK, st.Error)
	}
	if got := Get().Listener.Port; got != 19001 {
		t.Errorf("修好配置后新值未生效：listener.port=%d，期望 19001", got)
	}
	if got := Get().Listener.HeartbeatTimeout; got != 30*time.Second {
		t.Errorf("修好配置后新值未生效：heartbeat_timeout=%v，期望 30s", got)
	}
}

// TestReloadAppliesValidConfig 守护成功路径：合法配置必须真的被应用，
// 且 LastReload() 回传"成功 + 无错误"，供 health / 设置页诊断出口使用。
func TestReloadAppliesValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("listener:\n    port: 18777\n    mimicry_profile: cdn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	next := "listener:\n    port: 18888\n    mimicry_profile: nginx\n"
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	cfg := Get()
	if cfg.Listener.Port != 18888 {
		t.Errorf("listener.port=%d，期望 18888", cfg.Listener.Port)
	}
	if cfg.Listener.MimicryProfile != "nginx" {
		t.Errorf("mimicry_profile=%q，期望 nginx（热重载必须整体替换配置）", cfg.Listener.MimicryProfile)
	}
	st := LastReload()
	if !st.OK {
		t.Error("成功重载后 LastReload().OK 必须为 true")
	}
	if st.Error != "" {
		t.Errorf("成功重载后 LastReload().Error 必须为空，实际 %q", st.Error)
	}
	if st.Path == "" {
		t.Error("LastReload().Path 必须记录实际生效的配置文件路径（排障要看它）")
	}
	if st.Attempts < 2 {
		t.Errorf("Attempts=%d：初次加载 + 一次热重载至少 2 次", st.Attempts)
	}
}

// TestReloadStatusExposedForDiagnostics 守护"重载结果有既有出口"这条：
// 状态必须是可并发安全读取的副本，且字段语义稳定（health / 设置页直接读它）。
func TestReloadStatusExposedForDiagnostics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("listener:\n    port: 18777\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	a := LastReload()
	b := LastReload()
	if a.Attempts != b.Attempts || a.OK != b.OK || a.Path != b.Path {
		t.Errorf("LastReload 两次读取不一致：%+v / %+v（必须是稳定副本）", a, b)
	}
	if a.Path != path {
		t.Errorf("LastReload().Path=%q，期望 %q", a.Path, path)
	}
}
