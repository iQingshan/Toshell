package config

import (
	"os"
	"path/filepath"
	"testing"

	"toshell/internal/common/avops"
)

// ─── AV-Ops 配置（v1.4.0 S6）─────────────────────────────────────────────────
//
// 这一段钉住"默认必须让 L2+ 全部不可用 + 默认必须要求二次确认"：
// 它是"装上只是一个 C2"与"装上自带杀软对抗破坏能力"之间的分界线，
// 任何默认值被改宽都必须被这些用例拦住。

func loadFromYAML(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load 返回 nil")
	}
	return cfg
}

// TestAVOpsDefaultsAreFailClosed 没有 avops 段时：L2/L3/L4 全关、确认要求为真、
// 超时用 avops 包的默认常量（单一来源，避免"注释/viper/运行时兜底"三处漂移）。
func TestAVOpsDefaultsAreFailClosed(t *testing.T) {
	cfg := loadFromYAML(t, "server:\n    api_port: 18081\n")

	if cfg.AVOps.AllowL2 || cfg.AVOps.AllowL3 || cfg.AVOps.AllowL4 {
		t.Fatalf("默认配置下 L2+ 必须全部不可用，实际 %+v", cfg.AVOps)
	}
	// RequireConfirm 是 *bool：nil（未配置）也必须等价于"要求确认"。
	policy := policyOf(cfg)
	if policy.SkipConfirm {
		t.Fatal("默认配置下不允许跳过二次确认（零值/未配置都必须落在最严一侧）")
	}
	if policy.DefaultTimeoutSec != avops.DefaultTimeoutSec || policy.MaxTimeoutSec != avops.MaxTimeoutSec {
		t.Fatalf("默认超时 = %d/%d, want %d/%d（必须与 avops 常量同源）",
			policy.DefaultTimeoutSec, policy.MaxTimeoutSec, avops.DefaultTimeoutSec, avops.MaxTimeoutSec)
	}
	for _, tier := range []avops.Tier{avops.TierL2, avops.TierL3, avops.TierL4} {
		if ok, _ := policy.TierAllowed(tier); ok {
			t.Errorf("默认配置下 %s 不应允许执行", tier)
		}
	}
	if ok, _ := policy.TierAllowed(avops.TierL1); !ok {
		t.Error("默认配置下 L1 应允许（默认开 + 需确认）")
	}
}

// TestAVOpsExplicitOverrides 显式写进配置的值必须生效
// （否则"改了配置却不生效"是比默认值更糟的哑失败）。
func TestAVOpsExplicitOverrides(t *testing.T) {
	cfg := loadFromYAML(t, `
server:
    api_port: 18081
avops:
    allow_l2: true
    allow_l3: true
    allow_l4: true
    require_confirm: false
    default_timeout_sec: 33
    max_timeout_sec: 44
`)
	if !cfg.AVOps.AllowL2 || !cfg.AVOps.AllowL3 || !cfg.AVOps.AllowL4 {
		t.Fatalf("显式开启的 allow_* 未生效：%+v", cfg.AVOps)
	}
	if cfg.AVOps.RequireConfirm == nil {
		t.Fatal("显式写了 require_confirm 却解析成 nil（*bool 未生效：这个键会变成哑配置）")
	}
	if *cfg.AVOps.RequireConfirm {
		t.Fatal("require_confirm: false 未生效")
	}
	if n := cfg.AVOps.DefaultTimeoutSec; n != 33 {
		t.Fatalf("default_timeout_sec = %d, want 33", n)
	}
	if n := cfg.AVOps.MaxTimeoutSec; n != 44 {
		t.Fatalf("max_timeout_sec = %d, want 44", n)
	}
	p := policyOf(cfg)
	if !p.SkipConfirm {
		t.Fatal("require_confirm=false 未映射到策略（SkipConfirm 应为 true）")
	}
	if ok, reason := p.TierAllowed(avops.TierL4); !ok {
		t.Fatalf("allow_l4=true 时 L4 应放行，实际：%s", reason)
	}
}

// policyOf 复刻 api 层"配置 → 策略"的映射，用于断言映射本身的口径。
// 单独写在测试里而不是引用 api 包：config 包不能反向依赖 api（会成环）。
func policyOf(cfg *Config) avops.Policy {
	skip := false
	if cfg.AVOps.RequireConfirm != nil && !*cfg.AVOps.RequireConfirm {
		skip = true
	}
	return avops.Policy{
		AllowL2:           cfg.AVOps.AllowL2,
		AllowL3:           cfg.AVOps.AllowL3,
		AllowL4:           cfg.AVOps.AllowL4,
		SkipConfirm:       skip,
		DefaultTimeoutSec: cfg.AVOps.DefaultTimeoutSec,
		MaxTimeoutSec:     cfg.AVOps.MaxTimeoutSec,
	}.Normalize()
}
