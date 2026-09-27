package listener

import (
	"fmt"
	"testing"
	"time"

	"toshell/internal/common/features"
	"toshell/internal/common/types"
	"toshell/internal/server/session"
)

// TestApplyHeartbeatModules 心跳负载里的能力位必须写回会话，否则
// /sessions/{id}/capabilities 只能按 OS 兜底猜（S4 要修的根因之一：
// 各通道的 handleHeartbeat 只刷新 LastSeen、从不解析负载）。
func TestApplyHeartbeatModules(t *testing.T) {
	mgr := session.New()
	id := fmt.Sprintf("hb-%d", time.Now().UnixNano())
	if err := mgr.Add(&types.SessionInfo{ID: id, Hostname: "PC1", OS: "Windows 11"}); err != nil {
		t.Fatalf("session Add: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Remove(id) })

	token := features.EncodeToken(features.Input{Profile: "light", OS: "windows"})
	applyHeartbeatModules(mgr, id, []byte(`{"Status":"alive","CPUUsage":0,"MemoryUsed":0,"Modules":["`+token+`"]}`))

	sess, err := mgr.Get(id)
	if err != nil || sess == nil || sess.Info == nil {
		t.Fatalf("session Get: %v", err)
	}
	if len(sess.Info.ActiveModules) != 1 || sess.Info.ActiveModules[0] != token {
		t.Fatalf("ActiveModules = %v, want [%s]", sess.Info.ActiveModules, token)
	}

	// 老载荷/异常负载（没有 Modules、非法 JSON、空负载）不得清空已上报的值，
	// 也不得 panic —— 心跳的保活语义不能被这个附加字段影响。
	for _, payload := range [][]byte{
		[]byte(`{"Status":"alive"}`),
		nil,
		[]byte(``),
		[]byte(`not json`),
		[]byte(`{"Modules":[]}`),
	} {
		applyHeartbeatModules(mgr, id, payload)
	}
	sess, _ = mgr.Get(id)
	if len(sess.Info.ActiveModules) != 1 || sess.Info.ActiveModules[0] != token {
		t.Fatalf("老载荷/异常负载不该清掉已上报的能力位：%v", sess.Info.ActiveModules)
	}

	// 未注册的会话 id 不得 panic。
	applyHeartbeatModules(mgr, "no-such-session", []byte(`{"Modules":["bof_load"]}`))
	// nil 管理器不得 panic（部分精简装配）。
	applyHeartbeatModules(nil, id, []byte(`{"Modules":["bof_load"]}`))
}
