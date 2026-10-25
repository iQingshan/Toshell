package listener

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"toshell/internal/common/protocol"
	"toshell/internal/common/types"
	"toshell/internal/server/config"
	"toshell/internal/server/session"
	"toshell/internal/server/task"
)

// ─── 测试替身 ─────────────────────────────────────────────────────────────

// fakeTaskManager 只实现 HTTP 轮询用到的部分，GetNext 会真实"取走"任务，
// 用来证明未认证请求没有把任务抢走。
type fakeTaskManager struct {
	tasks        map[string][]*types.TaskInfo
	getNextCalls int
}

func (f *fakeTaskManager) GetNext(sessionID string) (*types.TaskInfo, error) {
	f.getNextCalls++
	q := f.tasks[sessionID]
	if len(q) == 0 {
		return nil, nil
	}
	t := q[0]
	f.tasks[sessionID] = q[1:]
	return t, nil
}

func (f *fakeTaskManager) GetNextBatch(sessionID string, max int) []*types.TaskInfo {
	q := f.tasks[sessionID]
	if len(q) == 0 {
		return nil
	}
	if len(q) > max {
		q = q[:max]
	}
	f.tasks[sessionID] = f.tasks[sessionID][len(q):]
	return q
}

func (f *fakeTaskManager) Complete(uint64, int32, string, string) error { return nil }
func (f *fakeTaskManager) Fail(uint64, string) error                    { return nil }
func (f *fakeTaskManager) FailWithResult(uint64, int32, string, string) error {
	return nil
}
func (f *fakeTaskManager) Get(uint64) (*types.TaskInfo, error) { return nil, nil }
func (f *fakeTaskManager) UpdateProgress(uint64, int) error    { return nil }
func (f *fakeTaskManager) ListReplayable(string) []*types.TaskInfo {
	return nil
}
func (f *fakeTaskManager) RequeueSent(string, time.Duration) int      { return 0 }
func (f *fakeTaskManager) TrackTransfer(uint64, string, int64, int64) {}
func (f *fakeTaskManager) GetTransfer(uint64) (*task.TransferState, bool) {
	return nil, false
}
func (f *fakeTaskManager) ClearTransfer(uint64) {}

// newTestHTTPListener 构造一个无 sessionMgr 的 HTTP 监听器（/task 路径不需要它）。
func newTestHTTPListener(t *testing.T, tm TaskManager) *HTTPListener {
	t.Helper()
	l, err := NewHTTPListener(&config.ListenerConfig{
		EncryptionKey: "0123456789abcdef0123456789abcdef", // 32 字节 AES-256
		Port:          18700,
	}, nil, tm)
	if err != nil {
		t.Fatalf("NewHTTPListener: %v", err)
	}
	return l
}

// encryptFrame 按线上格式封装请求体：AES-GCM(compress(TSHL 帧))。
func encryptFrame(t *testing.T, l *HTTPListener, p *protocol.Packet) []byte {
	t.Helper()
	compressed, err := compress(encodePacket(p))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	body, err := l.encryptor.Encrypt(compressed)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return body
}

// decodeFrame 解开响应体，返回内部 TSHL 帧。
func decodeFrame(t *testing.T, l *HTTPListener, body []byte) *protocol.Packet {
	t.Helper()
	dec, err := l.encryptor.Decrypt(body)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	plain, err := decompressData(dec)
	if err != nil {
		t.Fatalf("decompress response: %v", err)
	}
	p, err := parsePacket(plain)
	if err != nil || p == nil {
		t.Fatalf("parse response: %v", err)
	}
	return p
}

// ─── M2：/task 必须带会话令牌 ──────────────────────────────────────────────

// TestTaskHTTPRejectsWithoutToken 未认证（无 token）的 /task 必须 403，
// 且**不得调用 GetNext**（任务仍在 pending，植入端还能领到）。
func TestTaskHTTPRejectsWithoutToken(t *testing.T) {
	const sid = "1122334455667788"
	fm := &fakeTaskManager{tasks: map[string][]*types.TaskInfo{
		sid: {{ID: 42, TaskType: "command", Command: "id"}},
	}}
	l := newTestHTTPListener(t, fm)

	rec := httptest.NewRecorder()
	l.handleTaskHTTP(rec, httptest.NewRequest(http.MethodGet, "/task?session_id="+sid, nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("无 token 时状态码 = %d，want 403", rec.Code)
	}
	if fm.getNextCalls != 0 {
		t.Fatalf("无 token 时不得调用 GetNext（任务已被抢走），calls=%d", fm.getNextCalls)
	}
	if got := len(fm.tasks[sid]); got != 1 {
		t.Fatalf("任务必须仍在队列（pending），got %d 条", got)
	}

	// token 属于别的会话 → 同样 403，且不再调用 GetNext。
	if _, err := l.issueSessionToken("other-session"); err != nil {
		t.Fatal(err)
	}
	otherTok, _ := l.sessionToken("other-session")
	rec = httptest.NewRecorder()
	l.handleTaskHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/task?session_id="+sid+"&token="+otherTok, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("别的会话的 token 状态码 = %d，want 403", rec.Code)
	}
	if fm.getNextCalls != 0 {
		t.Fatalf("token 不匹配时不得调用 GetNext，calls=%d", fm.getNextCalls)
	}

	// 空 token 参数也不能 fail-open。
	rec = httptest.NewRecorder()
	l.handleTaskHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/task?session_id="+sid+"&token=", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("空 token 状态码 = %d，want 403", rec.Code)
	}
}

// TestTaskHTTPAcceptsWithToken 带正确 token 时 200 并拿到任务内容。
func TestTaskHTTPAcceptsWithToken(t *testing.T) {
	const sid = "aabbccddeeff0011"
	fm := &fakeTaskManager{tasks: map[string][]*types.TaskInfo{
		sid: {{ID: 7, TaskType: "command", Command: "whoami"}},
	}}
	l := newTestHTTPListener(t, fm)

	tok, err := l.issueSessionToken(sid)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	l.handleTaskHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/task?session_id="+sid+"&token="+tok, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("带正确 token 状态码 = %d，want 200（body=%s）", rec.Code, rec.Body.String())
	}
	p := decodeFrame(t, l, rec.Body.Bytes())
	var task protocol.Task
	if err := json.Unmarshal(p.Payload, &task); err != nil {
		t.Fatalf("任务 JSON: %v", err)
	}
	if task.ID != 7 || task.Command != "whoami" {
		t.Fatalf("拿到的任务 = %+v，want ID=7 Command=whoami", task)
	}
	if fm.getNextCalls != 1 {
		t.Fatalf("GetNext 调用次数 = %d，want 1", fm.getNextCalls)
	}
}

// TestHTTPRegisterIssuesSessionToken 注册响应必须下发 token，且重复注册会
// 轮换（旧 token 立即失效），服务端按 session_id 索引校验。
func TestHTTPRegisterIssuesSessionToken(t *testing.T) {
	mgr := session.New()
	sid := fmt.Sprintf("%016x", uint64(time.Now().UnixNano()))
	id, err := strconv.ParseUint(sid, 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Remove(sid) })

	l, err := NewHTTPListener(&config.ListenerConfig{
		EncryptionKey: "0123456789abcdef0123456789abcdef",
	}, mgr, nil)
	if err != nil {
		t.Fatal(err)
	}

	register := func() string {
		payload, _ := json.Marshal(protocol.Register{Hostname: "HOST-1", Username: "tester"})
		body := encryptFrame(t, l, &protocol.Packet{
			Magic:     [4]byte{'T', 'S', 'H', 'L'},
			Version:   protocol.Version,
			Type:      protocol.TypeRegister,
			ID:        id,
			Timestamp: uint64(time.Now().UnixMilli()),
			Payload:   payload,
		})
		rec := httptest.NewRecorder()
		l.handleRegisterHTTP(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("注册状态码 = %d，want 200（body=%s）", rec.Code, rec.Body.String())
		}
		p := decodeFrame(t, l, rec.Body.Bytes())
		var resp struct {
			Status       string `json:"status"`
			SessionID    string `json:"session_id"`
			SessionToken string `json:"session_token"`
		}
		if err := json.Unmarshal(p.Payload, &resp); err != nil {
			t.Fatalf("注册响应 JSON: %v", err)
		}
		if resp.Status != "registered" || resp.SessionID != sid {
			t.Fatalf("注册响应 = %+v，want status=registered session_id=%s", resp, sid)
		}
		if len(resp.SessionToken) != 64 {
			t.Fatalf("session_token 长度 = %d，want 64（32 字节 hex），token=%q", len(resp.SessionToken), resp.SessionToken)
		}
		if !l.verifySessionToken(sid, resp.SessionToken) {
			t.Fatalf("下发的 token 未通过服务端校验")
		}
		return resp.SessionToken
	}

	first := register()
	second := register()
	if first == second {
		t.Fatalf("重复注册应轮换 token（每次上线一个会话令牌）")
	}
	if l.verifySessionToken(sid, first) {
		t.Fatalf("旧 token 必须立即失效")
	}
	if !l.verifySessionToken(sid, second) {
		t.Fatalf("新 token 应通过校验")
	}

	// 会话删除后 token 应被清理（pruneSessionTokens）。
	if err := mgr.Remove(sid); err != nil {
		t.Fatal(err)
	}
	l.pruneSessionTokens()
	if _, ok := l.sessionToken(sid); ok {
		t.Fatalf("会话删除后 token 必须被清理")
	}
}

// ─── M4：请求体上限 ───────────────────────────────────────────────────────

// TestReadPollBodyLimit 直接验证体积上限工具函数：超限 → 413。
func TestReadPollBodyLimit(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte("12345")))
	if _, ok := readPollBody(rec, req, 4); ok {
		t.Fatalf("超过上限的 body 必须被拒绝")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("状态码 = %d，want 413", rec.Code)
	}
}

// TestHTTPPollingHandlersRejectOversizedBody 每个加了上限的入口都被覆盖：
// 超限一律 413（不是 200、不是 500），且不会继续走解密/落库逻辑。
func TestHTTPPollingHandlersRejectOversizedBody(t *testing.T) {
	const sid = "1122334455667788"
	fm := &fakeTaskManager{tasks: map[string][]*types.TaskInfo{}}
	l := newTestHTTPListener(t, fm)

	small := make([]byte, maxPollSmallBodyBytes+1)
	large := make([]byte, maxPollChunkBodyBytes+1)

	cases := []struct {
		name string
		path string
		body []byte
		call func(w http.ResponseWriter, r *http.Request)
	}{
		{"register", "/register", small, l.handleRegisterHTTP},
		{"heartbeat", "/heartbeat", small, l.handleHeartbeatHTTP},
		{"result", "/result", large, l.handleResultHTTP},
		{"tunnel", "/tunnel", large, l.handleTunnelHTTP},
		{"shell", "/shell", large, l.handleShellHTTP},
		{"file", "/file", large, l.handleFileHTTP},
		{"file/pull", "/file/pull", large, l.handleFilePullHTTP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(tc.body))
			tc.call(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s 超限 body 状态码 = %d，want 413（body=%q）", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
	if fm.getNextCalls != 0 {
		t.Fatalf("超限请求不得触发任务逻辑，GetNext calls=%d", fm.getNextCalls)
	}
}

// TestHTTPRegisterRejectsOversizedBodyWithoutSideEffect 注册超限不得创建会话。
func TestHTTPRegisterRejectsOversizedBodyWithoutSideEffect(t *testing.T) {
	mgr := session.New()
	sid := fmt.Sprintf("%016x", uint64(time.Now().UnixNano()))
	t.Cleanup(func() { _ = mgr.Remove(sid) })

	l, err := NewHTTPListener(&config.ListenerConfig{
		EncryptionKey: "0123456789abcdef0123456789abcdef",
	}, mgr, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{0xAB}, int(maxPollSmallBodyBytes)+1)
	rec := httptest.NewRecorder()
	l.handleRegisterHTTP(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("状态码 = %d，want 413", rec.Code)
	}
	if _, err := mgr.Get(sid); err == nil {
		t.Fatalf("超限注册请求不得创建会话")
	}
}

// ─── M7：解压超限在 HTTP 通道返回 413 ─────────────────────────────────────

// TestHTTPRegisterRejectsCompressionBomb 小 body、解压后 > 32 MiB 的帧必须
// 被 413 拒绝（而不是把 32 MiB 截断后继续解析，更不是 OOM）。
func TestHTTPRegisterRejectsCompressionBomb(t *testing.T) {
	l := newTestHTTPListener(t, &fakeTaskManager{})

	// 构造一个合法 TSHL 帧，再把它塞进一个解压后 40 MiB 的 gzip 流：
	// 直接在 gzip 里写 40 MiB 0 字节 + 帧尾巴即可（服务端会先撞上限）。
	var big bytes.Buffer
	gw := gzip.NewWriter(&big)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 40; i++ {
		if _, err := gw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := l.encryptor.Encrypt(big.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > int(maxPollChunkBodyBytes) {
		t.Fatalf("测试帧体积 %d 超过 body 上限，应只触发解压上限", len(body))
	}

	rec := httptest.NewRecorder()
	l.handleRegisterHTTP(rec, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("压缩炸弹状态码 = %d，want 413（body=%q）", rec.Code, rec.Body.String())
	}
}
