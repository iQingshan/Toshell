package mcp

import (
	"encoding/json"
	"fmt"
	"time"
)

// 统一结果信封：所有工具（内置 AI、REST、对外 MCP）返回同一形状，上层可用代码确定性处理，
// 不再出现"有的返回纯文本、有的返回 JSON、错误走 HTTP 404 + 纯文本"这种各自为政的情况。
//
// 关键字段语义：
//   - Meta.Truncated 为 true 时**必须**同时给出 TruncationNote —— 截断必须显式告知模型，
//     否则模型会把"部分"当成"全部"（这是最隐蔽的错源之一）。
//   - Meta.Handle 指向结果外置存储里的原文句柄，模型需要细节时用回读工具按分页取回。
//   - Meta.Untrusted 恒为 true：工具结果来自被控主机，属**不可信数据**，不得当作指令执行。

const (
	StatusOK    = "ok"
	StatusError = "error"
)

// 错误码（对外稳定，前端/Agent/MCP 客户端都依赖它做分支）。
const (
	CodeBadRequest   = "bad_request"
	CodeNotFound     = "not_found"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeNotAllowed   = "tool_not_allowed"
	CodeNeedsConsent = "needs_consent"
	CodeRateLimited  = "rate_limited"
	CodeTimeout      = "timeout"
	CodeUpstream     = "upstream_error"
	CodeInternal     = "internal_error"
)

// DefaultInlineLimit 内联返回的字节上限：超过则外置并只回摘要 + 句柄。
const DefaultInlineLimit = 8 * 1024

// ErrorInfo 结构化错误。
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// Meta 结果元信息。
type Meta struct {
	CallID         string `json:"call_id"`
	Tool           string `json:"tool,omitempty"`
	Truncated      bool   `json:"truncated"`
	TruncationNote string `json:"truncation_note,omitempty"`
	TotalBytes     int    `json:"total_bytes"`
	ReturnedBytes  int    `json:"returned_bytes"`
	Handle         string `json:"handle,omitempty"`
	NextCursor     string `json:"next_cursor,omitempty"`
	// Untrusted 恒为 true：结果来自被控主机，属不可信数据（防间接 prompt injection）。
	Untrusted  bool  `json:"untrusted"`
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// Envelope 统一信封。
type Envelope struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  *ErrorInfo  `json:"error,omitempty"`
	Meta   Meta        `json:"meta"`
}

// ResultWriter 结果外置存储的最小接口（实现见 ResultStore；测试可注入内存实现）。
type ResultWriter interface {
	Put(callID string, raw []byte) (handle string, total int, err error)
	Get(handle string, offset, limit int) (chunk []byte, total int, err error)
}

// NewOK 构造成功信封。
func NewOK(tool, callID string, data interface{}) *Envelope {
	return &Envelope{
		Status: StatusOK,
		Data:   data,
		Meta:   Meta{CallID: callID, Tool: tool, Untrusted: true},
	}
}

// NewError 构造失败信封（错误也是正常返回的一部分，不再用 HTTP 状态码表达能力之外的东西）。
func NewError(tool, callID, code, message string) *Envelope {
	return &Envelope{
		Status: StatusError,
		Error:  &ErrorInfo{Code: code, Message: message},
		Meta:   Meta{CallID: callID, Tool: tool, Untrusted: true},
	}
}

// WithDetail 追加错误细节（例如编译报错原文）。
func (e *Envelope) WithDetail(detail string) *Envelope {
	if e.Error != nil {
		e.Error.Detail = detail
	}
	return e
}

// WithDuration 记录耗时。
func (e *Envelope) WithDuration(d time.Duration) *Envelope {
	e.Meta.DurationMS = d.Milliseconds()
	return e
}

// JSON 序列化（失败时回退到一条可读的错误信封，绝不返回非法 JSON）。
func (e *Envelope) JSON() []byte {
	b, err := json.Marshal(e)
	if err != nil {
		fallback := NewError(e.Meta.Tool, e.Meta.CallID, CodeInternal, "marshal envelope: "+err.Error())
		if b2, err2 := json.Marshal(fallback); err2 == nil {
			return b2
		}
		return []byte(`{"status":"error","error":{"code":"internal_error","message":"marshal failed"},"meta":{"untrusted":true}}`)
	}
	return b
}

// FinalizeInline 处理"内联结果"：超出 inlineLimit 就把原文外置，只回摘要 + 句柄 + 显式截断标注。
//
// store 为 nil 时退化为内存内截断，但**仍然**标注 Truncated 与 TruncationNote（不静默截断）。
func (e *Envelope) FinalizeInline(store ResultWriter, raw string, inlineLimit int) *Envelope {
	if inlineLimit <= 0 {
		inlineLimit = DefaultInlineLimit
	}
	total := len(raw)
	e.Meta.TotalBytes = total
	e.Meta.Untrusted = true

	if total <= inlineLimit {
		e.Meta.ReturnedBytes = total
		if e.Status == StatusOK {
			e.Data = raw
		}
		return e
	}

	// 超限：优先外置（store 可用），否则只回前缀。
	if store != nil {
		handle, n, err := store.Put(e.Meta.CallID, []byte(raw))
		if err == nil {
			e.Meta.Handle = handle
			e.Meta.TotalBytes = n
			e.Meta.ReturnedBytes = 0
			e.Meta.Truncated = true
			e.Meta.TruncationNote = fmt.Sprintf(
				"结果共 %d 字节，已外置为句柄 %s；上下文里只给摘要，需要细节请调用 result_read 按 offset/limit 分页回读（本次未内联任何正文）。",
				n, handle)
			if e.Status == StatusOK {
				e.Data = map[string]interface{}{
					"summary":   fmt.Sprintf("（结果已外置，共 %d 字节）", n),
					"handle":    handle,
					"total":     n,
					"read_tool": "result_read",
				}
			}
			return e
		}
		// 外置失败：明确告知，仍然标注截断，不退化成"看起来完整"。
		e.Meta.TruncationNote = fmt.Sprintf("结果共 %d 字节，外置失败（%v），仅返回前 %d 字节。", total, err, inlineLimit)
	} else {
		e.Meta.TruncationNote = fmt.Sprintf("结果共 %d 字节，仅返回前 %d 字节（未配置结果外置存储）。", total, inlineLimit)
	}

	e.Meta.Truncated = true
	e.Meta.ReturnedBytes = inlineLimit
	if e.Status == StatusOK {
		e.Data = raw[:inlineLimit]
	}
	return e
}

// IsOK 便捷判断。
func (e *Envelope) IsOK() bool { return e.Status == StatusOK }
