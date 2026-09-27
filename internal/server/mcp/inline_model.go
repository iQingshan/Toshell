package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ─── 工具结果 → 模型可见文本（唯一转换点，v1.4.0 S2）─────────────────────
//
// 为什么放在 mcp 包而不是 ai 包（这是本次增量的一个关键取舍）：
//  1. 「多大算大 / 超限怎么处理 / 句柄怎么给 / 回读工具叫什么」这一整套语义**已经**归本包所有
//     —— envelope.go 的 Envelope.FinalizeInline 定义了信封形状，resultstore.go 定义了句柄
//     格式与分页口径，registry_tools.go 定义了回读元工具 result_read；
//  2. 消费方有三个且都会 import mcp：内置 Agent 的两个 ReAct 循环（ai 包）、REST 的
//     /api/v1/mcp/tools/{name}（api 包）、对外 MCP 的 tools/call（本包）。反向不成立：
//     server.go 顶部已写明「mcp 刻意不 import api / ai / config」以防循环依赖，所以这个
//     转换点不可能放在 ai 包里再由 mcp 复用；
//  3. 只放一处才能保证三处口径一致（同一个 inline_limit、同一套句柄、同一段截断文案）。
//     历史上正是"每个调用点各写一个 truncate(out, 4000)"才出的问题。
//
// 与 Envelope.FinalizeInline 的分工：
//   - FinalizeInline 决定「信封长什么样」（要不要外置、摘要里放什么）；
//   - InlineForModel 决定「**喂给模型的文本**长什么样」，并额外钉住一条硬性质：
//
//     **凡是被截断的，模型拿到的文本必须仍是合法 JSON，且一定带显式截断说明；
//     能外置时必须带可用句柄。绝不再出现"字符串硬截断 → 模型拿到坏 JSON/坏 base64"。**
//
// 为什么必须外置而不是把上限调大（历史 bug 的根因）：截图结果是一整段 base64 JSON，
// 旧实现用 truncate(out, 4000) 直接切字符串，正好把 base64 切在中间 —— 模型既无法解码，
// 也不知道自己拿到的不是全部（这是最隐蔽的错源）。把上限从 4000 抬到 8 KiB 只是把
// "切在中间"的位置往后挪，治不了本；正确的做法是"超限就外置 + 只回摘要 + 显式告知 +
// 给出可用句柄"，让模型自己按需分页取回（也顺带避免了每轮把同一段长结果重复注入上下文）。

// ModelView 一次工具结果在模型上下文里的可见形态。
//
// 调用方（ai 循环 / REST / MCP）应当**只**把 Text 放进模型上下文，把其余字段作为
// 元信息透传给前端与审计（ToolTrace / SSE tool_result 的新增可选字段）。
type ModelView struct {
	// Text 模型可见文本：未超限时是工具结果原文；超限时是统一信封 JSON（恒为合法 JSON）。
	Text string
	// Truncated 是否被截断（超限即 true，与是否成功外置无关）。
	Truncated bool
	// Handle 结果外置句柄；空串表示**未外置**（此时必须依赖 TruncationNote 说明原因，
	// 且模型无法回读完整结果）。
	Handle string
	// TotalBytes 结果原文总字节数；ReturnedBytes 本次真正内联给模型的字节数。
	TotalBytes    int
	ReturnedBytes int
	// TruncationNote 中文截断说明（未截断时为空）。
	TruncationNote string
	// SHA256 原文摘要（小写十六进制）。供"结果外置索引"落库与事后核对；
	// 只有超限（真正需要追溯的那批）才计算，避免给每个小结果白算一次哈希。
	SHA256 string
	// Envelope 生成过程中的信封（未超限时为 nil），便于调用方取 Meta 里的其他字段。
	Envelope *Envelope
}

// previewOverhead 截断预览时为信封自身字段（status/tool/call_id/total/note）预留的字节余量。
// 预览文本是作为 JSON 字符串字段内联的，切片长度必须先扣掉这部分，否则"预览 + 信封"会反过来超限。
const previewOverhead = 512

// InlineForModel 是"工具结果 → 模型可见文本"的唯一实现（纯函数，便于不依赖网络/LLM 单测）。
//
// 判定表：
//
//	len(raw) <= inlineLimit          → Text = 原文（工具结果是 json.Marshal 出来的，通常就是合法 JSON）
//	len(raw) >  inlineLimit 且外置成功 → Text = 统一信封 JSON（summary + handle + total + 截断说明），
//	                                     Handle 非空，模型用 result_read 按 offset/limit 回读
//	len(raw) >  inlineLimit 且外置失败/未配置存储
//	                                 → Text = 统一信封 JSON，data 里是**开头预览** + "这不是全部"的明确告知，
//	                                     Handle 为空、TruncationNote 说明无法回读的原因
//
// inlineLimit <= 0 时取 DefaultInlineLimit（8 KiB）：这个值来自配置 mcp.inline_limit，
// 与对外 MCP 路径共用同一个上限，避免"AI 看到 8 KiB、MCP 客户端看到别的值"这种口径漂移。
func InlineForModel(tool, callID, raw string, store ResultWriter, inlineLimit int) ModelView {
	limit := inlineLimit
	if limit <= 0 {
		limit = DefaultInlineLimit
	}
	total := len(raw)
	view := ModelView{Text: raw, TotalBytes: total, ReturnedBytes: total}
	if total <= limit {
		return view
	}

	// 超限：先算摘要（结果索引/事后核对要用），再决定怎么给模型。
	sum := sha256.Sum256([]byte(raw))
	view.SHA256 = hex.EncodeToString(sum[:])
	view.Truncated = true

	if store != nil {
		env := NewOK(tool, callID, nil)
		env.FinalizeInline(store, raw, limit)
		if env.Meta.Handle != "" {
			view.Text = string(env.JSON())
			view.Handle = env.Meta.Handle
			view.ReturnedBytes = env.Meta.ReturnedBytes
			view.TruncationNote = env.Meta.TruncationNote
			view.Envelope = env
			return view
		}
		// 外置失败：FinalizeInline 会退化成 raw[:limit] 的字符串切片，对模型是坏 JSON。
		// 这里换成"合法信封 + 开头预览"，原因仍如实写进 TruncationNote。
		// 注意不把 env 暴露出去：它的 Data 是那段不安全的切片，留着只会被误用。
		view.TruncationNote = env.Meta.TruncationNote
		cut := previewCut(raw, limit)
		view.ReturnedBytes = cut
		view.Text = truncatedPreviewText(tool, callID, raw, cut, view.TruncationNote)
		return view
	}

	view.TruncationNote = fmt.Sprintf(
		"结果共 %d 字节，超过内联上限 %d 字节，且服务端未启用结果外置存储"+
			"（mcp.result_dir 未配置或目录不可用）：下面只是**开头预览**，不是全部，也没有句柄可回读。"+
			"需要完整结果请缩小命令输出范围（例如加过滤条件、分页读取、降低截图分辨率）后重试。",
		total, limit)
	cut := previewCut(raw, limit)
	view.ReturnedBytes = cut
	view.Text = truncatedPreviewText(tool, callID, raw, cut, view.TruncationNote)
	return view
}

// previewCut 计算预览能取多少字节：上限减去信封余量，并回退到 UTF-8 字符边界。
//
// 为什么要回退到字符边界：按字节硬切会把一个多字节字符切成两半，json.Marshal 会把它替换成
// U+FFFD（JSON 仍然合法，但内容被无故改写）；中文结果很常见，这里顺手对齐边界。
func previewCut(raw string, limit int) int {
	cut := limit - previewOverhead
	if cut <= 0 {
		cut = limit / 2
	}
	if cut > len(raw) {
		cut = len(raw)
	}
	// UTF-8 续字节 0x80..0xBF：往前退到字符起点（最多退 3 字节）。
	for cut > 0 && cut < len(raw) && raw[cut]&0xC0 == 0x80 {
		cut--
	}
	if cut < 0 {
		cut = 0
	}
	return cut
}

// truncatedPreviewText 构造"显式截断预览"的信封文本。
//
// 关键性质：预览是作为**字符串字段**由 json.Marshal 转义的，所以即使原文是半截 JSON、
// 半截 base64 或含控制字符的二进制，外层信封**一定**是合法 JSON —— 这正是与旧
// truncate(raw, n) 的本质区别（旧实现把半截 JSON 直接丢给模型）。
func truncatedPreviewText(tool, callID, raw string, cut int, note string) string {
	if cut > len(raw) {
		cut = len(raw)
	}
	env := &Envelope{
		Status: StatusOK,
		Data: map[string]interface{}{
			"truncated_preview": raw[:cut],
			"notice": "上面的 truncated_preview 只是结果的**开头一部分**（服务端已显式截断），" +
				"不是全部，也不是合法可解析的 JSON/base64 片段：不要试图解析它，也不要把它当作完整结果使用。",
		},
		Meta: Meta{
			CallID:         callID,
			Tool:           tool,
			Truncated:      true,
			TruncationNote: note,
			TotalBytes:     len(raw),
			ReturnedBytes:  cut,
			Untrusted:      true,
		},
	}
	return string(env.JSON())
}
