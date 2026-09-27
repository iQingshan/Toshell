package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"toshell/internal/server/config"
)

// ═══ Agent 上下文四层装配 + token 预算（v1.4.0 S2 / 里程碑 M3）════════════════
//
// 为什么要分成四层，而不是"把所有消息原样发给模型"：
//
//	① 常驻层（resident）：角色 + 工具契约 + 方法论。**必须逐字节稳定**——DeepSeek/OpenAI
//	   的自动前缀缓存按"消息前缀"命中，只要 system 的第 1 个字节变了，整段前缀缓存就失效，
//	   每一轮都要按未命中价重新计费。旧实现把"当前在线会话清单"拼进 system（copilot.go 的
//	   systemPrompt），而它每轮都可能变 → 前缀缓存**永远**命中不了；更糟的是取清单时内部又
//	   调了一次 session_list 工具（一次未审计的工具调用）。所以会话清单被移到任务层。
//	② 任务层（task）：目标 / 计划进度 / 运行约束 / 预算快照 / 在线会话快照。每轮可变，
//	   但**不参与**前缀稳定性要求（它排在常驻层之后，缓存断点只发生在它这里）。
//	③ 工作层（working）：最近 N 条消息原文。模型推理的直接依据，默认保留 14 条，
//	   可配置（ai.context_working_keep）。**assistant.tool_calls 与对应 tool 回执必须
//	   一起留在同一层**：上游 chat/completions 会拒绝"tool 回执找不到它的 assistant"的序列。
//	④ 历史层（history）：更早的消息折叠成一行摘要。折叠必须保留真实工具名、外置句柄、
//	   截断标注，并显式写明"这是压缩摘要、不是原文"——否则模型会把摘要当成完整结果。
//
// 预算为什么是"先压缩、再停止"而不是直接停：
// 一次 run 的价值几乎全在"已经拿到的工具结果"里，直接停等于把这些结果连同可能的最终结论
// 一起丢掉。只要还能在不丢关键信息的前提下把上下文压进预算（缩短工作层、把大结果换成句柄
// 说明——原文在外置存储里可随时 result_read 回读），就应该继续跑；只有**压到极限仍然超预算**
// 才停止循环，并把 stop_reason 记为 max_tokens、照常产出"因预算耗尽而停止"的最终回复。

// 四层的层名：只出现在结构化日志与 run 的新增可选字段里，不构成对外契约。
const (
	LayerResident = "resident" // 常驻层：逐字节稳定，前缀缓存的基础
	LayerTask     = "task"     // 任务层：每轮可变的任务上下文
	LayerWorking  = "working"  // 工作层：最近 N 条原文
	LayerHistory  = "history"  // 历史层：更早消息的一行摘要
)

// 默认值（与 config 包的常量同源，避免"注释一个数、代码另一个数"的历史问题）。
const (
	// DefaultWorkingKeep 工作层默认保留的原文条数（= 旧实现的 keepRecent = 14）。
	DefaultWorkingKeep = config.DefaultContextWorkingKeep
	// DefaultAggressiveWorkingKeep 触发超预算后的激进压缩时，工作层保留的原文条数。
	DefaultAggressiveWorkingKeep = 4
	// aggressiveVerbatimTail 激进压缩时**完全不折叠**的尾部消息条数。
	// 最近一轮 assistant/tool 往返是模型下一步推理的直接依据，折叠它等于让模型失忆，
	// 所以即便在最激进的一档也保留它俩原样。
	aggressiveVerbatimTail = 2
	// maxWorkingMessageRunes 工作层单条消息的字符上限（防御性：正常情况下工具结果已被
	// mcp.InlineForModel 按 inline_limit 处理过，不会到这里；用户消息可能很长）。
	maxWorkingMessageRunes = 8000
	// foldAssistantRunes 历史层里 assistant 正文超过该长度才折叠（短正文保留原文更省事）。
	foldAssistantRunes = 300
	// maxHistoryUserRunes 历史层里 user 指令的字符上限（保留目标，但别让一条超长指令吃掉预算）。
	maxHistoryUserRunes = 2000
	// foldedLineMaxBytes 折叠摘要一行的字节上限（逐字节计，保证压缩比率可预期）。
	foldedLineMaxBytes = 240
	// foldedSummaryBytes 折叠摘要里"工具结果摘要"部分的字节上限。
	foldedSummaryBytes = 120
	// foldedNoteBytes 折叠摘要里"截断说明"部分的字节上限（说明可被截，句柄与回读指引不可）。
	foldedNoteBytes = 60
)

// foldedMarker 折叠摘要的前缀：既是给模型的说明，也是**幂等标记**——
// 已经折叠过的消息再次经过装配时不能再叠一层前缀（否则多轮装配会把摘要越滚越长）。
const foldedMarker = "[历史摘要-非原文]"

// truncatedMarker 超长单条被截断时的显式标注。
const truncatedMarker = "[已截断]"

// ═══ token 估算 ═════════════════════════════════════════════════════════════
//
// 估算口径（**不引入 tiktoken/大词表依赖**，理由见 docs/plan/01-agent.md 1.2.2：
// 嵌词表会抬高二进制体积与跨平台编译面，而这里只需要"发请求前的量级判断"）：
//
//	非 CJK 字符（ASCII/拉丁/数字/符号/空白）：4 字符 ≈ 1 token。
//	    这是英文自然文本的经验值，对代码/JSON/base64/日志这类标点与短 token 密集的
//	    文本是**偏低**的（实测可低到 2~3 字符/token）→ 属于低估方向。
//	CJK 字符（汉字/假名/谚文/CJK 与全角标点）：1 字符 ≈ 1 token。
//	    主流分词器对中文大约 0.6~1 token/字，取 1 是**偏高**的 → 属于高估方向。
//	两者相加后再由预算判定处统一乘 SafetyFactor（默认 1.3，即留 30% 余量）兜住"低估"的那部分。
//
// 结论：估算值只用于**发请求前的裁剪决策**；落库/展示的 token 一律优先用上游 usage 真值，
// 并用它回填校准系数（TokenCalibration），避免估算与实际长期漂移。

// TokenSafetyFactor token 预算的安全余量：估算值 × 1/1.3 才是实际可用额度。
// 取 1.3 的依据：估算对中文是高估、对代码/JSON 是低估，实测总误差在 ±30% 以内，
// 取 1.3 相当于"按最坏情况的低估"预留额度（预算 32000 → 估算超过 24615 就触发压缩）。
const TokenSafetyFactor = 1.3

// estimateTokens 字符近似的 token 估算（口径见上；**不含**安全余量）。
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	var cjk, other int
	for _, r := range s {
		if isCJK(r) {
			cjk++
		} else {
			other++
		}
	}
	// CJK 1 字/token、其余 4 字符/token；向上取整保证"非空文本估算不为 0"。
	return int(math.Ceil(float64(cjk) + float64(other)/4.0))
}

// isCJK 判定"在主流分词器里约 1 个 token/字"的区段。
func isCJK(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF: // CJK 统一表意文字
		return true
	case r >= 0x3400 && r <= 0x4DBF: // 扩展 A
		return true
	case r >= 0xF900 && r <= 0xFAFF: // 兼容表意文字
		return true
	case r >= 0x3040 && r <= 0x30FF: // 平假名 / 片假名
		return true
	case r >= 0xAC00 && r <= 0xD7AF: // 谚文音节
		return true
	case r >= 0x3000 && r <= 0x303F: // CJK 标点（、。「」等）
		return true
	case r >= 0xFF00 && r <= 0xFFEF: // 全角形式
		return true
	case r >= 0x20000 && r <= 0x2FA1F: // 扩展 B~F
		return true
	}
	return false
}

// messageOverheadTokens 每条消息的固定开销（role/tool_call_id/分隔符等）。
// 这个开销真实存在且与被计费内容无关，给一个保守的常数比忽略它更接近真值。
const messageOverheadTokens = 4

// EstimateTokens 估算一段文本的 token 数（导出供测试与可观测性使用）。
func EstimateTokens(s string) int { return estimateTokens(s) }

// EstimateMessageTokens 估算一条消息的 token 数（正文 + 工具调用参数 + 固定开销）。
func EstimateMessageTokens(m Message) int {
	n := messageOverheadTokens + estimateTokens(m.Content) + estimateTokens(m.Name)
	for _, tc := range m.ToolCalls {
		n += estimateTokens(tc.Function.Name) + estimateTokens(tc.Function.Arguments) + 4
	}
	return n
}

// EstimateMessagesTokens 估算一组消息的 token 数（单调不减：消息只增不减时结果不会变小）。
func EstimateMessagesTokens(msgs []Message) int {
	total := 0
	for _, m := range msgs {
		total += EstimateMessageTokens(m)
	}
	return total
}

// ═══ 估算校准（usage 回填）══════════════════════════════════════════════════

// 校准参数的取值理由：
//   - alpha=0.3：单次样本波动大（上游 usage 含系统/工具 schema 的固定开销），
//     指数滑动平均比"直接用最后一次比值"稳，也不至于慢到跟不上模型/口径变化；
//   - minEstimate=200：估算太小时比值噪声极大（ceil 误差就能翻倍），不采信；
//   - [0.5, 3.0] 夹紧：防止一次异常 usage（上游回 0 或回错）把系数带飞。
const (
	tokenCalibAlpha       = 0.3
	tokenCalibMinEstimate = 200
	tokenCalibMinFactor   = 0.5
	tokenCalibMaxFactor   = 3.0
)

// TokenCalibration 估算 → 真值的校准系数（真值来自上游 usage，纯值对象）。
//
// 语义：Factor ≈ 真实 prompt_tokens / 估算值。Apply(est) = ceil(est × Factor)。
// Factor 为 0 表示"还没校准过"，按 1.0 处理（估算即真值的最佳猜测）。
type TokenCalibration struct {
	Factor  float64
	Samples int
}

// Factor 返回生效系数（未校准时为 1.0）。
func (c TokenCalibration) EffectiveFactor() float64 {
	f := c.Factor
	if f <= 0 {
		return 1.0
	}
	if f < tokenCalibMinFactor {
		return tokenCalibMinFactor
	}
	if f > tokenCalibMaxFactor {
		return tokenCalibMaxFactor
	}
	return f
}

// Apply 把估算值按当前系数校准（用于预算判定；raw 估算值本身不变，日志里两者都记）。
func (c TokenCalibration) Apply(estimated int) int {
	if estimated <= 0 {
		return 0
	}
	return int(math.Ceil(float64(estimated) * c.EffectiveFactor()))
}

// Observe 用一次真实 usage 回填校准（estimated 为本次请求的估算 prompt token）。
// 样本无效（估算/真值 <=0 或估算过小）时原样返回，绝不因为一次噪声样本改坏系数。
func (c TokenCalibration) Observe(estimated, actual int) TokenCalibration {
	if estimated < tokenCalibMinEstimate || actual <= 0 {
		return c
	}
	sample := float64(actual) / float64(estimated)
	if math.IsNaN(sample) || math.IsInf(sample, 0) || sample <= 0 {
		return c
	}
	prev := c.EffectiveFactor()
	next := prev*(1-tokenCalibAlpha) + sample*tokenCalibAlpha
	if next < tokenCalibMinFactor {
		next = tokenCalibMinFactor
	}
	if next > tokenCalibMaxFactor {
		next = tokenCalibMaxFactor
	}
	return TokenCalibration{Factor: next, Samples: c.Samples + 1}
}

// RunTokenUsage 一次 run 的 token 用量（纯值对象）。
//
// 真值优先、估算兜底：上游不回 usage（部分兼容端点、或流式的最后一个 chunk 没带）
// 时，该轮按估算计入 EstimatedTokens——**预算不会因为"上游不回 usage"而失效**。
type RunTokenUsage struct {
	PromptTokens     int // usage 真值累计（无 usage 的轮次不计入）
	CompletionTokens int
	EstimatedTokens  int // 无 usage 轮次的估算回填（已含 30% 余量，取保守值）
	Samples          int // 采信到的 usage 样本数
	Calibration      TokenCalibration
}

// Total 预算判定用的累计值（真值 + 无 usage 轮次的估算）。
func (u RunTokenUsage) Total() int {
	return u.PromptTokens + u.CompletionTokens + u.EstimatedTokens
}

// ObserveUsage 记录一次**带回 usage 真值**的 LLM 往返，并用它回填校准。
func (u RunTokenUsage) ObserveUsage(prompt, completion, estimatedPrompt int) RunTokenUsage {
	if prompt < 0 {
		prompt = 0
	}
	if completion < 0 {
		completion = 0
	}
	u.PromptTokens += prompt
	u.CompletionTokens += completion
	if prompt > 0 || completion > 0 {
		u.Samples++
		u.Calibration = u.Calibration.Observe(estimatedPrompt, prompt)
	}
	return u
}

// ObserveEstimate 记录一次**没有 usage**的往返：按估算回填，保证预算仍然有效。
func (u RunTokenUsage) ObserveEstimate(estimatedPrompt int) RunTokenUsage {
	if estimatedPrompt > 0 {
		u.EstimatedTokens += estimatedPrompt
	}
	return u
}

// ═══ 预算 ═══════════════════════════════════════════════════════════════════

// TokenBudget 生效的 token 预算（纯值对象）：单次上下文预算 + 单次 run 累计预算。
type TokenBudget struct {
	// MaxContextTokens 单次请求送入模型的上下文预算（近似 token）。
	MaxContextTokens int
	// MaxRunTokens 一次 run 的累计 token 预算（prompt+completion 真值口径）。
	MaxRunTokens int
}

// TokenBudgetFromConfig 由配置得到生效预算（非法值回落默认，**不允许关掉预算**）。
func TokenBudgetFromConfig(cfg config.AIConfig) TokenBudget {
	return TokenBudget{
		MaxContextTokens: EffectiveMaxContextTokens(cfg),
		MaxRunTokens:     EffectiveMaxRunTokens(cfg),
	}
}

// EffectiveMaxContextTokens 返回生效的单次上下文预算（0/负数 → 默认值）。
func EffectiveMaxContextTokens(cfg config.AIConfig) int {
	if cfg.MaxContextTokens > 0 {
		return cfg.MaxContextTokens
	}
	return config.DefaultMaxContextTokens
}

// EffectiveMaxRunTokens 返回生效的单次 run 累计 token 预算（0/负数 → 默认值）。
func EffectiveMaxRunTokens(cfg config.AIConfig) int {
	if cfg.MaxRunTokens > 0 {
		return cfg.MaxRunTokens
	}
	return config.DefaultMaxRunTokens
}

// EffectiveContextWorkingKeep 返回生效的工作层保留条数（0/负数 → 默认值）。
func EffectiveContextWorkingKeep(cfg config.AIConfig) int {
	if cfg.ContextWorkingKeep > 0 {
		return cfg.ContextWorkingKeep
	}
	return config.DefaultContextWorkingKeep
}

// UsableContextTokens 把"配置的预算"换算成"估算触发的阈值"：预算 / 1.3。
// 预算 <=0 → 0，表示不做预算判定（仅供单测与"无预算"调用点使用）。
func UsableContextTokens(maxContextTokens int) int {
	if maxContextTokens <= 0 {
		return 0
	}
	return int(math.Ceil(float64(maxContextTokens) / TokenSafetyFactor))
}

// ShouldStopTokens 判断累计 token 用量是否已达预算，并给出 stop_reason（""=继续）。
//
// 与三处硬上限（轮次/工具调用数/墙钟）分开实现而不是塞进 shouldStopRun：
//  1. 三处硬上限的判定是"次数/时间"，这里用的是**上游 usage 真值**（缺 usage 时用估算回填），
//     数据来源不同；混在一起会让 shouldStopRun 的纯函数语义变模糊（且会改动既有测试钉住的
//     返回值表）；
//  2. 语义一致：达到上限即停（>=），stop_reason 与 max_turns/max_tool_calls/max_wallclock
//     同风格取名 max_tokens。
func ShouldStopTokens(usage RunTokenUsage, budget TokenBudget) (bool, string) {
	if budget.MaxRunTokens > 0 && usage.Total() >= budget.MaxRunTokens {
		return true, stopReasonMaxTokens
	}
	return false, ""
}

// ═══ 装配输入 / 输出 ═══════════════════════════════════════════════════════

// ContextOptions 装配选项（纯值对象）。
type ContextOptions struct {
	// WorkingKeep 工作层保留的原文条数（<=0 → DefaultWorkingKeep）。
	WorkingKeep int
	// MinWorkingKeep 超预算触发激进压缩后工作层保留的条数（<=0 → DefaultAggressiveWorkingKeep）。
	MinWorkingKeep int
	// BudgetTokens 单次上下文预算（近似 token）；<=0 表示**不做预算判定**
	// （仅用于单测与"不需要预算"的调用点；生产路径一律由 contextOptionsFromConfig 填默认值）。
	BudgetTokens int
	// Calibration 估算校准系数（来自本 run 已观测到的 usage）。
	Calibration TokenCalibration
}

// contextOptionsFromConfig 由配置得到装配选项（预算与工作层条数都取生效值）。
func contextOptionsFromConfig(cfg config.AIConfig) ContextOptions {
	return ContextOptions{
		WorkingKeep:    EffectiveContextWorkingKeep(cfg),
		MinWorkingKeep: DefaultAggressiveWorkingKeep,
		BudgetTokens:   EffectiveMaxContextTokens(cfg),
	}
}

// ContextInput 一次装配的全部输入（纯数据；取数据的事由调用方做，装配本身是纯函数，
// 因此可以完全不依赖网络/LLM/真实会话地单测）。
type ContextInput struct {
	// Resident 常驻层正文。必须由调用方保证同一 run 内逐字节相同（见 Copilot.residentPrompt）。
	Resident string
	// Objective 任务层：当前目标。
	Objective string
	// Plan 任务层：计划进度。
	Plan []GoalStep
	// Constraints 任务层：不变的运行约束（授权范围、结果不可信等）。
	Constraints string
	// Sessions 任务层：在线会话快照（由调用方取一次后传入，不要每轮去调 session_list）。
	Sessions string
	// BudgetText 任务层：预算快照文本（让模型看得见"还剩多少额度"）。
	BudgetText string
	// History 完整历史消息（run.Messages 原文；**会被忽略其开头的 system**——
	// 常驻层由 Resident 重新给出，从而保证前缀稳定）。
	History []Message
	// Opts 装配选项。
	Opts ContextOptions
}

// ContextLayerStat 单层统计（条数 / 估算 token）。
type ContextLayerStat struct {
	Name     string `json:"name"`
	Messages int    `json:"messages"`
	Tokens   int    `json:"tokens"`
	Folded   int    `json:"folded,omitempty"` // 本层被折叠（内容被摘要替换）的条数
}

// ContextStats 一次装配的统计信息：进结构化日志（组件 ai）与 run 的可观测字段。
//
// 字段全部是"新增可选"，不涉及任何既有对外字段的重命名。
type ContextStats struct {
	// Layers 按**消息装配顺序**排列：resident → task → history → working。
	Layers []ContextLayerStat `json:"layers"`
	// TotalMessages / TotalTokens：装配结果的消息条数与字符近似估算 token。
	TotalMessages int `json:"total_messages"`
	TotalTokens   int `json:"total_tokens"`
	// CalibratedTokens = TotalTokens × 校准系数（预算判定用的就是这个值）。
	CalibratedTokens int `json:"calibrated_tokens"`
	// BudgetTokens 配置的上下文预算；UsableTokens 是扣除 30% 余量后的触发阈值。
	BudgetTokens int `json:"budget_tokens"`
	UsableTokens int `json:"usable_tokens"`
	// Compressed 本次装配是否压缩过（历史层折叠过，或触发了激进压缩）。
	Compressed bool `json:"compressed"`
	// Aggressive 是否触发了第二段（更激进的）压缩。
	Aggressive bool `json:"aggressive"`
	// CollapsedMessages 被折叠成摘要的消息条数（历史层 + 激进压缩的工作层）。
	CollapsedMessages int `json:"collapsed_messages"`
	// WorkingKept / WorkingLimit 工作层实际保留条数与本次使用的上限。
	WorkingKept  int `json:"working_kept"`
	WorkingLimit int `json:"working_limit"`
	// OverBudget 压到极限**仍然**超预算：调用方应停止循环并记 stop_reason=max_tokens。
	OverBudget bool `json:"over_budget"`
	// ResidentHash 常驻层 sha256（前缀缓存命中情况的可观测性/回归门禁）。
	ResidentHash string `json:"resident_hash,omitempty"`
	// CalibrationFactor 本次使用的校准系数（1.0 = 未校准）。
	CalibrationFactor float64 `json:"calibration_factor,omitempty"`
}

// LayerTokens 取某层的估算 token（层不存在时 0）。
func (s ContextStats) LayerTokens(name string) int {
	for _, l := range s.Layers {
		if l.Name == name {
			return l.Tokens
		}
	}
	return 0
}

// LayerMessages 取某层的条数（层不存在时 0）。
func (s ContextStats) LayerMessages(name string) int {
	for _, l := range s.Layers {
		if l.Name == name {
			return l.Messages
		}
	}
	return 0
}

// LogFields 生成结构化日志用的单行字段（组件 ai）。
func (s ContextStats) LogFields() string {
	return fmt.Sprintf("context[resident=%dm/%dt task=%dm/%dt history=%dm/%dt(folded=%d) working=%dm/%dt "+
		"total_msgs=%d est_tokens=%d calibrated=%d budget=%d usable=%d compressed=%v aggressive=%v over_budget=%v calib=%.2f resident_hash=%s]",
		s.LayerMessages(LayerResident), s.LayerTokens(LayerResident),
		s.LayerMessages(LayerTask), s.LayerTokens(LayerTask),
		s.LayerMessages(LayerHistory), s.LayerTokens(LayerHistory), s.layerFolded(LayerHistory),
		s.LayerMessages(LayerWorking), s.LayerTokens(LayerWorking),
		s.TotalMessages, s.TotalTokens, s.CalibratedTokens, s.BudgetTokens, s.UsableTokens,
		s.Compressed, s.Aggressive, s.OverBudget, s.CalibrationFactor, shortHash(s.ResidentHash))
}

// layerFolded 取某层被折叠的条数（日志用）。
func (s ContextStats) layerFolded(name string) int {
	for _, l := range s.Layers {
		if l.Name == name {
			return l.Folded
		}
	}
	return 0
}

// shortHash 日志里只取哈希前 12 位（够区分、不刷屏）。
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ═══ 装配 ═══════════════════════════════════════════════════════════════════

// AssembleContext 四层装配（纯函数）：常驻层 → 任务层 → 历史层 → 工作层。
//
// 装配顺序就是消息顺序：历史层在工作层之前，因为工作层是"最近 N 条原文"。
// 预算判定分两段：第一段正常装配；超预算则第二段激进装配（缩减工作层 + 把较旧的工作层
// 消息也折叠成摘要 + 截短会话清单）；仍然超预算时由 OverBudget 告知调用方停止循环
// （**不再**发起 LLM 调用——否则正好把已经超预算的上下文又发一次）。
func AssembleContext(in ContextInput) ([]Message, ContextStats) {
	// History 开头的 system 是上一次装配塞进去的常驻层副本，丢掉：常驻层由 in.Resident
	// 重新给出（保证同一 run 内逐字节一致），不丢就会出现两份 system。
	convo := stripLeadingSystem(in.History)
	return assembleCore(in.Resident, in.taskLayerText, convo, in.Opts)
}

// CompressMessages 对"已经装配好的消息序列"做分层压缩（同步副驾驶循环的预算检查点用）。
//
// 与 AssembleContext 的关系：两者共用同一套分层/折叠实现，区别只在于常驻层从哪来——
// 这里保留消息序列里已有的 system 正文（同步路径没有 AgentRun，也没必要重新生成任务层），
// 只重算工作层/历史层的切分与折叠。**不会**修改入参（返回的是副本）。
func CompressMessages(msgs []Message, opts ContextOptions) ([]Message, ContextStats) {
	resident, convo := splitLeadingSystem(msgs)
	// 紧随常驻层的那条 system 就是任务层：原样保留（它是任务上下文，不是历史消息）。
	// 只在"看起来确实是任务层"时才这么认——避免把对话中途的 system（如防死循环纠偏提示）
	// 误当成任务层搬到消息最前面，那样会改变提示的时序语义。
	task := ""
	if len(convo) > 0 && convo[0].Role == "system" && looksLikeTaskLayer(convo[0].Content) {
		task = convo[0].Content
		convo = convo[1:]
	}
	return assembleCore(resident, func(bool) string { return task }, convo, opts)
}

// taskLayerMarkers 任务层正文里必然出现的段落标记（用于识别"这条 system 是不是任务层"）。
var taskLayerMarkers = []string{"【当前目标】", "【计划进度】", "【运行约束】", "【预算】", "【当前在线会话】"}

// looksLikeTaskLayer 判断一段 system 正文是不是装配出来的任务层。
func looksLikeTaskLayer(s string) bool {
	for _, m := range taskLayerMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// taskLayerText 生成任务层正文（每轮可变；不参与前缀缓存稳定性要求）。
//
// aggressive=true 时把在线会话清单截短——超预算的最后一档"可牺牲"信息就是它
// （会话清单只是帮模型选会话，session_list/session_context 随时可以再查）。
func (in ContextInput) taskLayerText(aggressive bool) string {
	sessions := in.Sessions
	if aggressive {
		sessions = trimSessionList(sessions, 8)
	}
	var b strings.Builder
	if o := strings.TrimSpace(in.Objective); o != "" {
		b.WriteString("【当前目标】")
		b.WriteString(o)
		b.WriteString("\n")
	}
	if len(in.Plan) > 0 {
		b.WriteString("【计划进度】")
		limit := len(in.Plan)
		if aggressive && limit > 5 {
			limit = 5 // 最后一档只保留前 5 步，后面的用序号示意
		}
		for i := 0; i < limit; i++ {
			st := in.Plan[i].Status
			if st == "" {
				st = "pending"
			}
			fmt.Fprintf(&b, "%d.%s(%s) ", in.Plan[i].Index, in.Plan[i].Desc, st)
		}
		if limit < len(in.Plan) {
			fmt.Fprintf(&b, "…（其余 %d 步略）", len(in.Plan)-limit)
		}
		b.WriteString("\n")
	}
	if c := strings.TrimSpace(in.Constraints); c != "" {
		b.WriteString("【运行约束】")
		b.WriteString(c)
		b.WriteString("\n")
	}
	if t := strings.TrimSpace(in.BudgetText); t != "" {
		b.WriteString("【预算】")
		b.WriteString(t)
		b.WriteString("\n")
	}
	if s := strings.TrimSpace(sessions); s != "" {
		b.WriteString("【当前在线会话】\n")
		b.WriteString(s)
		b.WriteString("以上是当前上线的目标会话（快照，可能已过期）。需要时用 session_context 获取某会话详细上下文，" +
			"结合上下文判断下一步，无需每步都问用户；若上下文不足，先深入获取再给建议。\n")
	}
	return strings.TrimSpace(b.String())
}

// trimSessionList 截短会话清单（只保留前 n 行）。
func trimSessionList(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" || n <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n…（其余 %d 个会话略，需要时用 session_list 再查）", len(lines)-n)
}

// contextCounts 单次装配的分层计数（内部用）。
type contextCounts struct {
	residentMessages, residentTokens int
	taskMessages, taskTokens         int
	historyMessages, historyTokens   int
	historyFolded                    int
	workingMessages, workingTokens   int
	workingFolded                    int
	workingLimit                     int
}

// assembleCore 装配主体：resident + task + [历史层][工作层]，含两段式预算压缩。
// taskFn 按"是否激进档"生成任务层正文（同步路径没有任务层，传返回空串的函数即可）。
// 约定：convo **不含**常驻层副本（调用方先剥掉），否则常驻层会重复。
func assembleCore(resident string, taskFn func(aggressive bool) string, convo []Message, opts ContextOptions) ([]Message, ContextStats) {
	keep := opts.WorkingKeep
	if keep <= 0 {
		keep = DefaultWorkingKeep
	}
	minKeep := opts.MinWorkingKeep
	if minKeep <= 0 {
		minKeep = DefaultAggressiveWorkingKeep
	}
	if minKeep > keep {
		minKeep = keep
	}

	stats := ContextStats{
		BudgetTokens:      opts.BudgetTokens,
		UsableTokens:      UsableContextTokens(opts.BudgetTokens),
		ResidentHash:      hashText(resident),
		CalibrationFactor: opts.Calibration.EffectiveFactor(),
	}

	msgs, counts := assembleOnce(resident, taskFn(false), convo, keep, false)
	fillStats(&stats, counts, opts.Calibration)

	// 第一段超预算 → 第二段（激进压缩）；仍超 → OverBudget，调用方据此停止循环。
	if stats.UsableTokens > 0 && stats.CalibratedTokens > stats.UsableTokens {
		msgs, counts = assembleOnce(resident, taskFn(true), convo, minKeep, true)
		stats.Aggressive = true
		fillStats(&stats, counts, opts.Calibration)
	}

	stats.Compressed = stats.Aggressive || stats.CollapsedMessages > 0
	stats.OverBudget = stats.UsableTokens > 0 && stats.CalibratedTokens > stats.UsableTokens
	return msgs, stats
}

// fillStats 把单次装配的计数写进统计（TotalTokens/CalibratedTokens 同步重算）。
func fillStats(stats *ContextStats, c contextCounts, calib TokenCalibration) {
	stats.Layers = []ContextLayerStat{
		{Name: LayerResident, Messages: c.residentMessages, Tokens: c.residentTokens},
		{Name: LayerTask, Messages: c.taskMessages, Tokens: c.taskTokens},
		{Name: LayerHistory, Messages: c.historyMessages, Tokens: c.historyTokens, Folded: c.historyFolded},
		{Name: LayerWorking, Messages: c.workingMessages, Tokens: c.workingTokens, Folded: c.workingFolded},
	}
	stats.TotalMessages = c.residentMessages + c.taskMessages + c.historyMessages + c.workingMessages
	stats.TotalTokens = c.residentTokens + c.taskTokens + c.historyTokens + c.workingTokens
	stats.CalibratedTokens = calib.Apply(stats.TotalTokens)
	stats.CollapsedMessages = c.historyFolded + c.workingFolded
	stats.WorkingKept = c.workingMessages
	stats.WorkingLimit = c.workingLimit
}

// assembleOnce 单次装配（workingKeep 条原文留在工作层；aggressive=true 时把工作层里
// 较旧的消息也折叠成摘要）。
func assembleOnce(resident, task string, convo []Message, workingKeep int, aggressive bool) ([]Message, contextCounts) {
	if workingKeep > len(convo) {
		workingKeep = len(convo)
	}
	start := len(convo) - workingKeep
	if start < 0 {
		start = 0
	}
	// 工作层起点必须避开"assistant.tool_calls 与它的 tool 回执"之间：
	// 上游 chat/completions 要求每个 tool 回执都能找到声明它的 assistant，拆散的序列会被直接拒绝。
	start = safeWorkingStart(convo, start)

	out := make([]Message, 0, len(convo)+2)
	var c contextCounts
	c.workingLimit = workingKeep

	if resident != "" {
		out = append(out, Message{Role: "system", Content: resident})
		c.residentMessages = 1
		c.residentTokens = EstimateMessageTokens(out[len(out)-1])
	}
	if strings.TrimSpace(task) != "" {
		m := Message{Role: "system", Content: task}
		out = append(out, m)
		c.taskMessages = 1
		c.taskTokens = EstimateMessageTokens(m)
	}

	names := buildToolNameIndex(convo)

	// 历史层：更早的消息折叠成一行摘要（保留真实工具名 / 句柄 / 截断标注 / "非原文"说明）。
	for i := 0; i < start; i++ {
		m := foldMessage(convo[i], names)
		if m.Content != convo[i].Content {
			c.historyFolded++
		}
		out = append(out, m)
		c.historyMessages++
		c.historyTokens += EstimateMessageTokens(m)
	}

	// 工作层：最近 N 条原文（激进档里，除末尾 aggressiveVerbatimTail 条外也折叠）。
	verbatimFrom := len(convo) - aggressiveVerbatimTail
	for i := start; i < len(convo); i++ {
		m := convo[i]
		if aggressive && i < verbatimFrom {
			folded := foldMessage(m, names)
			if folded.Content != m.Content {
				c.workingFolded++
			}
			m = folded
		} else {
			m = capMessageContent(m, maxWorkingMessageRunes)
		}
		out = append(out, m)
		c.workingMessages++
		c.workingTokens += EstimateMessageTokens(m)
	}
	return out, c
}

// safeWorkingStart 计算安全的工作层起点：如果起点落在一条**有配对义务**的 tool 回执上，
// 就往前退到声明它的 assistant，保证成对消息不被拆到两层。
//
// 只对"真的能配到 assistant"的回执生效：测试/迁移数据里存在没有 assistant 声明的孤儿
// tool 消息，为它们回退会让压缩彻底失效（整段历史都留在工作层）。
func safeWorkingStart(convo []Message, start int) int {
	for start > 0 {
		m := convo[start]
		if m.Role != "tool" || m.ToolCallID == "" {
			break
		}
		if !declaresToolCall(convo, start, m.ToolCallID) {
			break
		}
		start--
	}
	return start
}

// declaresToolCall 判断 [0, before) 里是否有 assistant 声明了该 tool_call id。
func declaresToolCall(convo []Message, before int, callID string) bool {
	if callID == "" {
		return false
	}
	for i := before - 1; i >= 0; i-- {
		for _, tc := range convo[i].ToolCalls {
			if tc.ID == callID {
				return true
			}
		}
	}
	return false
}

// buildToolNameIndex 建立 tool_call id → 工具名 的索引。
//
// 为什么要建索引：折叠历史时**只能**从真实消息里取工具名。旧实现把名字写死成 task_wait
// （`summarizeToolResult("task_wait", ...)`），模型看到的历史摘要全是 task_wait，
// 于是误判"哪些事已经做过"，这正是本次要修掉的 bug。
func buildToolNameIndex(convo []Message) map[string]string {
	idx := make(map[string]string)
	for _, m := range convo {
		for _, tc := range m.ToolCalls {
			if tc.ID != "" && tc.Function.Name != "" {
				idx[tc.ID] = tc.Function.Name
			}
		}
	}
	return idx
}

// foldMessage 把一条历史消息折叠成一行摘要（幂等：已折叠过的消息原样返回）。
func foldMessage(m Message, names map[string]string) Message {
	switch m.Role {
	case "tool":
		if m.Content == "" || strings.HasPrefix(m.Content, foldedMarker) {
			return m
		}
		name := names[m.ToolCallID]
		if name == "" {
			name = m.Name
		}
		if name == "" {
			name = "unknown"
		}
		m.Content = foldedToolLine(name, m.Content)
		return m
	case "assistant":
		if strings.HasPrefix(m.Content, foldedMarker) {
			return m
		}
		calls := toolCallNames(m.ToolCalls)
		body := strings.TrimSpace(m.Content)
		if calls == "" && len([]rune(body)) <= foldAssistantRunes {
			return m // 已经很短：折叠只会白丢信息
		}
		var b strings.Builder
		b.WriteString(foldedMarker)
		if calls != "" {
			b.WriteString("助手请求调用工具：")
			b.WriteString(calls)
			b.WriteString("；")
		}
		b.WriteString("正文摘要：")
		if body == "" {
			b.WriteString("（无正文）")
		} else {
			b.WriteString(truncateRunes(body, foldAssistantRunes))
		}
		// ToolCalls 保持原样：这是 tool 回执的配对依据，绝不能为了省 token 把它删掉。
		m.Content = b.String()
		return m
	case "user":
		if strings.HasPrefix(m.Content, foldedMarker) {
			return m
		}
		if len([]rune(m.Content)) > maxHistoryUserRunes {
			m.Content = truncateRunes(m.Content, maxHistoryUserRunes) + truncatedMarker +
				"（用户指令原文过长，此处只保留开头；这是历史指令，不是本轮原文）"
		}
		return m
	default: // system 等
		if strings.HasPrefix(m.Content, foldedMarker) {
			return m
		}
		return capMessageContent(m, maxHistoryUserRunes)
	}
}

// foldedToolLine 生成"被折叠的历史工具结果"的一行摘要。
//
// 三个必须保留的东西（v1.4.0 S2 修的正是这里）：
//  1. **真实工具名**（来自 assistant.tool_calls 的 call_id 反查，取不到才回落 name 字段）；
//  2. 外置信封的**句柄**与**截断说明**——否则模型会以为这段历史是完整结果，
//     也不知道还能用 result_read 回读；
//  3. "这是压缩摘要、不是原文"的显式标注。
func foldedToolLine(toolName, content string) string {
	if env, ok := parseEnvelopeMeta(content); ok && env.Handle != "" {
		// 顺序有意：句柄/字节数/截断标记在前，回读指引紧随，**截断说明放最后**——
		// 行长超限被截时先丢说明、绝不丢句柄与回读指引（说明可以从 result_read 重新拿到）。
		line := fmt.Sprintf("%s工具 %s 的历史结果：结果已外置为句柄 %s（共 %d 字节，truncated=%v）。"+
			"需要正文请用 result_read 按 offset/limit 分页回读。",
			foldedMarker, toolName, env.Handle, env.TotalBytes, env.Truncated)
		if env.Note != "" {
			line += "截断说明：" + truncateBytesRunes(env.Note, foldedNoteBytes)
		}
		if len(line) > foldedLineMaxBytes {
			line = line[:foldedLineMaxBytes]
		}
		return line
	}
	s := summarizeToolResult(toolName, content)
	if strings.TrimSpace(s) == "" {
		s = "（空结果）"
	}
	line := fmt.Sprintf("%s工具 %s 的历史结果（已压缩为摘要，非原文）：%s",
		foldedMarker, toolName, truncateBytesRunes(s, foldedSummaryBytes))
	return truncateBytesRunes(line, foldedLineMaxBytes)
}

// envelopeFoldMeta 外置信封里"折叠时必须保留"的元信息。
type envelopeFoldMeta struct {
	Handle     string
	TotalBytes int
	Truncated  bool
	Note       string
}

// parseEnvelopeMeta 识别统一结果信封（沿用 summarizeToolResult 的识别方式：只看 meta.handle，
// 不猜具体工具的字段），返回需要保留的元信息。
func parseEnvelopeMeta(content string) (envelopeFoldMeta, bool) {
	if content == "" || content[0] != '{' {
		return envelopeFoldMeta{}, false
	}
	var env struct {
		Meta struct {
			Handle         string `json:"handle"`
			TotalBytes     int    `json:"total_bytes"`
			Truncated      bool   `json:"truncated"`
			TruncationNote string `json:"truncation_note"`
		} `json:"meta"`
	}
	if json.Unmarshal([]byte(content), &env) != nil || env.Meta.Handle == "" {
		return envelopeFoldMeta{}, false
	}
	return envelopeFoldMeta{
		Handle:     env.Meta.Handle,
		TotalBytes: env.Meta.TotalBytes,
		Truncated:  env.Meta.Truncated,
		Note:       env.Meta.TruncationNote,
	}, true
}

// toolCallNames 把一条 assistant 消息里的工具调用名拼成可读列表。
func toolCallNames(calls []ToolCall) string {
	if len(calls) == 0 {
		return ""
	}
	names := make([]string, 0, len(calls))
	for _, tc := range calls {
		n := tc.Function.Name
		if n == "" {
			n = "unknown"
		}
		names = append(names, n)
	}
	return strings.Join(names, "、")
}

// capMessageContent 给单条消息的正文兜一个字符上限（截断必须显式标注）。
func capMessageContent(m Message, maxRunes int) Message {
	if maxRunes <= 0 || len([]rune(m.Content)) <= maxRunes {
		return m
	}
	m.Content = truncateRunes(m.Content, maxRunes) + truncatedMarker +
		"（原文过长已截断；这不是完整内容，需要全文请用 result_read 或缩小命令输出范围后重试）"
	return m
}

// splitLeadingSystem 取出**第一条** system 作为常驻层，其余作为对话（压缩路径用）。
// 只取一条：紧随其后的那条 system 是任务层（装配时排在常驻层之后），属于任务上下文，
// 不是"常驻层的第二份副本"。
func splitLeadingSystem(msgs []Message) (string, []Message) {
	if len(msgs) > 0 && msgs[0].Role == "system" {
		return msgs[0].Content, append([]Message(nil), msgs[1:]...)
	}
	return "", append([]Message(nil), msgs...)
}

// stripLeadingSystem 丢掉对话开头的**一条** system（常驻层副本），保留任务层与后续 system。
func stripLeadingSystem(msgs []Message) []Message {
	if len(msgs) > 0 && msgs[0].Role == "system" {
		return msgs[1:]
	}
	return msgs
}

// ═══ 工具函数 ═══════════════════════════════════════════════════════════════

// truncateRunes 按"字符"截断（不是字节），避免把多字节字符切成两半
// （裸字节切会让 json.Marshal 把半个字符替换成 U+FFFD，日语/中文结果被无故改写）。
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// truncateBytesRunes 按字节上限截断，但保证落在字符边界上（折叠摘要的行长按字节控制）。
func truncateBytesRunes(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// hashText 文本的 sha256（小写十六进制）。
func hashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
