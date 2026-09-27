// Package moduleabi 是 v1.4.0 S4「内存模块按需加载」的 **ABI 契约唯一事实来源**。
//
// 背景（为什么需要一份显式 ABI）：
//   - 已有的反射式加载底座（implant/blob_windows.go）只会「映射 PE → 修重定位/导入表 →
//     调 DllMain → 可选调一个**零参**导出」。零参意味着模块拿不到会话 id、拿不到参数、
//     也回不来输出 —— 只能靠 side effect（自己再连一次 C2），既不可观测也无法做审计。
//   - 所以本包定义 tsh_module_ctx + tsh_module_main 约定：模块**同步**接收一个上下文、
//     把结果写进宿主给的输出缓冲区、用返回值表达成败。宿主（植入端）与该约定一起
//     构成 ABI；C 侧同一份契约在 internal/server/builder/implant_c/module/tsh_module.h。
//
// 为什么 ABI 版本必须硬拒而不是「尽量兼容」：
//   - ctx 是一个**裸内存结构体**，双方靠字段偏移对齐。版本不符时字段偏移/语义可能已经
//     变了，继续跑不会报错，只会读到垃圾指针/写坏内存 —— 那是「加载了但行为诡异」，
//     比直接拒绝危险得多（进程内崩宿主 = 会话永久掉线）。因此：
//     ① 服务端下发前比对 manifest 声明的 abi 与本包 Version；
//     ② 植入端加载后**先调 tsh_module_abi()**，返回值和本包 Version 不等即拒绝执行，
//     并把双方的版本号一起回传（可观测的失败，而不是静默错行为）。
//
// 为什么 ABI 常量是「版本化令牌」而不是散落的魔数：
//   - 与 internal/common/features 的 cap:v1 令牌同一思路：把版本写进唯一常量，
//     解析/编解码集中在本包，未来 tsh_module_abi=2 时两侧只需要各改一处。
//
// 注意：植入端模板是**独立 module**（toshell-implant，自带 go.mod），import 不到本包，
// 因此植入端里有一份逐字段镜像（implant/xload_windows.go）。两份的一致性由
// 单测守住（moduleabi_test.go 会解析 C 头与本包结构体逐字段比对，并核对植入端镜像）。
package moduleabi

import (
	"fmt"
	"strings"
)

// Version 是当前 ABI 版本。任何字段增删/语义变化都必须 +1（不许原地改）。
const Version uint32 = 1

// TokenPrefix 是模块 ABI 令牌前缀（形如 `tshmod:v1`）。
//
// 为什么要一个"字符串令牌"而不是只比较整数：模块是**独立交付物**，可能由第三方/
// 操作员手工构建并在别处流转。把版本写进一个可 grep 的令牌，使
// manifest.json / 构建日志 / 错误文案里都能一眼看出"这个模块是哪一代 ABI"。
const TokenPrefix = "tshmod:v1"

// ─── 导出约定（模块必须/可选导出的符号名）────────────────────────────────────

const (
	// ExportABI 必须导出：uint32_t tsh_module_abi(void)，返回模块的 ABI 版本。
	ExportABI = "tsh_module_abi"
	// ExportMain 必须导出：int32_t tsh_module_main(tsh_module_ctx *ctx)，模块入口。
	ExportMain = "tsh_module_main"
	// ExportName 可选导出：const char *tsh_module_name(void)，人类可读的模块名。
	ExportName = "tsh_module_name"
	// ExportError 可选导出：const char *tsh_module_error(void)，
	// 返回上一次执行的错误说明（NUL 结尾 UTF-8）。没有它时宿主只能用返回码文案。
	ExportError = "tsh_module_error"
)

// ─── 返回值 / 错误码约定 ─────────────────────────────────────────────────────
//
// 约定：0 = 成功；负数 = 失败，且负数就是"错误类别"（不是 errno）。
// 这样宿主不必解析模块自己的输出就能给出稳定的错误分类（可审计、可断言），
// 细节说明再由 tsh_module_error() 补充。
const (
	CodeOK        int32 = 0
	CodeErrABI    int32 = -1 // ABI 不符 / 缺 tsh_module_abi
	CodeErrArgs   int32 = -2 // 参数 JSON 不合法或缺少必需字段
	CodeErrDenied int32 = -3 // 目标环境不满足前提（权限/平台/依赖缺失）
	CodeErrOutput int32 = -4 // 输出缓冲区不足（out_len 已被写满）
	CodeErrPanic  int32 = -5 // 模块内部异常已被自身捕获
	CodeErrHost   int32 = -6 // 宿主侧错误（映射失败、导出缺失、校验不符）
)

// codeMessages 是返回码 → 中文说明。**面向操作员**，所以必须能直接看懂"哪里不对"，
// 不允许出现空文案（未知码也会回落到带码值的说明）。
var codeMessages = map[int32]string{
	CodeOK:        "成功",
	CodeErrABI:    "模块 ABI 版本不符或缺少 tsh_module_abi 导出",
	CodeErrArgs:   "模块参数不合法（args_json 解析失败或缺少必需字段）",
	CodeErrDenied: "模块执行前提不满足（权限/平台/依赖）",
	CodeErrOutput: "模块输出超出宿主提供的缓冲区上限",
	CodeErrPanic:  "模块内部异常（已由模块自身捕获）",
	CodeErrHost:   "宿主侧错误（PE 映射/导出解析/完整性校验失败）",
}

// CodeMessage 把返回码翻译成中文说明（未知码也给出可用的文案）。
func CodeMessage(code int32) string {
	if msg, ok := codeMessages[code]; ok {
		return msg
	}
	return fmt.Sprintf("未知模块返回码 %d", code)
}

// ─── 上限（宿主与模块共同遵守）──────────────────────────────────────────────

const (
	// MaxArgsLen 参数 JSON 长度上限（宿主会拒绝更长的参数，避免模块拿到被截断的 JSON）。
	MaxArgsLen = 64 * 1024
	// DefaultOutputCap 宿主提供的最小输出容量；模块必须在 out_len <= out_cap 内写入。
	DefaultOutputCap = 64 * 1024
	// MaxModuleSize 单个模块二进制的体积上限（受协议单帧上限约束，见 protocol.MaxPayloadSize）。
	MaxModuleSize = 4 * 1024 * 1024
)

// ─── 上下文结构（与 C 头逐字段对齐）─────────────────────────────────────────

// Ctx 是 tsh_module_ctx 的 Go 镜像。
//
// ⚠️ 字段顺序/类型必须与 implant_c/module/tsh_module.h 完全一致，且**只允许用
// ≤4 字节的标量 + 指针**：amd64 上 gcc 与 Go 的 uint64 对齐规则一致，但 386 上
// long long 的对齐有多种历史约定，混进 uint64 就是"在某个工具链上偏移错位"的种子。
// 会话 id 因此拆成 lo/hi 两个 uint32。
//
// 本结构在植入端是**手工内存**（VirtualAlloc 的 RW 页）而不是 Go 堆对象：
// 模块会同步读写它，若它落在可被 Go 运行时移动/回收的地方，就会出现
// "回调期间指针失效"这类极难复现的崩溃（Go 目前不移动对象，但不能把正确性押在这上面）。
type Ctx struct {
	StructSize   uint32  // 本结构字节数（双方据此发现布局漂移）
	ABIVersion   uint32  // = Version
	SessionIDLo  uint32  // 会话标识低 32 位
	SessionIDHi  uint32  // 会话标识高 32 位
	ArgsJSON     uintptr // const char*：参数 JSON（UTF-8，NUL 结尾）
	ArgsLen      uint32  // 参数 JSON 字节数（不含结尾 NUL）
	Flags        uint32  // 保留：当前恒 0（模块不得依赖）
	OutBuf       uintptr // char*：输出缓冲区（宿主分配，模块写入）
	OutCap       uint32  // 输出缓冲区容量（含结尾 NUL 的可用字节数）
	OutLen       uint32  // 模块写入的输出长度（不含结尾 NUL）
	TokenFNV     uint32  // 一次性 token 的 FNV-1a 32 位摘要（模块可用于审计/去重，**不含明文 token**）
	Reserved     uint32  // 保留：当前恒 0
	HostReserved uintptr // 保留：宿主回调表（当前恒 NULL）
}

// FieldNames 返回 Ctx 的字段名（按内存顺序）。
// 单测用它把 C 头 / 植入端镜像与这里的顺序逐字段对齐 —— 手写结构体最容易出的错
// 就是"字段顺序对了但漏了一个"，那会整体错位而编译器不会报错。
func FieldNames() []string {
	return []string{
		"StructSize", "ABIVersion", "SessionIDLo", "SessionIDHi",
		"ArgsJSON", "ArgsLen", "Flags",
		"OutBuf", "OutCap", "OutLen",
		"TokenFNV", "Reserved", "HostReserved",
	}
}

// SessionID 把 lo/hi 拼回 64 位会话 id（与植入端 buildCtx 的拆分对称）。
func (c *Ctx) SessionID() uint64 {
	return uint64(c.SessionIDLo) | uint64(c.SessionIDHi)<<32
}

// ArgumentHeader 是宿主下发给模块的上下文**头信息**（不放模块二进制本身）。
//
// 它同时是 token 的一次性凭据描述：植入端拿 token 取出模块二进制（按 token 索引，
// 用后即焚），再用这里的 module_id/sha256 核对"下发的字节确实是我被授权执行的那个"。
type ArgumentHeader struct {
	ModuleID string `json:"module_id"`
	Token    string `json:"token"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
	ABI      uint32 `json:"abi"`
	Entry    string `json:"entry,omitempty"`
	// ArgsJSON 是操作员/上层给的参数，原样透传给模块（不解析、不改写）。
	ArgsJSON string `json:"args_json,omitempty"`
}

// Validate 做纯函数级自检（服务端下发前与植入端收到后各跑一次，口径一致）。
// 返回的错误文案直接面向操作员：必须能区分"哪一步不对"。
func (h *ArgumentHeader) Validate() error {
	if strings.TrimSpace(h.Token) == "" {
		return fmt.Errorf("module token missing")
	}
	if strings.TrimSpace(h.ModuleID) == "" {
		return fmt.Errorf("module_id missing")
	}
	if len(h.SHA256) != 64 {
		return fmt.Errorf("sha256 must be 64 hex chars, got %d", len(h.SHA256))
	}
	for i := 0; i < len(h.SHA256); i++ {
		c := h.SHA256[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return fmt.Errorf("sha256 contains non-hex char %q", string(c))
		}
	}
	if h.Size <= 0 {
		return fmt.Errorf("module size must be positive, got %d", h.Size)
	}
	if h.Size > MaxModuleSize {
		return fmt.Errorf("module size %d exceeds limit %d", h.Size, MaxModuleSize)
	}
	if h.ABI != Version {
		// 版本握手失败必须在此**明确拒绝**：调用方据此回传双方的版本号，
		// 而不是把不兼容的模块塞进进程里"试试看"。
		return fmt.Errorf("module abi mismatch: module declares %d, host requires %d", h.ABI, Version)
	}
	if len(h.ArgsJSON) > MaxArgsLen {
		return fmt.Errorf("args_json too large: %d > %d", len(h.ArgsJSON), MaxArgsLen)
	}
	return nil
}

// FNV1a32 计算 token 的摘要（模块上下文的 TokenFNV 字段用）。
// 用 FNV-1a 而不是 sha256：目的只是"让模块能做审计关联/去重"，不需要抗碰撞，
// 且 4 字节刚好塞进 4 字节对齐的 ctx，不引入任何 64 位对齐问题。
func FNV1a32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
