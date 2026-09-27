package modules

import "fmt"

// 错误码：**对外契约**（HTTP 响应里的 code 字段 / 审计日志 / 测试断言都依赖它），
// 只允许新增，不允许改名。命名口径：<对象>_<问题>，全小写下划线。
//
// 为什么一定要有稳定的机器可读码：失败路径的价值在于"可判定"。只有中文文案时，
// 脚本/前端/MCP 调用方只能做字符串匹配，任何文案微调都会静默破坏它们的判断。
const (
	// ── 会话（第 1 步）──
	CodeSessionNotFound = "session_not_found"
	CodeSessionInactive = "session_inactive"
	// ── 模块登记与字节（第 2、3 步）──
	CodeModuleNotRegistered = "module_not_registered"
	CodeManifestInvalid     = "module_manifest_invalid"
	CodeModuleFileMissing   = "module_file_missing"
	CodeHashMismatch        = "module_hash_mismatch"
	CodeSizeMismatch        = "module_size_mismatch"
	// ── 平台/ABI（第 4、5、6 步）──
	CodeArchMismatch     = "module_arch_mismatch"
	CodeOSMismatch       = "module_os_mismatch"
	CodeABIMismatch      = "module_abi_version_mismatch"
	CodeABIExportsAbsent = "module_abi_exports_missing"
	CodeNotNative        = "module_not_native"
	CodePEInvalid        = "module_pe_invalid"
	// ── token（第 7 步）──
	CodeTokenNotFound     = "token_not_found"
	CodeTokenExpired      = "token_expired"
	CodeTokenReused       = "token_reused"
	CodeTokenSessionWrong = "token_session_mismatch"
	CodeTokenModuleWrong  = "token_module_mismatch"
	// ── 下发（第 8 步）──
	CodePushFailed    = "module_push_failed"
	CodeTaskCreateErr = "module_task_create_failed"
	// ── 其它 ──
	CodeImplantUnsupported = "implant_exec_module_unsupported"
	CodeTooLarge           = "module_too_large"
	CodeBadRequest         = "bad_request"
)

// Error 是带错误码与 HTTP 状态的服务端错误。
//
// 把 HTTP 状态挂在错误对象上（而不是在 handler 里 switch 错误码）是为了让
// "哪类失败该返回几"这个决定只有一处：会话不存在 → 404、字节/版本/架构不符 → 409
// （请求本身合法，但目标状态冲突，重试无用且危险）、服务端自身问题 → 500。
type Error struct {
	Code    string `json:"code"`
	Message string `json:"error"`
	HTTP    int    `json:"-"`
}

func (e *Error) Error() string { return e.Message }

// ErrorCode 从任意 error 提取机器可读码（非 *Error 时返回空串）。
func ErrorCode(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

// NewError 构造一个带码错误（handler 构造纯函数之外的错误时复用）。
func NewError(httpStatus int, code, format string, a ...interface{}) *Error {
	return &Error{Code: code, HTTP: httpStatus, Message: fmt.Sprintf(format, a...)}
}
