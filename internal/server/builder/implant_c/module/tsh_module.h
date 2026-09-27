/* tsh_module.h —— ToShell 内存模块 ABI（v1.4.0 S4）
 *
 * 这是 internal/common/moduleabi 的 C 侧同一份契约。任何字段增删/语义变化都必须
 * 把 TSH_MODULE_ABI_VERSION +1，并同步修改 Go 侧 moduleabi.Version —— 两份不一致时
 * 加载会被**硬拒**（宿主先调 tsh_module_abi 比对版本），不会"加载了但行为诡异"。
 *
 * 为什么全部字段都是 <= 4 字节标量 + 指针：
 * iv. 386 上 `long long`/`uint64_t` 的对齐在历史上存在多种约定（gcc 的 -malign-double、
 *     MSVC、SysV），而宿主植入端是 Go（windows/386）——Go 对 uint64 用 4 字节对齐。
 *     混进一个 uint64 就可能让 ctx 的字段偏移在某一侧错位，而编译器不会报错。
 *     所以会话 id 拆成 lo/hi 两个 uint32（见下）。
 *
 * 模块必须导出（缺任何一个都会被宿主拒绝加载）：
 *   uint32_t tsh_module_abi(void);                  // 返回 TSH_MODULE_ABI_VERSION
 *   int32_t  tsh_module_main(tsh_module_ctx *ctx);   // 入口，返回值见下面的返回码
 * 模块可选导出：
 *   const char *tsh_module_name(void);              // 人类可读名字
 *   const char *tsh_module_error(void);             // 上次失败原因（NUL 结尾 UTF-8）
 *
 * 调用约定：宿主**同步**调用 tsh_module_main（在任务 worker 线程上）。模块应当
 * 尽快返回；要跑长活请自己起线程，但宿主只等任务超时窗口。
 */
#ifndef TSH_MODULE_H
#define TSH_MODULE_H

#include <stdint.h>
#include <stddef.h>

#define TSH_MODULE_ABI_VERSION 1u

/* 返回码：0 = 成功；负数 = 失败类别（不是 errno） */
#define TSH_MOD_OK            0
#define TSH_MOD_ERR_ABI      (-1) /* ABI 不符 / 缺 tsh_module_abi */
#define TSH_MOD_ERR_ARGS     (-2) /* args_json 不合法或缺少必需字段 */
#define TSH_MOD_ERR_DENIED   (-3) /* 前提不满足（权限/平台/依赖） */
#define TSH_MOD_ERR_OUTPUT   (-4) /* 输出缓冲区不足 */
#define TSH_MOD_ERR_PANIC    (-5) /* 模块内部异常（自身捕获） */
#define TSH_MOD_ERR_HOST     (-6) /* 宿主侧错误（映射/导出/校验） */

typedef struct tsh_module_ctx {
    uint32_t struct_size;    /* 本结构字节数：双方据此发现布局漂移 */
    uint32_t abi_version;    /* = TSH_MODULE_ABI_VERSION */
    uint32_t session_id_lo;  /* 会话标识低 32 位 */
    uint32_t session_id_hi;  /* 会话标识高 32 位 */
    const char *args_json;   /* 参数 JSON（UTF-8，NUL 结尾），只读 */
    uint32_t args_len;       /* 参数 JSON 字节数（不含结尾 NUL） */
    uint32_t flags;          /* 保留：当前恒 0，模块不得依赖 */
    char *out_buf;           /* 输出缓冲区（宿主分配），模块写入 */
    uint32_t out_cap;        /* 输出缓冲区容量（含结尾 NUL 的可用字节数） */
    uint32_t out_len;        /* 模块写入的输出长度（不含结尾 NUL） */
    uint32_t token_fnv;      /* 一次性 token 的 FNV-1a 32 位摘要（审计用，无明文 token） */
    uint32_t reserved;       /* 保留：当前恒 0 */
    void *host_reserved;     /* 保留：宿主回调表（当前恒 NULL） */
} tsh_module_ctx;

/* 编译期布局断言：前 4 个 uint32 + args_json 的偏移在 32/64 位下都恒为 0/4/8/12/16。
 * 只要有人调整了字段顺序，这里会直接在编译期炸掉（比运行期错位好得多）。 */
typedef char tsh_ctx_layout_check[
    (offsetof(tsh_module_ctx, struct_size)   == 0  &&
     offsetof(tsh_module_ctx, abi_version)   == 4  &&
     offsetof(tsh_module_ctx, session_id_lo) == 8  &&
     offsetof(tsh_module_ctx, session_id_hi) == 12 &&
     offsetof(tsh_module_ctx, args_json)     == 16) ? 1 : -1];

/* 便捷宏：把字符串写进输出缓冲区并置 out_len（超限返回 TSH_MOD_ERR_OUTPUT）。 */
static __inline int tsh_out_str(tsh_module_ctx *ctx, const char *s, uint32_t n) {
    if (ctx == 0 || ctx->out_buf == 0) {
        return TSH_MOD_ERR_HOST;
    }
    if ((uint32_t)n + 1u > ctx->out_cap) {
        return TSH_MOD_ERR_OUTPUT;
    }
    {
        uint32_t i;
        for (i = 0; i < n; i++) {
            ctx->out_buf[i] = s[i];
        }
        ctx->out_buf[n] = 0;
        ctx->out_len = n;
    }
    return TSH_MOD_OK;
}

#endif /* TSH_MODULE_H */
