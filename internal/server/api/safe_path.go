package api

// 路径安全收敛点（审计 Toshell_AUDIT_2026-10-24：H2 / H3 / M9）
//
// 本文件是服务端**唯一**的载荷路径校验实现：所有「用户/数据库可控字符串 → 磁盘路径」
// 的拼接都必须经过这里（handlers_builders.go 的构建清理、按名下载、载荷落盘读取、
// 遗留文件下载/删除）。
//
// 为什么只靠 filepath.Join 不够？
// filepath.Join 只做**词法清理**（Clean）：它会忠实地折叠 ".." 与重复分隔符，但
// **完全不限制结果仍落在基目录内**，甚至对绝对路径会直接丢弃前面的 dir：
//
//	filepath.Join("/srv/toshell/implants", "../configs/server.yaml")
//	// => "/srv/toshell/configs/server.yaml"   ← Join 认为这是"合法"路径
//	filepath.Join("/srv/toshell/implants", "../../etc/passwd")
//	// => "/srv/etc/passwd"
//
// 所以 Join、Join+Base、甚至 Clean+前缀字符串比较（"implants_evil" 也会命中
// "implants" 前缀）都不构成边界。正确做法是拼接后求**相对路径**再做断言：
// filepath.Rel(dir, p) 只要等于 ".." 或以 ".."+分隔符开头，就说明跑出了 dir。
//
// 另一层是**符号链接**：词法上 p 明明在 dir 内，但路径上某一层可能是软链、真实
// 目标在 dir 外 —— 词法断言看不见。因此对存在的目标再做一次 EvalSymlinks 后
// 重复断言；目标不存在时保持词法结论即可（后续 os.Stat/os.Open 会因不存在而失败，
// 不会误读越界内容）。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// maxPayloadNameLen 载荷名/文件名长度上限（字节）。64 足够容纳
	// "implant-<unix>"、"build-<unixnano>" 这类服务端命名，又不会让名字本身
	// 撑爆文件系统或日志。
	maxPayloadNameLen = 64

	// unsafePayloadNameMsg 对外统一的中文原因。**不回显**用户输入（避免把攻击载荷
	// 原样反射进响应/日志，也避免日志注入）。
	unsafePayloadNameMsg = "载荷名只允许字母/数字/点/下划线/连字符（1~64 字符，且不能以点开头）"
)

// ErrEmptyPath 空路径：既不是文件也不是目录，一律拒绝。
var ErrEmptyPath = errors.New("path is empty")

// safePayloadName 把「载荷名」收敛成一个**单段安全文件名**。
//
// 规则（白名单，而非黑名单）：
//  1. 长度 1..64 字节；
//  2. 只允许 [A-Za-z0-9._-]；
//  3. 不允许以 "." 开头 —— 因此 "."、".."、".hidden" 全部被拒；
//  4. filepath.Base(s) == s —— 上面的字符集已排除 / \ :，这一条是纵深防御：
//     万一以后有人放宽字符集，分隔符仍需单独把关；
//  5. 显式拒绝 / \ : 与 NUL（字符白名单已覆盖，保留独立分支是为了让「为什么拒绝」
//     在代码里可读，并防止白名单被后续改动悄悄削弱）。
//
// 通过校验时**原样返回**（不做大小写/其它改写），保证 "build-1792..."、
// "implant-1792..." 这类既有合法名逐字节不变，不破坏现有功能。
func safePayloadName(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("载荷名不能为空")
	}
	if len(s) > maxPayloadNameLen {
		return "", fmt.Errorf("载荷名过长（%d 字节，最多 %d）", len(s), maxPayloadNameLen)
	}
	if strings.HasPrefix(s, ".") {
		return "", fmt.Errorf("载荷名不能以点开头")
	}
	// 显式分隔符/冒号/NUL 检查（纵深防御，见函数注释第 5 条）。
	if strings.ContainsAny(s, `/\:`) || strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("载荷名不能包含路径分隔符、冒号或 NUL")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return "", fmt.Errorf("载荷名包含非法字符 %q", string(c))
	}
	// 纵深防御：即使字符集被放宽，也不允许多段路径 / 绝对路径。
	if base := filepath.Base(s); base != s {
		return "", fmt.Errorf("载荷名必须是单个文件名（不能含路径段）")
	}
	return s, nil
}

// resolveInDir 把 name 拼到 dir 下并断言结果**仍在 dir 内**，返回清理后的绝对路径。
//
// 三重校验：
//  1. 词法：filepath.IsAbs / VolumeName 先挡掉「绝对路径」这类会让 Join 丢弃 dir
//     的输入（Windows 的 C:foo、\\server\share 一并挡掉）；
//  2. 词法：Join 之后用 filepath.Rel(dir, p) 断言不以 ".." 开头（并拒绝指向 dir 自身）；
//  3. 物理：目标若存在，EvalSymlinks 后重复第 2 步，防软链逃逸（不存在则只做词法断言）。
//
// ⚠️ 本函数允许 name 含子目录（对调用方更通用）；如果调用方只想要单段文件名，
// 必须先过 safePayloadName —— 真正的「单段」约束在那里，别在这里重复实现。
func resolveInDir(dir, name string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("基目录为空")
	}
	if name == "" {
		return "", ErrEmptyPath
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("路径包含 NUL 字符")
	}
	// 绝对路径 / 带卷标的路径：filepath.Join 会直接采用它们（等于绕过基目录）。
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("不允许绝对路径：%q", name)
	}

	base, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("解析基目录失败: %w", err)
	}
	p := filepath.Join(base, name) // Join = 拼接 + 词法 Clean（不构成边界！见文件头注释）

	rel, err := filepath.Rel(base, p)
	if err != nil {
		return "", fmt.Errorf("无法计算相对路径（不在同一卷？）: %w", err)
	}
	if !relInside(rel) {
		return "", fmt.Errorf("路径越界：%q 不在基目录内", name)
	}
	if rel == "." {
		// name 是 "." / "sub/.." 之类，指向目录本身；载荷操作的对象必须是文件。
		return "", fmt.Errorf("路径指向基目录本身：%q", name)
	}

	// 物理断言：词法检查看不到符号链接。目标存在时解析真实路径再断言一次；
	// 目标不存在（EvalSymlinks 报错）时保持词法结论 —— 后续 os.Stat/os.Open
	// 同样会失败，不会读到越界内容。
	if real, lerr := filepath.EvalSymlinks(p); lerr == nil {
		rbase, berr := filepath.EvalSymlinks(base)
		if berr != nil {
			rbase = base
		}
		rrel, rerr := filepath.Rel(rbase, real)
		if rerr != nil || !relInside(rrel) || rrel == "." {
			return "", fmt.Errorf("路径经符号链接逃逸出基目录：%q", name)
		}
	}
	return p, nil
}

// relInside 判断 filepath.Rel 的结果是否表示「仍在基目录内」。
// 只放行真正的后代路径（"./x" 或 "x"），".."、"../x"、绝对路径一律拒绝。
func relInside(rel string) bool {
	if rel == ".." || filepath.IsAbs(rel) {
		return false
	}
	if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return rel != ""
}
