package api

// 路径安全收敛点（审计 Toshell_AUDIT_2026-10-24：H2 / H3 / M9；复审计
// docs/SECURITY-REAUDIT-1.4.2.md：N1 / N5）
//
// 本文件是服务端**唯一**的载荷/工具路径校验实现：所有「用户/数据库可控字符串 →
// 磁盘路径」的拼接都必须经过这里（handlers_builders.go 的构建清理、按名下载、
// 载荷落盘读取、遗留文件下载/删除；handlers_mcp.go 的 data/tools 工具路径）。
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
// 第二层是**重解析点**（symlink / Windows 目录 junction）。词法上 p 明明在 dir
// 内，但路径上某一层可能是链接、真实目标在 dir 外 —— 词法断言看不见。这里有三条
// 必须写进维护者脑子里的 Windows 事实（复审计 N1 的根因）：
//
//  1. 软链（symlink）在 os.Lstat 下带 ModeSymlink，filepath.EvalSymlinks 会跟随
//     并返回真实路径；
//  2. **目录 junction（IO_REPARSE_TAG_MOUNT_POINT）在 Lstat 下不是 symlink**
//     （Go 在 Windows 上把非 symlink 的重解析点标记成 ModeIrregular），
//     所以「只检查 ModeSymlink」或「只靠 EvalSymlinks」都**看不穿** junction：
//     EvalSymlinks(junction) 会原样返回该路径（看起来"解析成功"），
//     而 EvalSymlinks(junction\子项) 直接报错；
//  3. 于是唯一可靠的做法是**两条互补的物理断言**，任一条失败即拒绝（fail-closed）：
//     a) EvalSymlinks 必须成功，并对解析结果重复 Rel 断言（覆盖软链、覆盖
//     真实路径逃逸）；
//     b) 从基目录到目标**逐段** os.Lstat，拒绝 ModeIrregular（覆盖 junction，
//     因为 junction 的 Lstat 不是 symlink，只能靠这个 mode 位识别）。
//
// ⚠️ 绝对不允许「EvalSymlinks 报错就回落成只做词法断言」：那等于把 junction、
// 悬空软链、无法解析的父目录全部放行，而复审计 N1 正是靠这一点用未认证的
// `file:<junction>\win.ini` 读到、并用 DELETE 删掉了基目录外的文件。
// 反过来，也不能把 Lstat 当唯一依据：junction 在 Lstat 下不是 symlink。

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
	unsafePayloadNameMsg = "载荷名只允许字母/数字/点/下划线/连字符（1~64 字符，不能以点开头/结尾，不能是 Windows 设备名）"
)

// ErrEmptyPath 空路径：既不是文件也不是目录，一律拒绝。
var ErrEmptyPath = errors.New("path is empty")

// safePayloadName 把「载荷名」收敛成一个**单段安全文件名**。
//
// 规则（白名单，而非黑名单）：
//  1. 长度 1..64 字节；
//  2. 不允许以 "." 开头 —— 因此 "."、".."、".hidden" 全部被拒；
//  3. 不允许以 "." 或空格**结尾**（复审计 N5）：Windows 会静默去掉尾点/尾空格，
//     把 "a." 当成 "a"、"a " 当成 "a"，造成「校验的名字」与「磁盘上的名字」
//     不一致（后续按名下载/去重/清理都会错位）；
//  4. 拒绝 Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，含带扩展名形式），
//     与 internal/server/plugin 的 ValidatePluginName 对齐：在 Windows 上
//     "NUL"、"NUL.raw" 打开的是设备而不是文件，读取得到空体、删除是 no-op；
//  5. 只允许 [A-Za-z0-9._-]；
//  6. filepath.Base(s) == s —— 上面的字符集已排除 / \ :，这一条是纵深防御：
//     万一以后有人放宽字符集，分隔符仍需单独把关；
//  7. 显式拒绝 / \ : 与 NUL（字符白名单已覆盖，保留独立分支是为了让「为什么拒绝」
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
	// N5：Windows 会去掉结尾的点和空格；"a." 与 "a" 在磁盘上等价。
	if strings.HasSuffix(s, ".") {
		return "", fmt.Errorf("载荷名不能以点结尾（Windows 会把 a. 当成 a）")
	}
	if strings.HasSuffix(s, " ") {
		return "", fmt.Errorf("载荷名不能以空格结尾")
	}
	// N5：与 plugin.ValidatePluginName 对齐，拒绝 Windows 保留设备名。
	if isWindowsReservedDeviceName(s) {
		return "", fmt.Errorf("载荷名 %q 是 Windows 保留设备名", s)
	}
	// 显式分隔符/冒号/NUL 检查（纵深防御，见函数注释第 7 条）。
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

// isWindowsReservedDeviceName 判断 name 是否是 Windows 保留设备名。
//
// 与 internal/server/plugin.isReservedDeviceName 的逻辑保持一致（那边未导出，
// 这里复制一份；两边规则必须同步，否则又会出现 N5 那种「两套校验漂移」）。
// Windows 会忽略设备名末尾的空格、也会忽略第一个点之后的部分，因此先取第一个点
// 之前的主名，再去掉尾部空格后按大写比较："NUL"、"NUL.raw"、"nul " 全部命中。
func isWindowsReservedDeviceName(name string) bool {
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToUpper(strings.Trim(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	}
	return false
}

// requireSingleSegmentName 断言 name 是一个**单段文件名**（不含任何路径分隔符、
// 不是 "."/".."、不做多段路径）。
//
// 为什么单独需要它：resolveInDir 为了通用性允许 name 含子目录（只要最终仍在
// dir 内）；但载荷下载/删除的 id 来自 **URL**，一旦允许 "子目录/文件"，就等于
// 给「中间某段是 junction」留了入口（复审计 N1 的第 2 条建议：从根上消除
// "子路径 + 中间重解析点"）。因此凡是「不可能是子路径」的调用点都必须先过这里。
func requireSingleSegmentName(name string) error {
	if name == "" {
		return ErrEmptyPath
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("文件名包含 NUL 字符")
	}
	// 显式检查两种分隔符：Unix 上 "\\" 不是分隔符，但 Windows 上是；
	// 这里与平台无关地一律拒绝，避免同一请求在不同平台行为分叉。
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("只允许单段文件名（不能包含路径分隔符）")
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return fmt.Errorf("只允许单段文件名（不能含路径段）")
	}
	return nil
}

// resolveInDir 把 name 拼到 dir 下并断言结果**仍在 dir 内**，返回清理后的绝对路径。
//
// 判定顺序（任何一步失败都返回 error，没有"回落放行"分支）：
//  1. 词法前置：dir 非空、name 非空、不含 NUL、不是绝对路径/带卷标（Windows 的
//     C:foo、\\server\share 会让 Join 直接丢弃 dir）；
//  2. 词法边界：Join 后 Rel(dir,p) 不得以 ".." 或 ".."+分隔符 开头、不得为绝对
//     路径、不得是 "."（指向目录本身）；
//  3. 基目录必须能被解析：EvalSymlinks(dir) 失败 → 拒绝（父/基目录不存在或无法
//     解析时不猜，直接 fail-closed）；
//  4. **父目录必须能被解析**：EvalSymlinks(filepath.Dir(p)) 失败 → 拒绝。解析出的
//     真实父目录再对真实基目录做一次 Rel 断言（识破软链/junction 目录逃逸）；
//  5. 逐段物理断言：从基目录到目标逐段 os.Lstat，拒绝 ModeIrregular（Windows
//     junction/mount point 在 Lstat 下**不是** symlink，只能靠这个 mode 位识别）。
//     某一段不存在就停止（后面的段不可能存在）；
//  6. 目标存在（第 5 步走到最后一段且 Lstat 成功）时：EvalSymlinks(p) **必须**
//     成功，再对真实基目录做一次 Rel 断言（识破软链目标逃逸）；报错也拒绝；
//  7. 目标不存在时：只允许第 3/4 步已通过、第 5 步没有发现重解析点，**并且**
//     name 是单段文件名（filepath.Base(name) == name 且不含 / \）。这样「创建类」
//     调用不会沿着一个 junction 目录写到基目录之外。
//
// 第 5 步不能省：EvalSymlinks 之于 junction 是「对 junction 本身原样返回、对
// junction\子项报错」，所以对「junction\不存在的文件」这种目标，第 4 步会成功、
// 第 6 步根本不执行 —— 只有逐段 Lstat 能把它拦下来。
//
// ⚠️ 本函数允许 name 含子目录（对调用方更通用）；如果调用方只想要单段文件名，
// 必须先过 safePayloadName / requireSingleSegmentName —— 真正的「单段」约束在那里。
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

	// ── 物理断言（fail-closed，复审计 N1）──────────────────────────────────

	// 3. 基目录必须可解析。基目录不存在/无法解析时不"猜"，直接拒绝。
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", fmt.Errorf("基目录无法解析为真实路径（拒绝）: %w", err)
	}

	// 4. 父目录必须可解析，并在真实路径上再做一次边界断言。
	realParent, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", fmt.Errorf("父目录不存在或无法解析（拒绝）: %w", err)
	}
	prel, err := filepath.Rel(realBase, realParent)
	if err != nil || !relInsideOrSelf(prel) {
		return "", fmt.Errorf("路径经符号链接/重解析点逃逸出基目录：%q", name)
	}

	// 5. 逐段 Lstat：junction 在 Lstat 下不是 symlink，必须靠 ModeIrregular 识别。
	exists, err := assertNoReparsePoints(base, rel)
	if err != nil {
		return "", err
	}

	if !exists {
		// 7. 目标不存在：只允许单段文件名的创建/删除意图。
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			return "", fmt.Errorf("目标不存在时只允许单段文件名：%q", name)
		}
		return p, nil
	}

	// 6. 目标存在：EvalSymlinks 必须成功（报错也拒绝），并对真实路径再断言一次。
	realTarget, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("目标无法解析为真实路径（拒绝）: %w", err)
	}
	rrel, err := filepath.Rel(realBase, realTarget)
	if err != nil || !relInside(rrel) || rrel == "." {
		return "", fmt.Errorf("路径经符号链接/重解析点逃逸出基目录：%q", name)
	}
	return p, nil
}

// assertNoReparsePoints 从 base 开始逐段 Lstat rel 的每个分量，拒绝
// ModeIrregular（Windows 的 junction/mount point 及其它非 symlink 重解析点）。
//
// 返回 exists：true 表示 rel 的每一段都存在（目标已存在）；false 表示在某个分量
// 处 os.IsNotExist（此时目标必然不存在，后续段不可能存在）。
//
// 为什么只拒绝 ModeIrregular、不拒绝 ModeSymlink？软链会被第 4/6 步的
// EvalSymlinks 解析并断言真实路径，语义是「指向目录内部仍可用、指向外面被拒」；
// 而 junction 不会被 EvalSymlinks 跟随，只能在这里拒绝（见文件头注释）。
func assertNoReparsePoints(base, rel string) (bool, error) {
	cur := base
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, fmt.Errorf("无法检查路径分量 %q（拒绝）: %w", part, err)
		}
		if fi.Mode()&os.ModeIrregular != 0 {
			return false, fmt.Errorf("路径包含 Windows 重解析点（junction/mount point）：%q", part)
		}
	}
	return true, nil
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

// relInsideOrSelf 同 relInside，但额外放行 "."：父目录等于基目录是合法的
// （文件直接位于基目录下）。
func relInsideOrSelf(rel string) bool {
	if rel == "." {
		return true
	}
	return relInside(rel)
}
