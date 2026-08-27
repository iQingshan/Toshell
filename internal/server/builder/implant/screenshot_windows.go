//go:build windows && !light

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"syscall"
	"time"
	"unsafe"
)

var (
	procGetDC                  = resolveAPI("user32.dll", "GetDC")
	procReleaseDC              = resolveAPI("user32.dll", "ReleaseDC")
	procCreateCompatibleDC     = resolveAPI("gdi32.dll", "CreateCompatibleDC")
	procCreateCompatibleBitmap = resolveAPI("gdi32.dll", "CreateCompatibleBitmap")
	procSelectObject           = resolveAPI("gdi32.dll", "SelectObject")
	procBitBlt                 = resolveAPI("gdi32.dll", "BitBlt")
	procGetDIBits              = resolveAPI("gdi32.dll", "GetDIBits")
	procDeleteDC               = resolveAPI("gdi32.dll", "DeleteDC")
	procDeleteObject           = resolveAPI("gdi32.dll", "DeleteObject")
	procGetDeviceCaps          = resolveAPI("gdi32.dll", "GetDeviceCaps")
	procGetSystemMetrics       = resolveAPI("user32.dll", "GetSystemMetrics")

	procSetProcessDPIAware     = resolveAPI("user32.dll", "SetProcessDPIAware")
	procSetProcessDpiAwareness = resolveAPI("shcore.dll", "SetProcessDpiAwareness")
	procRtlGetVersion          = resolveAPI("ntdll.dll", "RtlGetVersion")

	procEnumWindows     = resolveAPI("user32.dll", "EnumWindows")
	procGetWindowRect   = resolveAPI("user32.dll", "GetWindowRect")
	procIsWindowVisible = resolveAPI("user32.dll", "IsWindowVisible")
	procPrintWindow     = resolveAPI("user32.dll", "PrintWindow")

	// 截图多级回退相关(适配服务会话/无桌面/多版本 Win)
	procGetDesktopWindow     = resolveAPI("user32.dll", "GetDesktopWindow")
	procOpenInputDesktop     = resolveAPI("user32.dll", "OpenInputDesktop")
	procSetThreadDesktop     = resolveAPI("user32.dll", "SetThreadDesktop")
	procCloseDesktop         = resolveAPI("user32.dll", "CloseDesktop")
	procCreateDC             = resolveAPI("gdi32.dll", "CreateDCW")
	procEnumDisplaySettingsW = resolveAPI("user32.dll", "EnumDisplaySettingsW")
)

const (
	SM_XVIRTUALSCREEN  = 76
	SM_YVIRTUALSCREEN  = 77
	SM_CXVIRTUALSCREEN = 78
	SM_CYVIRTUALSCREEN = 79

	PW_RENDERFULLCONTENT = 0x00000002 // PrintWindow 标志，Win8.1+ 渲染 DirectX 内容

	PROCESS_DPI_AWARE = 2 // PROCESS_PER_MONITOR_DPI_AWARE，Win8.1+

	SRCCOPY        = 0x00CC0020
	CAPTUREBLT     = 0x40000000 // 捕获被窗口遮挡的层叠窗口，避免截图不完整
	HORZRES        = 8
	VERTRES        = 10
	BI_RGB         = 0
	DIB_RGB_COLORS = 0

	// OpenInputDesktop/SetThreadDesktop 相关
	DESKTOP_READOBJECTS   = 0x0001 // 允许读取桌面对象
	DESKTOP_WRITEOBJECTS  = 0x0080 // 允许在桌面上写入对象
	DESKTOP_SWITCHDESKTOP = 0x0100 // 允许线程切换到此桌面

	// EnumDisplaySettings 枚举当前显示模式
	ENUM_CURRENT_SETTINGS = 0xFFFFFFFF
)

// BITMAPINFOHEADER structure
type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// osVersionInfoExW 对应 OSVERSIONINFOW
type osVersionInfoExW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
}

// devModeW 对应 DEVMODEW（精简到屏幕截图需要的字段即可）
// 用于 EnumDisplaySettingsW 在 GetSystemMetrics 无法取得尺寸时获取真实屏幕分辨率
type devModeW struct {
	DeviceName         [32]uint16
	SpecVersion        uint16
	DriverVersion      uint16
	Size               uint16
	DriverExtra        uint16
	Fields             uint32
	PositionX          int32
	PositionY          int32
	DisplayOrientation uint32
	DisplayFixedOutput uint32
	Color              uint16
	Duplex             uint16
	YResolution        uint16
	TTOption           uint16
	Collate            uint16
	FormName           [32]uint16
	LogPixels          uint16
	BitsPerPel         uint32
	PelsWidth          uint32
	PelsHeight         uint32
}

// getWindowsVersion 通过 RtlGetVersion 获取真实系统版本。
// 注意：GetVersionEx 在 Win8.1+ 会被 manifest 屏蔽而返回旧版本，故用 ntdll 直查。
func getWindowsVersion() (major, minor, build uint32) {
	vi := osVersionInfoExW{OSVersionInfoSize: uint32(unsafe.Sizeof(osVersionInfoExW{}))}
	ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	if ret != 0 {
		return 0, 0, 0
	}
	return vi.MajorVersion, vi.MinorVersion, vi.BuildNumber
}

// setProcessDPIAware 设置进程 DPI 感知，保证高 DPI(缩放>100%)下拿到物理像素、截全屏。
// 优先 SetProcessDpiAwareness(Win8.1+)，失败回退 SetProcessDPIAware(Vista+/Win7)。
func setProcessDPIAware() {
	if procSetProcessDpiAwareness != nil {
		procSetProcessDpiAwareness.Call(uintptr(PROCESS_DPI_AWARE)) // 忽略返回码：已设置过会返回 E_ACCESSDENIED
	}
	if procSetProcessDPIAware != nil {
		procSetProcessDPIAware.Call()
	}
}

// getVirtualScreenBounds 获取覆盖所有显示器的虚拟屏幕范围（物理像素，DPI aware 后）
// 多级回退：虚拟屏幕 → 主屏(SM_CXSCREEN/SM_CYSCREEN) → EnumDisplaySettingsW 显示设备
func getVirtualScreenBounds() (x, y, w, h int) {
	x = getSystemMetrics(SM_XVIRTUALSCREEN)
	y = getSystemMetrics(SM_YVIRTUALSCREEN)
	w = getSystemMetrics(SM_CXVIRTUALSCREEN)
	h = getSystemMetrics(SM_CYVIRTUALSCREEN)
	// 老系统或非交互会话下虚拟屏幕可能返回 0，回退主屏
	if w == 0 || h == 0 {
		x, y = 0, 0
		w = getSystemMetrics(0) // SM_CXSCREEN
		h = getSystemMetrics(1) // SM_CYSCREEN
	}
	// 某些精简系统/远程桌面会话 GetSystemMetrics 也可能返回 0，
	// 再回退到 EnumDisplaySettingsW 从显示设备读取主屏分辨率
	if w == 0 || h == 0 {
		dm := devModeW{Size: uint16(unsafe.Sizeof(devModeW{}))}
		ret, _, _ := procEnumDisplaySettingsW.Call(0, ENUM_CURRENT_SETTINGS, uintptr(unsafe.Pointer(&dm)))
		if ret != 0 && dm.PelsWidth > 0 && dm.PelsHeight > 0 {
			x, y = 0, 0
			w = int(dm.PelsWidth)
			h = int(dm.PelsHeight)
		}
	}
	return
}

// acquireScreenDC 获取屏幕 DC，多级回退，兼容不同 Windows 环境：
//  1. GetDC(NULL) 获取默认桌面 DC（常规交互会话）
//  2. GetDC(GetDesktopWindow()) 获取桌面窗口 DC（部分系统 GetDC(NULL) 失败）
//  3. OpenInputDesktop + SetThreadDesktop 切换到当前输入桌面后重试（服务/会话 0 场景）
//  4. CreateDC("DISPLAY") 直接创建设备上下文（无需窗口/桌面句柄）
func acquireScreenDC() (uintptr, func()) {
	// 1. 常规：GetDC(NULL)
	if hdc, _, _ := procGetDC.Call(0); hdc != 0 {
		return hdc, func() { procReleaseDC.Call(0, hdc) }
	}
	// 2. 桌面窗口 DC
	if hwndDesktop, _, _ := procGetDesktopWindow.Call(); hwndDesktop != 0 {
		if hdc, _, _ := procGetDC.Call(hwndDesktop); hdc != 0 {
			return hdc, func() { procReleaseDC.Call(hwndDesktop, hdc) }
		}
	}
	// 3. 切换输入桌面后重试（服务进程/无默认桌面时输入桌面通常仍存在）
	if hInput, _, _ := procOpenInputDesktop.Call(
		0, 0, DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS|DESKTOP_SWITCHDESKTOP); hInput != 0 {
		if ret, _, _ := procSetThreadDesktop.Call(hInput); ret != 0 {
			if hdc, _, _ := procGetDC.Call(0); hdc != 0 {
				procCloseDesktop.Call(hInput)
				return hdc, func() { procReleaseDC.Call(0, hdc) }
			}
		}
		procCloseDesktop.Call(hInput)
	}
	// 4. CreateDC("DISPLAY")：无需桌面句柄
	if name, err := syscall.UTF16PtrFromString("DISPLAY"); err == nil {
		if hdc, _, _ := procCreateDC.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0); hdc != 0 {
			return hdc, func() { procDeleteDC.Call(hdc) }
		}
	}
	return 0, nil
}

// captureScreenshot 使用 Windows GDI API 截取屏幕，返回原始 BGRA 像素数据。
// 自适应多系统版本：
//   - Win7/Win2008：GDI 主方案 + PrintWindow 兜底
//   - Win8.1+/Win10/Win11：DPI 感知 + 虚拟屏幕(多显示器) + GDI + PrintWindow(DX 内容) 双方案
//   - 高 DPI：设置 DPI aware，物理像素全屏
//   - 非交互会话/服务/无默认桌面：GetDC 多级回退 + 屏幕尺寸多级回退
// 老系统兼容加固：GetDIBits 偶发失败/空帧时自动重试，避免 Win2008 等旧系统
// 一次失败就整体报错。
func captureScreenshot() ([]byte, int, int, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(250 * time.Millisecond) // 老系统 GDI 偶发瞬时空帧，等待后重试
		}
		px, stride, height, err := captureScreenshotOnce()
		if err == nil {
			return px, stride, height, nil
		}
		lastErr = err
	}
	return nil, 0, 0, lastErr
}

func captureScreenshotOnce() ([]byte, int, int, error) {
	setProcessDPIAware()
	major, _, _ := getWindowsVersion()

	// 获取屏幕 DC（多级回退）
	hdcScreen, releaseDC := acquireScreenDC()
	if hdcScreen == 0 {
		return nil, 0, 0, fmt.Errorf("获取屏幕 DC 失败 (err=%d)，可能运行在无桌面的非交互会话(服务/会话0)，请以交互用户身份运行", getLastError())
	}
	defer releaseDC()

	// 虚拟屏幕边界（覆盖多显示器），优先物理像素分辨率
	x, y, width, height := getVirtualScreenBounds()
	if width == 0 || height == 0 {
		return nil, 0, 0, fmt.Errorf("无法获取屏幕尺寸 (err=%d)：目标可能无显示设备（Headless 服务器）或运行在非交互会话，请确认存在活动桌面", getLastError())
	}

	// 创建兼容 DC
	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleDC 失败 (err=%d)", getLastError())
	}
	defer procDeleteDC.Call(hdcMem)

	// 创建兼容位图
	hbmp, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, uintptr(width), uintptr(height))
	if hbmp == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleBitmap 失败 (err=%d)", getLastError())
	}
	defer procDeleteObject.Call(hbmp)

	// 将位图选入 DC
	oldBmp, _, _ := procSelectObject.Call(hdcMem, hbmp)
	defer procSelectObject.Call(hdcMem, oldBmp)

	// 主方案：GDI 拷贝屏幕到位图（CAPTUREBLT 捕获被窗口遮挡内容，坐标取虚拟屏幕原点）
	bitBltOK := true
	ret, _, _ := procBitBlt.Call(hdcMem, 0, 0, uintptr(width), uintptr(height),
		hdcScreen, uintptr(x), uintptr(y), SRCCOPY|CAPTUREBLT)
	if ret == 0 {
		bitBltOK = false
	}

	// 读取像素（兼容 top-down / bottom-up，含 Win2008 老显卡）
	pixelData, stride, err := getDIBitsData(hdcMem, hbmp, width, height)
	if err != nil {
		return nil, 0, 0, err
	}

	// 检测结果是否异常（全黑/空内容）：锁屏、安全桌面、或硬件加速窗口未被 GDI 捕获
	blank := isMostlyBlack(pixelData, stride, height)

	// 兜底方案：PrintWindow 逐窗口合成（Win8.1+ 可捕获 DirectX 硬件加速内容）
	if !bitBltOK || blank {
		if ok, _ := printWindowComposite(hdcScreen, hdcMem, x, y, width, height); ok {
			// 重新读取合成后的像素
			if pd, s, e := getDIBitsData(hdcMem, hbmp, width, height); e == nil {
				pixelData, stride = pd, s
				blank = isMostlyBlack(pd, s, height)
			}
		}
	}

	if blank {
		// 老系统（Win2008/7）无登录桌面/服务会话时同样可能全黑，给出针对性提示
		if major >= 10 {
			return nil, 0, 0, fmt.Errorf("捕获图像为纯黑/空白，目标可能处于锁屏或安全桌面(Windows %d)，请先解锁桌面", major)
		}
		return nil, 0, 0, fmt.Errorf("捕获图像为纯黑/空白：目标可能处于锁屏、无交互桌面（服务会话/Headless 服务器）或远程会话已断开，请确认存在活动桌面后重试")
	}

	return pixelData, stride, height, nil
}

// getDIBitsData 从位图读取 BGRA 像素。先尝试 top-down DIB（负 biHeight），
// 失败则回退 bottom-up（正 biHeight + 行翻转）——兼容 Win2008 等老系统/虚拟显卡驱动。
func getDIBitsData(hdcMem, hbmp uintptr, width, height int) ([]byte, int, error) {
	stride := ((width*32 + 31) / 32) * 4
	pixelData := make([]byte, stride*height)

	bi := bitmapInfoHeader{
		Size:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:       int32(width),
		Height:      -int32(height), // top-down
		Planes:      1,
		BitCount:    32,
		Compression: BI_RGB,
	}

	ret, _, _ := procGetDIBits.Call(
		hdcMem,
		hbmp,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&pixelData[0])),
		uintptr(unsafe.Pointer(&bi)),
		DIB_RGB_COLORS,
	)
	if ret == 0 {
		// bottom-up 重试
		bi.Height = int32(height)
		ret, _, _ = procGetDIBits.Call(
			hdcMem,
			hbmp,
			0,
			uintptr(height),
			uintptr(unsafe.Pointer(&pixelData[0])),
			uintptr(unsafe.Pointer(&bi)),
			DIB_RGB_COLORS,
		)
		if ret == 0 {
			return nil, 0, fmt.Errorf("GetDIBits 失败 (err=%d)", getLastError())
		}
		flipPixelsVertically(pixelData, stride, height)
	}
	return pixelData, stride, nil
}

// isMostlyBlack 采样判断图像是否基本为黑（采样 1/8 点）
func isMostlyBlack(pixelData []byte, stride, height int) bool {
	if len(pixelData) == 0 {
		return true
	}
	width := stride / 4
	if width == 0 || height == 0 {
		return true
	}
	black := 0
	total := 0
	for y := 0; y < height; y += 8 {
		for x := 0; x < width; x += 8 {
			off := y*stride + x*4
			if off+2 >= len(pixelData) {
				continue
			}
			if pixelData[off] < 10 && pixelData[off+1] < 10 && pixelData[off+2] < 10 {
				black++
			}
			total++
		}
	}
	return total > 0 && black*100/total > 90
}

// printWindowEnumCtx 传递给 EnumWindows 回调的上下文
type printWindowEnumCtx struct {
	hdcScreen uintptr
	hdcMem    uintptr
	screenX   int
	screenY   int
	screenW   int
	screenH   int
	covered   int
}

// printWindowComposite 枚举所有可见顶层窗口，用 PrintWindow 逐一绘制到主位图，
// 解决硬件加速(DirectX/浏览器视频)窗口在 GDI BitBlt 下黑屏的问题。
// 兼容性：PrintWindow 自 Win2000 即存在；PW_RENDERFULLCONTENT 标志仅 Win8.1+，
// 老系统传 0 亦可用（回退捕获普通窗口内容）。
func printWindowComposite(hdcScreen, hdcMem uintptr, sx, sy, sw, sh int) (bool, error) {
	ctx := printWindowEnumCtx{hdcScreen: hdcScreen, hdcMem: hdcMem, screenX: sx, screenY: sy, screenW: sw, screenH: sh}
	procEnumWindows.Call(syscall.NewCallback(printWindowEnumProc), uintptr(unsafe.Pointer(&ctx)))
	return ctx.covered > 0, nil
}

// printWindowEnumProc EnumWindows 回调：对每个可见窗口执行 PrintWindow
func printWindowEnumProc(hwnd uintptr, lparam uintptr) uintptr {
	ctx := (*printWindowEnumCtx)(unsafe.Pointer(lparam))
	// 跳过不可见窗口
	if ret, _, _ := procIsWindowVisible.Call(hwnd); ret == 0 {
		return 1
	}

	// 窗口矩形
	var r struct{ Left, Top, Right, Bottom int32 }
	if ret, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r))); ret == 0 {
		return 1
	}
	w := int(r.Right - r.Left)
	h := int(r.Bottom - r.Top)
	if w <= 0 || h <= 0 || w > 8192 || h > 8192 {
		return 1
	}
	// 与虚拟屏幕求交
	// 注意：不能用内置 max/min（Go 1.21+ 才有），植入端用 go1.20 编译以兼容 Win7/2008
	ix0 := imax(ctx.screenX, int(r.Left))
	iy0 := imax(ctx.screenY, int(r.Top))
	ix1 := imin(ctx.screenX+ctx.screenW, int(r.Right))
	iy1 := imin(ctx.screenY+ctx.screenH, int(r.Bottom))
	if ix1 <= ix0 || iy1 <= iy0 {
		return 1
	}

	// 窗口 DC + 位图
	hdcWin, _, _ := procCreateCompatibleDC.Call(ctx.hdcScreen)
	if hdcWin == 0 {
		return 1
	}
	defer procDeleteDC.Call(hdcWin)
	hbmpWin, _, _ := procCreateCompatibleBitmap.Call(ctx.hdcScreen, uintptr(w), uintptr(h))
	if hbmpWin == 0 {
		return 1
	}
	defer procDeleteObject.Call(hbmpWin)
	oldBmp, _, _ := procSelectObject.Call(hdcWin, hbmpWin)
	defer procSelectObject.Call(hdcWin, oldBmp)

	// 先填充透明背景（黑色），再 PrintWindow
	procBitBlt.Call(hdcWin, 0, 0, uintptr(w), uintptr(h), 0, 0, 0, 0x00000042 /*BLACKNESS*/)

	// 优先 PW_RENDERFULLCONTENT(Win8.1+ 渲染 DX 内容)，失败回退 0
	flag := PW_RENDERFULLCONTENT
	if ret, _, _ := procPrintWindow.Call(hwnd, hdcWin, uintptr(flag)); ret == 0 {
		flag = 0
		if ret, _, _ = procPrintWindow.Call(hwnd, hdcWin, uintptr(flag)); ret == 0 {
			return 1
		}
	}

	// 将窗口位图拷贝到主位图的对应位置（相对虚拟屏幕原点）
	dstX := ix0 - ctx.screenX
	dstY := iy0 - ctx.screenY
	procBitBlt.Call(ctx.hdcMem, uintptr(dstX), uintptr(dstY), uintptr(ix1-ix0), uintptr(iy1-iy0),
		hdcWin, uintptr(ix0-int(r.Left)), uintptr(iy0-int(r.Top)), SRCCOPY)
	ctx.covered++
	return 1
}

// imax/imin：自实现取整型最大/最小值。
// 注意：植入端为了兼容 Win7/2008 使用 go1.20 工具链编译，而内置 max/min 是 Go 1.21+
// 才引入的，因此这里用自定义实现（名称避开内置函数以避免未来工具链冲突）。
func imax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getSystemMetrics 获取系统指标
func getSystemMetrics(index int) int {
	ret, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(ret)
}

// getDeviceCaps 获取设备能力值（物理像素）
func getDeviceCaps(hdc uintptr, index int) int {
	ret, _, _ := procGetDeviceCaps.Call(hdc, uintptr(index))
	return int(ret)
}

// getLastError 获取最近一次系统调用的错误码
func getLastError() uint32 {
	if err := syscall.GetLastError(); err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			return uint32(errno)
		}
	}
	return 0
}

// flipPixelsVertically 将 bottom-up DIB 的像素垂直翻转（按行），与 top-down 输出对齐
func flipPixelsVertically(pixelData []byte, stride, height int) {
	for y := 0; y < height/2; y++ {
		top := y * stride
		bot := (height - 1 - y) * stride
		for i := 0; i < stride; i++ {
			pixelData[top+i], pixelData[bot+i] = pixelData[bot+i], pixelData[top+i]
		}
	}
}

// bgraToRGBA 将 BGRA 像素数据转换为 image.RGBA (逐行处理, 复用缓冲)
func bgraToRGBA(pixelData []byte, stride int, height int) *image.RGBA {
	width := stride / 4 // 32-bit = 4 bytes per pixel

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		srcOffset := y * stride
		dstOffset := y * img.Stride
		for x := 0; x < width; x++ {
			src := srcOffset + x*4
			dst := dstOffset + x*4
			img.Pix[dst+0] = pixelData[src+2] // R
			img.Pix[dst+1] = pixelData[src+1] // G
			img.Pix[dst+2] = pixelData[src+0] // B
			img.Pix[dst+3] = pixelData[src+3] // A
		}
	}
	return img
}

// encodeToPNG 将 BGRA 像素数据编码为 PNG (使用 BestSpeed 加快编码速度)
func encodeToPNG(pixelData []byte, stride int, height int) ([]byte, error) {
	img := bgraToRGBA(pixelData, stride, height)

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("PNG 编码失败: %v", err)
	}
	return buf.Bytes(), nil
}

// encodeToJPEG 将 BGRA 像素数据编码为 JPEG, 用于大尺寸截图的体积/速度优化
func encodeToJPEG(pixelData []byte, stride int, height int, quality int) ([]byte, error) {
	img := bgraToRGBA(pixelData, stride, height)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, fmt.Errorf("JPEG 编码失败: %v", err)
	}
	return buf.Bytes(), nil
}

// screenshotResult 构造截图结果的 JSON 字符串
func screenshotResult(base64data string, format string, width, height int) string {
	result := map[string]interface{}{
		"image":  base64data,
		"format": format,
		"width":  width,
		"height": height,
	}
	data, _ := json.Marshal(result)
	return string(data)
}

// handleScreenshot 入口函数：截取屏幕并返回 JSON 结果。
// 大尺寸截图自动改用 JPEG 以显著减小体积、加快回传。
func handleScreenshot(taskData string) (string, int32, string) {
	pixelData, stride, height, err := captureScreenshot()
	if err != nil {
		return "", -1, fmt.Sprintf("截图失败: %v", err)
	}

	width := stride / 4
	format := "png"
	imgData, err := encodeToPNG(pixelData, stride, height)
	if err != nil {
		return "", -1, fmt.Sprintf("PNG 编码失败: %v", err)
	}

	// 大图(>2MB PNG)改用 JPEG, 编码更快且体积更小
	if len(imgData) > 2*1024*1024 {
		if jpgData, jerr := encodeToJPEG(pixelData, stride, height, 85); jerr == nil && len(jpgData) < len(imgData) {
			imgData = jpgData
			format = "jpeg"
		}
	}

	b64 := base64.StdEncoding.EncodeToString(imgData)
	output := screenshotResult(b64, format, width, height)

	return output, 0, ""
}
