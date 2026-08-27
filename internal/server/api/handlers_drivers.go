package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"toshell/internal/server/drivers"
)

// listDriversHandler 返回内置 BYOVD 驱动目录（供前端"一键加载内置驱动"）。
func (s *Server) listDriversHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"drivers": drivers.List(),
		"count":   len(drivers.Catalog),
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
