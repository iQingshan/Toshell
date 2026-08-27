package api

import (
	"encoding/json"
	"net/http"

	"toshell/internal/server/intel"
)

// ─── 情报库接口 ─────────────────────────────────────────────────────
// GET /api/v1/intel            → 全部情报
// GET /api/v1/intel?kind=ip    → 按类型过滤

func (s *Server) listIntelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	kind := r.URL.Query().Get("kind")
	store := intel.Get()
	if kind != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kind":  kind,
			"items": store.ListByKind(kind),
			"count": len(store.ListByKind(kind)),
		})
		return
	}
	items := store.List()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": items,
		"count": len(items),
	})
}
