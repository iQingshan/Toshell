package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"toshell/internal/server/ai"
	"toshell/internal/server/database"
	"toshell/internal/server/logging"
)

// ─── 副驾驶剧本化端点 ─────────────────────────────────────────────
// GET  /api/v1/copilot/playbooks        列出内置剧本
// POST /api/v1/copilot/playbook/run     执行剧本（异步，返回 runID）
// GET  /api/v1/copilot/playbook/runs    列出历史运行
// GET  /api/v1/copilot/playbook/runs/{id} 查询单次运行进度

func (s *Server) listPlaybooksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pbs := []ai.Playbook{}
	if s.playbookR != nil {
		pbs = s.playbookR.ListPlaybooks() // 内置任务流 + 运行期注册
	}
	// 任务流/任务模板与 Templates 页同源：内存 + DB，去重合并
	seen := map[string]bool{}
	for _, p := range pbs {
		seen[p.ID] = true
	}
	appendTpl := func(t *TaskTemplate) {
		if t == nil || seen[t.ID] {
			return
		}
		seen[t.ID] = true
		pbs = append(pbs, *templateToPlaybook(t))
	}
	tplStore.mu.RLock()
	for _, t := range tplStore.templates {
		appendTpl(t)
	}
	tplStore.mu.RUnlock()
	if db := database.Get(); db != nil {
		if cts, err := db.ListCustomTemplates(); err == nil {
			for _, ct := range cts {
				if seen[ct.ID] {
					continue
				}
				var tasks []TemplateTask
				if json.Unmarshal([]byte(ct.TasksJSON), &tasks) != nil {
					continue
				}
				appendTpl(&TaskTemplate{
					ID: ct.ID, Name: ct.Name, Description: ct.Description,
					Category: ct.Category, Tasks: tasks, CreatedAt: ct.CreatedAt,
				})
			}
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"playbooks": pbs,
		"count":     len(pbs),
	})
}

func (s *Server) runPlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.playbookR == nil {
		http.Error(w, `{"error":"playbook runner not available"}`, http.StatusServiceUnavailable)
		return
	}
	var req struct {
		PlaybookID string `json:"playbook_id"`
		SessionID  string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.PlaybookID == "" || req.SessionID == "" {
		http.Error(w, `{"error":"playbook_id and session_id required"}`, http.StatusBadRequest)
		return
	}
	run, err := s.playbookR.Run(req.PlaybookID, req.SessionID)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id":     run.ID,
		"playbook":   run.Playbook,
		"session_id": run.SessionID,
		"status":     run.Status,
	})
}

func (s *Server) listPlaybookRunsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.playbookR == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"runs": []interface{}{}, "count": 0})
		return
	}
	runs := s.playbookR.ListRuns(50)
	json.NewEncoder(w).Encode(map[string]interface{}{"runs": runs, "count": len(runs)})
}

func (s *Server) getPlaybookRunHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]
	if s.playbookR == nil {
		http.Error(w, `{"error":"playbook runner not available"}`, http.StatusServiceUnavailable)
		return
	}
	if run := s.playbookR.GetRun(id); run != nil {
		json.NewEncoder(w).Encode(run)
		return
	}
	http.Error(w, `{"error":"run not found"}`, http.StatusNotFound)
}

// analyzePlaybook 剧本完成后的 AI 智能总结：把各步结果喂给 LLM，产出
// 中文「结果综述 + 下一步建议」。副驾驶未配置或调用失败返回空串（前端
// 用步骤结果摘要兜底）。作为 PlaybookRunner 的 analyzer 回调被调用。
func (s *Server) analyzePlaybook(sessionID string, results []ai.StepResult) string {
	if s.copilot == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("目标会话: " + sessionID + "\n\n本次剧本执行已结束，各步骤结果如下：\n\n")
	success := 0
	for _, r := range results {
		icon := "✅"
		switch r.Status {
		case "failed":
			icon = "❌"
		case "skipped":
			icon = "⏭️"
		case "completed":
			success++
		}
		b.WriteString(icon + " 步骤「" + r.Name + "」(" + r.Tool + ") → " + r.Status)
		if r.Error != "" {
			b.WriteString("；错误: " + r.Error)
		}
		b.WriteString("\n")
		if r.Output != "" {
			b.WriteString("    结果: " + truncatePlaybookString(r.Output, 300) + "\n")
		}
	}
	b.WriteString("\n成功 " + strconv.Itoa(success) + " / 共 " + strconv.Itoa(len(results)) + " 步。")

	system := "你是 ToShell C2 平台的 AI 副驾驶，也是一名资深红队/渗透测试专家。" +
		"用户刚通过「剧本化执行」对一个目标会话完成了一次侦察/攻击链路。请基于给定的各步骤执行结果，用简洁中文输出：\n" +
		"1. 【结果综述】这次剧本完成了哪些动作、拿到了哪些关键信息、有哪些步骤失败或异常。\n" +
		"2. 【攻击判断】根据拿到的主机/用户/域/网络/杀软/凭据信息，判断目标画像与所处阶段（如：是否域环境、有无域控/域管线索、杀软与 EDR 强度、已获取的可利用凭据、主机在攻击路径中的角色）。\n" +
		"3. 【下一步建议】给出具体可执行的下一步操作，按优先级排序并覆盖典型攻击路径：横向移动、权限维持、提权、凭据利用、域渗透/内网探测、规避杀软等。每条要给出本平台可用的工具方向（如 credentials/process_list/process_kill/screenshot/session_list 等工具名或对应命令思路）。\n" +
		"直接输出内容即可，不要调用任何工具，不要输出无关对话。"

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	summary, err := s.copilot.Summarize(ctx, system, b.String())
	if err != nil {
		logging.Warn("ai", "playbook analysis failed: %v", err)
		return ""
	}
	return summary
}

func truncatePlaybookString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
