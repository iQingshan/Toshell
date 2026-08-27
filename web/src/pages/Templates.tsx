import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Search, Play, Loader2, CheckCircle2, XCircle,
  Clock, AlertTriangle, Layers, Server,
  FileSearch, ShieldCheck, ArrowRightLeft, Download,
  Zap, X, Plus, Eye, Copy, Pencil,
} from 'lucide-react'
import { templateApi, sessionApi } from '../api'
import type { Session } from '../types'

// ─── Types ────────────────────────────────────────────────────────────────────

interface TemplateTask {
  task_type: string
  data: string
  timeout: number
  wait: boolean
}

interface TaskTemplate {
  id: string
  name: string
  description: string
  category: string
  tasks: TemplateTask[]
  created_at: number
}

interface WorkflowTaskResult {
  task_type: string
  task_id: number
  status: string
  output?: string
}

interface WorkflowExecution {
  id: string
  session_id: string
  template: string
  status: string
  progress: number
  total: number
  results: WorkflowTaskResult[]
  created_at: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const CATEGORY_LABELS: Record<string, string> = {
  recon: '侦查',
  persistence: '持久化',
  lateral: '横向移动',
  exfil: '数据窃取',
  quick: '快捷操作',
}

const CATEGORY_ORDER: string[] = ['quick', 'recon', 'persistence', 'lateral', 'exfil']

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  recon: <FileSearch size={16} />,
  persistence: <ShieldCheck size={16} />,
  lateral: <ArrowRightLeft size={16} />,
  exfil: <Download size={16} />,
  quick: <Zap size={16} />,
  custom: <Layers size={16} />,
}

const STATUS_ICONS: Record<string, React.ReactNode> = {
  pending: <Clock size={14} />,
  running: <Loader2 size={14} className="animate-spin" />,
  completed: <CheckCircle2 size={14} />,
  failed: <XCircle size={14} />,
  timeout: <AlertTriangle size={14} />,
}

// ─── Component ────────────────────────────────────────────────────────────────

export function Templates() {
  const [templates, setTemplates] = useState<TaskTemplate[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [loading, setLoading] = useState(true)
  const [showSessionPicker, setShowSessionPicker] = useState(false)
  const [selectedTemplate, setSelectedTemplate] = useState<TaskTemplate | null>(null)
  const [sessionSearch, setSessionSearch] = useState('')
  const [activeWorkflow, setActiveWorkflow] = useState<WorkflowExecution | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Custom template form states
  const [showCustomForm, setShowCustomForm] = useState(false)
  const [editingTemplate, setEditingTemplate] = useState<TaskTemplate | null>(null)
  const [customName, setCustomName] = useState('')
  const [customDesc, setCustomDesc] = useState('')
  const [customCategory, setCustomCategory] = useState('recon')
  // Multi-task support: list of tasks in the workflow
  const [customTasks, setCustomTasks] = useState<TemplateTask[]>([
    { task_type: 'shell', data: '{"command":"whoami"}', timeout: 60, wait: true },
  ])

  // View full output modal
  const [viewOutput, setViewOutput] = useState<string | null>(null)
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  const copyToClipboard = async (text: string, idx: number) => {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    setCopiedIndex(idx)
    setTimeout(() => setCopiedIndex(null), 1500)
  }

  const fetchTemplates = useCallback(async () => {
    try {
      const res = await templateApi.list()
      setTemplates(res.data?.templates || [])
    } catch (err) {
      console.error('Failed to fetch templates:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchSessions = useCallback(async () => {
    try {
      const res = await sessionApi.list()
      setSessions(res.data?.sessions || [])
    } catch (err) {
      console.error('Failed to fetch sessions:', err)
    }
  }, [])

  useEffect(() => {
    fetchTemplates()
  }, [fetchTemplates])

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const startPolling = useCallback((workflowId: string) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const res = await templateApi.getWorkflow(workflowId)
        const wf = res.data as WorkflowExecution
        setActiveWorkflow(wf)
        if (wf.status === 'completed' || wf.status === 'failed') {
          if (pollRef.current) clearInterval(pollRef.current)
          pollRef.current = null
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current)
        pollRef.current = null
      }
    }, 1000)
  }, [])

  const handleExecuteClick = (tmpl: TaskTemplate) => {
    setSelectedTemplate(tmpl)
    setShowSessionPicker(true)
    fetchSessions()
  }

  const handleSessionSelect = async (session: Session) => {
    if (!selectedTemplate) return
    setShowSessionPicker(false)

    try {
      const res = await templateApi.execute(session.id, selectedTemplate.id)
      const workflowId = res.data?.workflow_id
      if (workflowId) {
        setActiveWorkflow({
          id: workflowId,
          session_id: session.id,
          template: selectedTemplate.name,
          status: 'running',
          progress: 0,
          total: selectedTemplate.tasks.length,
          results: [],
          created_at: Date.now(),
        })
        startPolling(workflowId)
      }
    } catch (err) {
      console.error('Failed to execute workflow:', err)
    }
  }

  const handleEditClick = (tmpl: TaskTemplate) => {
    setEditingTemplate(tmpl)
    setCustomName(tmpl.name)
    setCustomDesc(tmpl.description || '')
    setCustomCategory(tmpl.category)
    setCustomTasks(tmpl.tasks.map(t => ({ ...t })))
    setShowCustomForm(true)
  }

  const handleCreateCustom = async () => {
    if (!customName.trim()) return
    if (customTasks.length === 0) return

    const payload = {
      name: customName.trim(),
      description: customDesc.trim() || '自定义任务模板',
      category: customCategory,
      tasks: customTasks.map((t) => ({ ...t })),
    }

    try {
      if (editingTemplate) {
        await templateApi.update(editingTemplate.id, payload)
      } else {
        await templateApi.create(payload)
      }
      await fetchTemplates()
    } catch (err) {
      console.error('Failed to save template:', err)
      if (!editingTemplate) {
        // Fallback: add locally only for new templates
        const newTemplate: TaskTemplate = {
          id: `custom-${Date.now()}`,
          ...payload,
          created_at: Date.now(),
        }
        setTemplates((prev) => [...prev, newTemplate])
      }
    }

    setShowCustomForm(false)
    setEditingTemplate(null)
    setCustomName('')
    setCustomDesc('')
    setCustomCategory('recon')
    setCustomTasks([{ task_type: 'shell', data: '{"command":"whoami"}', timeout: 60, wait: true }])
  }

  const addCustomTask = () => {
    setCustomTasks((prev) => [...prev, { task_type: 'shell', data: '{}', timeout: 60, wait: true }])
  }

  const removeCustomTask = (index: number) => {
    if (customTasks.length <= 1) return
    setCustomTasks((prev) => prev.filter((_, i) => i !== index))
  }

  const updateCustomTask = (index: number, field: keyof TemplateTask, value: string | number | boolean) => {
    setCustomTasks((prev) => prev.map((t, i) => (i === index ? { ...t, [field]: value } : t)))
  }

  const filteredSessions = sessions.filter((s) => {
    if (!sessionSearch) return true
    const q = sessionSearch.toLowerCase()
    return (
      s.id.toLowerCase().includes(q) ||
      s.hostname.toLowerCase().includes(q) ||
      s.username.toLowerCase().includes(q)
    )
  })

  // Group templates by category, sorted by CATEGORY_ORDER
  const grouped = templates.reduce<Record<string, TaskTemplate[]>>((acc, t) => {
    const cat = t.category || 'other'
    if (!acc[cat]) acc[cat] = []
    acc[cat].push(t)
    return acc
  }, {})
  const sortedCategories = Object.keys(grouped).sort((a, b) => {
    const ia = CATEGORY_ORDER.indexOf(a), ib = CATEGORY_ORDER.indexOf(b)
    if (ia === -1 && ib === -1) return a.localeCompare(b)
    if (ia === -1) return 1
    if (ib === -1) return -1
    return ia - ib
  })

  if (loading) {
    return (
      <div className="templates-page">
        <div className="templates-loading">
          <Loader2 size={32} className="animate-spin" />
          <p>加载模板...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="templates-page">
      <div className="templates-header">
        <div className="templates-title">
          <Layers size={24} />
          <h1>任务模板</h1>
          <span className="templates-count">{templates.length} 个模板</span>
        </div>
      </div>

      {/* Workflow Progress */}
      {activeWorkflow && (
        <div className={`workflow-panel ${activeWorkflow.status}`}>
          <div className="workflow-panel-header">
            <div className="workflow-panel-title">
              <span className={`workflow-status-dot ${activeWorkflow.status}`} />
              <span>{activeWorkflow.template}</span>
            </div>
            <button
              className="workflow-close"
              onClick={() => {
                if (pollRef.current) clearInterval(pollRef.current)
                pollRef.current = null
                setActiveWorkflow(null)
              }}
            >
              <X size={16} />
            </button>
          </div>
          <div className="workflow-progress-bar">
            <div
              className={`workflow-progress-fill ${activeWorkflow.status}`}
              style={{
                width: activeWorkflow.total > 0
                  ? `${(activeWorkflow.progress / activeWorkflow.total) * 100}%`
                  : '0%',
              }}
            />
          </div>
          <div className="workflow-progress-text">
            {activeWorkflow.progress} / {activeWorkflow.total} 已完成
            <span className={`workflow-status-tag ${activeWorkflow.status}`}>
              {activeWorkflow.status === 'running'
                ? '运行中'
                : activeWorkflow.status === 'completed'
                ? '已完成'
                : '失败'}
            </span>
          </div>
          {activeWorkflow.results.length > 0 && (
            <div className="workflow-results">
              {activeWorkflow.results.map((r, i) => (
                <div key={i} className={`workflow-task-result ${r.status}`}>
                  <span className="workflow-task-icon">
                    {STATUS_ICONS[r.status] || STATUS_ICONS.pending}
                  </span>
                  <span className="workflow-task-type">{r.task_type}</span>
                  <span className="workflow-task-status-text">{r.status}</span>
                  {r.output && (
                    <div className="workflow-task-output-wrapper">
                      <pre className="workflow-task-output">{r.output.length > 200 ? r.output.substring(0, 200) + '...' : r.output}</pre>
                      <div className="workflow-task-output-actions">
                        <button className="btn-copy" onClick={() => copyToClipboard(r.output || '', i)}>
                          <Copy size={12} /> {copiedIndex === i ? '已复制' : '复制'}
                        </button>
                        {r.output.length > 200 && (
                          <button className="btn-view-all" onClick={() => setViewOutput(r.output || '')}>
                            <Eye size={12} /> 查看全部 ({r.output.length} 字符)
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Template List */}
      {sortedCategories.map((category) => {
        const tmpls = grouped[category]
        return (
        <div key={category} className="template-category-section">
          <div className="template-category-header">
            <span className={`template-category-label ${category}`}>
              {CATEGORY_ICONS[category] || <Layers size={16} />}
              {CATEGORY_LABELS[category] || category}
            </span>
            <span className="template-category-count">{tmpls.length}</span>
          </div>
          <div className="template-grid">
            {tmpls.map((tmpl) => (
              <div key={tmpl.id} className="template-card">
                <div className="template-card-header">
                  <h3 className="template-card-name">{tmpl.name}</h3>
                  <span className={`template-category ${tmpl.category}`}>
                    {CATEGORY_LABELS[tmpl.category] || tmpl.category}
                  </span>
                </div>
                <p className="template-card-desc">{tmpl.description}</p>
                <div className="template-card-meta">
                  <span className="template-task-count">
                    <Server size={14} />
                    {tmpl.tasks.length} 个任务
                  </span>
                </div>
                <div className="template-card-actions">
                  <button
                    className="template-execute-btn"
                    onClick={() => handleExecuteClick(tmpl)}
                    disabled={activeWorkflow?.status === 'running'}
                  >
                    <Play size={14} />
                    执行
                  </button>
                  <button
                    className="template-edit-btn"
                    onClick={() => handleEditClick(tmpl)}
                    title="编辑此模板"
                  >
                    <Pencil size={14} />
                  </button>
                  {tmpl.id.startsWith('custom-') && (
                    <button
                      className="template-delete-btn"
                      onClick={async () => {
                        if (!confirm(`确定删除模板 "${tmpl.name}"？`)) return
                        try {
                          await templateApi.delete(tmpl.id)
                          await fetchTemplates()
                        } catch (err) {
                          console.error('Failed to delete template:', err)
                          setTemplates((prev) => prev.filter((t) => t.id !== tmpl.id))
                        }
                      }}
                      title="删除此模板"
                    >
                      <X size={14} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
        )
      })}

      {/* New Template Button */}
      <div className="template-add-section">
        <button className="template-add-btn" onClick={() => setShowCustomForm(true)}>
          <Plus size={16} />
          创建自定义模板
        </button>
      </div>

      {/* Session Picker Modal */}
      {showSessionPicker && (
        <div className="modal-overlay" onClick={() => setShowSessionPicker(false)}>
          <div className="modal session-picker-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>
                选择目标会话 — {selectedTemplate?.name}
              </h3>
              <button className="modal-close" onClick={() => setShowSessionPicker(false)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body">
              <div className="session-picker-search">
                <Search size={16} />
                <input
                  type="text"
                  placeholder="搜索会话 ID、主机名或用户名..."
                  value={sessionSearch}
                  onChange={(e) => setSessionSearch(e.target.value)}
                  autoFocus
                />
              </div>
              <div className="session-picker-list">
                {filteredSessions.length === 0 ? (
                  <div className="session-picker-empty">
                    <Server size={24} />
                    <p>没有找到匹配的会话</p>
                  </div>
                ) : (
                  filteredSessions.map((s) => (
                    <button
                      key={s.id}
                      className="session-picker-item"
                      onClick={() => handleSessionSelect(s)}
                    >
                      <div className="session-picker-item-info">
                        <span className="session-picker-item-id">{s.id}</span>
                        <span className="session-picker-item-host">
                          {s.hostname} / {s.username}
                        </span>
                      </div>
                      <span className={`session-picker-item-status ${s.status}`}>
                        {s.status === 'active' ? '在线' : '离线'}
                      </span>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Custom Template Create/Edit Modal */}
      {showCustomForm && (
        <div className="modal-overlay" onClick={() => { setShowCustomForm(false); setEditingTemplate(null) }}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640 }}>
            <div className="modal-header">
              <h3>{editingTemplate ? '编辑任务模板' : '创建自定义任务模板'}</h3>
              <button className="modal-close" onClick={() => { setShowCustomForm(false); setEditingTemplate(null) }}><X size={18} /></button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>模板名称 *</label>
                <input type="text" value={customName} onChange={(e) => setCustomName(e.target.value)} placeholder="例如：执行特定命令" />
              </div>
              <div className="form-group">
                <label>描述</label>
                <input type="text" value={customDesc} onChange={(e) => setCustomDesc(e.target.value)} placeholder="描述这个模板的用途" />
              </div>
              <div className="form-group">
                <label>分类</label>
                <select value={customCategory} onChange={(e) => setCustomCategory(e.target.value)}>
                  {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>{v}</option>
                  ))}
                </select>
              </div>

              {/* Workflow Tasks */}
              <div className="form-group">
                <div className="custom-tasks-header">
                  <label>任务列表 ({customTasks.length})</label>
                  <button type="button" className="btn-add-task" onClick={addCustomTask}>
                    <Plus size={14} /> 添加任务
                  </button>
                </div>
                <div className="custom-tasks-list">
                  {customTasks.map((t, i) => (
                    <div key={i} className="custom-task-item">
                      <span className="custom-task-index">#{i + 1}</span>
                      <div className="custom-task-fields">
                        <select
                          className="custom-task-select"
                          value={t.task_type}
                          onChange={(e) => updateCustomTask(i, 'task_type', e.target.value)}
                        >
                          <option value="shell">Shell 命令</option>
                          <option value="sysinfo">系统信息</option>
                          <option value="process_list">进程列表</option>
                          <option value="service_list">服务列表</option>
                          <option value="netstat">网络连接</option>
                          <option value="screenshot">截图</option>
                          <option value="file_list">文件列表</option>
                          <option value="credentials">凭证收集</option>
                          <option value="av_detect">杀软识别</option>
                          <option value="bof_load">BOF 加载</option>
                        </select>
                        <input
                          type="text"
                          className="custom-task-data"
                          value={t.data}
                          onChange={(e) => updateCustomTask(i, 'data', e.target.value)}
                          placeholder='参数 JSON，如 {"command":"whoami"}'
                        />
                        <input
                          type="number"
                          className="custom-task-timeout"
                          value={t.timeout}
                          onChange={(e) => updateCustomTask(i, 'timeout', Number(e.target.value))}
                          min={10}
                          max={600}
                          title="超时秒数"
                        />
                      </div>
                      {customTasks.length > 1 && (
                        <button
                          type="button"
                          className="btn-remove-task"
                          onClick={() => removeCustomTask(i)}
                          title="移除此任务"
                        >
                          <X size={14} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-small" onClick={() => { setShowCustomForm(false); setEditingTemplate(null) }}>取消</button>
              <button className="btn-primary" onClick={handleCreateCustom} disabled={!customName.trim() || customTasks.length === 0}>
                {editingTemplate ? `保存修改 (${customTasks.length} 个任务)` : `创建模板 (${customTasks.length} 个任务)`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Full Output Modal */}
      {viewOutput !== null && (
        <div className="modal-overlay" onClick={() => setViewOutput(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 800, maxHeight: '85vh' }}>
            <div className="modal-header">
              <h3>任务输出</h3>
              <button className="modal-close" onClick={() => setViewOutput(null)}><X size={18} /></button>
            </div>
            <div className="modal-body" style={{ maxHeight: '65vh', overflow: 'auto' }}>
              <pre style={{
                fontFamily: 'var(--font-mono)', fontSize: 13, lineHeight: 1.6,
                whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0,
                color: 'var(--color-text)', padding: 16, background: 'var(--color-bg)',
                borderRadius: 'var(--radius-md)',
              }}>{viewOutput}</pre>
            </div>
            <div className="modal-footer">
              <button className="btn-copy" onClick={() => copyToClipboard(viewOutput || '', -1)}>
                <Copy size={14} /> {copiedIndex === -1 ? '已复制' : '复制'}
              </button>
              <button className="btn-small" onClick={() => setViewOutput(null)}>关闭</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
