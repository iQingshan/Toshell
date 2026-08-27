import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Users, ListOrdered, Activity, Clock, Server, Cpu, HardDrive,
  Radio, ArrowUpRight, Bot, Wifi, WifiOff, Monitor, CheckCircle2,
  XCircle, Timer, ChevronRight, RefreshCw,
} from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { sessionApi, taskApi, systemApi, copilotApi } from '../api'
import { useUIStore } from '../stores/uiStore'
import type { Session, TaskStats } from '../types'
import type { WSEvent } from '../hooks/useWebSocket'
import './Dashboard.css'

interface SystemStats {
  hostname: string
  goroutines: number
  go_version: string
  cpu_count: number
  memory: {
    alloc: number
    total_alloc: number
    sys: number
    heap_inuse: number
  }
  sessions: { total: number; active: number }
  uptime: string
  timestamp: string
}

interface TaskBrief {
  id: number
  session_id: string
  task_type: string
  command: string
  status: string
  created_at: string
  output?: string
  error?: string
}

/** 构建会话趋势数据：按小时桶统计最近 24h 的会话上线数 */
function buildTrend(sessions: Session[]): { time: string; count: number }[] {
  const buckets: { time: string; count: number }[] = []
  const now = Date.now()
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now - i * 3600 * 1000)
    buckets.push({ time: `${String(d.getHours()).padStart(2, '0')}:00`, count: 0 })
  }
  for (const s of sessions) {
    const t = new Date(s.first_seen).getTime()
    if (isNaN(t)) continue
    const idx = Math.floor((now - t) / 3600 / 1000)
    if (idx >= 0 && idx < 24) {
      buckets[23 - idx].count++
    }
  }
  return buckets
}

const fmtUptime = (u: string) => (u ? u.replace(/\.\d+/, '') : '-')

const osIcon = (os: string) => {
  const o = (os || '').toLowerCase()
  if (o.includes('windows')) return 'win'
  if (o.includes('linux')) return 'lin'
  if (o.includes('darwin') || o.includes('mac')) return 'mac'
  return 'oth'
}

/** 过长命令安全截断（防止把「最近任务」行撑爆） */
const truncate = (s: string, n = 46) => (s && s.length > n ? s.slice(0, n) + '…' : (s || ''))

export function Dashboard() {
  const navigate = useNavigate()
  const setSelectedSession = useUIStore((s) => s.setSelectedSession)
  const [sessions, setSessions] = useState<Session[]>([])
  const [tasks, setTasks] = useState<TaskBrief[]>([])
  const [taskStats, setTaskStats] = useState<TaskStats | null>(null)
  const [systemStats, setSystemStats] = useState<SystemStats | null>(null)
  const [copilotOk, setCopilotOk] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const wsConnectedRef = useRef(false)

  const fetchData = useCallback(async () => {
    try {
      const [sessionsRes, taskStatsRes, statsRes, tasksRes] = await Promise.all([
        sessionApi.list(),
        taskApi.stats(),
        systemApi.stats(),
        taskApi.list().catch(() => ({ data: { tasks: [] as TaskBrief[] } })),
      ])
      const sessionsData = sessionsRes?.data?.sessions
      setSessions(Array.isArray(sessionsData) ? sessionsData : [])
      setTaskStats(taskStatsRes?.data?.stats ?? null)
      if (statsRes?.data) setSystemStats(statsRes.data)
      const t = (tasksRes?.data as { tasks?: TaskBrief[] })?.tasks
      setTasks(Array.isArray(t) ? t.slice(0, 8) : [])
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  const loadCopilot = useCallback(async () => {
    try {
      const r = await copilotApi.status()
      setCopilotOk(!!r.data?.enabled)
    } catch {
      setCopilotOk(false)
    }
  }, [])

  const handleWSEvent = useCallback((event: WSEvent) => {
    switch (event.type) {
      case 'session_online':
      case 'session_offline':
      case 'task_completed':
      case 'task_failed':
        fetchData()
        break
    }
  }, [fetchData])

  useEffect(() => {
    const token = localStorage.getItem('toshell-token')
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/ws/events?token=${token}`
    const ws = new WebSocket(wsUrl)
    ws.onopen = () => { wsConnectedRef.current = true }
    ws.onmessage = (e) => {
      try { handleWSEvent(JSON.parse(e.data) as WSEvent) } catch { /* ignore */ }
    }
    ws.onclose = () => { wsConnectedRef.current = false }
    return () => { wsConnectedRef.current = false; ws.close() }
  }, [handleWSEvent])

  useEffect(() => {
    fetchData()
    loadCopilot()
    const interval = setInterval(() => { if (!wsConnectedRef.current) fetchData() }, 5000)
    return () => clearInterval(interval)
  }, [fetchData, loadCopilot])

  const trend = useMemo(() => buildTrend(sessions), [sessions])
  const activeSessions = sessions.filter((s) => s.status === 'active').length
  const deadSessions = sessions.length - activeSessions
  const totalTasks = taskStats?.total ?? 0
  const completedTasks = taskStats?.completed ?? 0
  const pendingTasks = taskStats?.pending ?? 0
  const failedTasks = (taskStats?.failed ?? 0) + (taskStats?.timeout ?? 0)
  const settled = completedTasks + failedTasks
  const successRate = settled > 0 ? Math.round((completedTasks / settled) * 100) : 0

  // 内存占用百分比：alloc / sys（进程保留内存）
  const memAlloc = systemStats?.memory?.alloc ?? 0
  const memSys = systemStats?.memory?.sys ?? 0
  const memPct = memSys > 0 ? Math.min(Math.round((memAlloc / memSys) * 100), 100) : 0
  // 堆内存占比：heap_inuse / sys
  const heapInuse = systemStats?.memory?.heap_inuse ?? 0
  const heapPct = memSys > 0 ? Math.min(Math.round((heapInuse / memSys) * 100), 100) : 0

  // 点击最近会话：先写入全局选中态再跳转（会话页打开时右侧详情直接显示该会话）
  const openSession = (s: Session) => {
    setSelectedSession(s)
    navigate(`/sessions/${s.id}`)
  }

  const statusColor = (st: string) =>
    st === 'completed' ? 'ok' : st === 'failed' || st === 'timeout' ? 'err' : 'run'

  return (
    <div className="dashboard">
      {/* 顶栏：欢迎 + 快速入口 */}
      <div className="dash-hero">
        <div className="dash-hero-left">
          <h1>驾驶舱</h1>
          <p>
            <span className="hero-live"><span className="live-dot" /> 实时</span>
            {wsConnectedRef.current ? 'WebSocket 已连接' : '轮询模式'}
          </p>
        </div>
        <div className="dash-hero-actions">
          <button className="hero-btn" onClick={() => navigate('/sessions')}>
            <Users size={15} /> 会话管理
          </button>
          <button className="hero-btn" onClick={() => navigate('/builds')}>
            <Radio size={15} /> 生成载荷
          </button>
          <button className="hero-btn accent" onClick={() => navigate('/copilot')}>
            <Bot size={15} /> AI 副驾驶
            {copilotOk === true && <span className="hero-badge">在线</span>}
            {copilotOk === false && <span className="hero-badge off">未配置</span>}
          </button>
        </div>
      </div>

      {/* 统计卡片 */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon sessions"><Users size={18} /></div>
          <div className="stat-main">
            <span className="stat-spark">总会话</span>
            <span className="stat-value">{loading ? '—' : sessions.length}</span>
          </div>
          <div className="stat-foot">
            <span className="stat-tag ok"><Wifi size={11} /> {activeSessions} 活跃</span>
            <span className="stat-tag muted">{deadSessions} 离线</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon tasks"><ListOrdered size={18} /></div>
          <div className="stat-main">
            <span className="stat-spark">总任务</span>
            <span className="stat-value">{loading ? '—' : totalTasks}</span>
          </div>
          <div className="stat-foot">
            <span className="stat-tag warn"><Clock size={11} /> {pendingTasks} 待执行</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon completed"><CheckCircle2 size={18} /></div>
          <div className="stat-main">
            <span className="stat-spark">成功</span>
            <span className="stat-value">{loading ? '—' : completedTasks}</span>
          </div>
          <div className="stat-foot">
            <span className="stat-tag ok"><Activity size={11} /> 成功率 {successRate}%</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon failed"><XCircle size={18} /></div>
          <div className="stat-main">
            <span className="stat-spark">失败/超时</span>
            <span className="stat-value">{loading ? '—' : failedTasks}</span>
          </div>
          <div className="stat-foot">
            <span className="stat-tag err"><Timer size={11} /> 已结算 {settled}</span>
          </div>
        </div>
      </div>

      {/* 图表 + 系统状态 */}
      <div className="charts-container">
        <div className="chart-card">
          <div className="chart-header">
            <div>
              <h3>会话趋势</h3>
              <span className="chart-subtitle">最近 24 小时上线分布</span>
            </div>
            <span className="chart-total">{sessions.length} 个会话</span>
          </div>
          <div className="chart-body">
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="colorSessions" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#71717a', fontSize: 11 }} interval={3} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#71717a', fontSize: 11 }} allowDecimals={false} width={28} />
                <Tooltip
                  contentStyle={{
                    background: 'var(--color-bg-tertiary)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '8px',
                    color: 'var(--color-text)',
                    fontSize: 12,
                  }}
                  formatter={(v: number) => [`${v} 个`, '上线']}
                  labelFormatter={(l) => `时间 ${l}`}
                />
                <Area type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#colorSessions)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="system-card">
          <div className="chart-header">
            <div>
              <h3>系统状态</h3>
              <span className="chart-subtitle">服务器实时资源</span>
            </div>
            <span className="chart-total mono">{systemStats?.hostname || '—'}</span>
          </div>
          <div className="system-stats">
            <div className="system-stat">
              <div className="system-stat-icon"><Cpu size={20} /></div>
              <div className="system-stat-info">
                <span className="system-stat-label">CPU 核心 / 协程</span>
                <span className="system-stat-value">{systemStats?.cpu_count ?? '—'} 核 · {systemStats?.goroutines ?? '—'} goroutines</span>
              </div>
            </div>

            <div className="system-stat">
              <div className="system-stat-icon mem"><HardDrive size={18} /></div>
              <div className="system-stat-info">
                <span className="system-stat-label">内存占用（{memAlloc} MB / {memSys} MB）</span>
                <div className="progress-bar">
                  <div className="progress-fill memory" style={{ width: `${memPct}%` }} />
                </div>
                <span className="system-stat-value">{memPct}%</span>
              </div>
            </div>

            <div className="system-stat">
              <div className="system-stat-icon heap"><Server size={18} /></div>
              <div className="system-stat-info">
                <span className="system-stat-label">堆内存（{heapInuse} MB / {memSys} MB）</span>
                <div className="progress-bar">
                  <div className="progress-fill disk" style={{ width: `${heapPct}%` }} />
                </div>
                <span className="system-stat-value">{heapPct}%</span>
              </div>
            </div>

            <div className="system-stat">
              <div className="system-stat-icon uptime"><Clock size={18} /></div>
              <div className="system-stat-info">
                <span className="system-stat-label">运行时间</span>
                <span className="system-stat-value">{systemStats?.uptime ? fmtUptime(systemStats.uptime) : '—'}</span>
              </div>
            </div>

            <div className="system-meta">
              <span>Go {systemStats?.go_version || '—'}</span>
              <span>{systemStats?.timestamp ? new Date(systemStats.timestamp).toLocaleTimeString() : '—'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* 最近会话 + 最近任务 */}
      <div className="info-container">
        <div className="panel-card">
          <div className="panel-header">
            <div>
              <h3><Monitor size={16} /> 最近会话</h3>
              <span className="chart-subtitle">点击查看详情</span>
            </div>
            <button className="panel-more" onClick={() => navigate('/sessions')}>
              全部 <ChevronRight size={14} />
            </button>
          </div>
          <div className="panel-list">
            {loading ? (
              <div className="panel-empty"><RefreshCw size={18} className="spin" /> 加载中...</div>
            ) : sessions.length === 0 ? (
              <div className="panel-empty"><WifiOff size={18} /> 暂无会话</div>
            ) : (
              sessions.slice(0, 5).map((s) => (
                <div key={s.id} className="panel-row" onClick={() => openSession(s)}>
                  <span className={`os-badge ${osIcon(s.os)}`}>
                    {osIcon(s.os) === 'win' ? 'W' : osIcon(s.os) === 'lin' ? 'L' : osIcon(s.os) === 'mac' ? 'M' : '?'}
                  </span>
                  <div className="panel-row-main">
                    <span className="panel-row-title">{s.hostname || 'unknown'}</span>
                    <span className="panel-row-sub">{s.os} {s.arch} · {s.username}</span>
                  </div>
                  <div className="panel-row-right">
                    <span className={`status-dot ${s.status === 'active' ? 'online' : 'offline'}`} />
                    <span className="panel-row-time">{new Date(s.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel-card">
          <div className="panel-header">
            <div>
              <h3><ListOrdered size={16} /> 最近任务</h3>
              <span className="chart-subtitle">最新 8 条</span>
            </div>
            <button className="panel-more" onClick={() => navigate('/templates')}>
              全部 <ChevronRight size={14} />
            </button>
          </div>
          <div className="panel-list">
            {loading ? (
              <div className="panel-empty"><RefreshCw size={18} className="spin" /> 加载中...</div>
            ) : tasks.length === 0 ? (
              <div className="panel-empty"><ListOrdered size={18} /> 暂无任务</div>
            ) : (
              tasks.map((t) => (
                <div key={t.id} className="panel-row">
                  <span className={`task-state ${statusColor(t.status)}`} />
                  <div className="panel-row-main">
                    <span className="panel-row-title" title={t.command || t.task_type}>{truncate(t.command) || t.task_type || `#${t.id}`}</span>
                    <span className="panel-row-sub mono">{(t.task_type || 'task')} · #{t.id}</span>
                  </div>
                  <div className="panel-row-right">
                    <span className={`task-tag ${statusColor(t.status)}`}>{t.status}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* 服务器信息条 */}
      <div className="server-strip">
        <div className="server-strip-item"><span>主机</span><strong>{systemStats?.hostname || '—'}</strong></div>
        <div className="server-strip-item"><span>Go</span><strong>{systemStats?.go_version || '—'}</strong></div>
        <div className="server-strip-item"><span>内存</span><strong>{memAlloc} MB</strong></div>
        <div className="server-strip-item"><span>会话</span><strong>{activeSessions} 活跃</strong></div>
        <div className="server-strip-item"><span>监听器</span><strong>{new Set(sessions.map((s) => s.listener)).size || '—'} 类型</strong></div>
        <div className="server-strip-item grow">
          <a className="strip-link" href="/about"><ArrowUpRight size={13} /> 关于 ToShell</a>
        </div>
      </div>
    </div>
  )
}
