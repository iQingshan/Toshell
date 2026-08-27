import { useState, useEffect, useMemo, useCallback } from 'react'
import {
  RefreshCw, Users, ListOrdered, LogIn,
  CheckCircle2, XCircle, Clock, Filter, ChevronDown,
} from 'lucide-react'
import { sessionApi, taskApi, logApi } from '../api'
import type { Session, Task, LogEntry } from '../types'
import './Timeline.css'

// 时间线事件（聚合会话/任务/日志三源）
interface TimelineEvent {
  id: string
  time: number
  kind: 'session_online' | 'session_offline' | 'task_completed' | 'task_failed' | 'task_pending' | 'login'
  title: string
  detail: string
  sessionId?: string
  hostname?: string
  severity: 'ok' | 'err' | 'warn' | 'info'
}

/** 全局行动时间线：跨会话统一时间流，操作复盘可视化 */
export function Timeline() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [tasks, setTasks] = useState<Task[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [kindFilter, setKindFilter] = useState<string>('all')
  const [sessionFilter, setSessionFilter] = useState<string>('all')
  const [limit, setLimit] = useState(50)

  const fetchAll = useCallback(async () => {
    setLoading(true)
    try {
      const [sRes, tRes, lRes] = await Promise.all([
        sessionApi.list().catch(() => ({ data: { sessions: [] as Session[] } })),
        taskApi.list().catch(() => ({ data: { tasks: [] as Task[] } })),
        logApi.list(200).catch(() => ({ data: { logs: [] as LogEntry[] } })),
      ])
      setSessions(sRes?.data?.sessions || [])
      setTasks((tRes?.data as { tasks?: Task[] })?.tasks || [])
      setLogs(lRes?.data?.logs || [])
    } catch (e) {
      console.error('Failed to fetch timeline data:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  const hostnameOf = (sid?: string) => sessions.find((s) => s.id === sid)?.hostname || sid || '—'

  // 聚合三源为统一事件流
  const events = useMemo<TimelineEvent[]>(() => {
    const evs: TimelineEvent[] = []

    // 会话：上线（first_seen）/ 状态
    for (const s of sessions) {
      const t = new Date(s.first_seen).getTime()
      if (!isNaN(t)) {
        evs.push({
          id: `s-on-${s.id}`, time: t, kind: 'session_online',
          title: `会话上线：${s.hostname || 'unknown'}`,
          detail: `${s.os || ''} ${s.arch || ''} · ${s.username || ''} · ${s.listener || ''} 监听器`,
          sessionId: s.id, hostname: s.hostname, severity: 'ok',
        })
      }
    }

    // 任务：按状态分类
    for (const t of tasks) {
      const created = new Date(t.created_at).getTime()
      const done = t.completed_at ? new Date(t.completed_at).getTime() : 0
      const tt = (t as unknown as { task_type?: string }).task_type
      const cmd = (t.command || tt || `#${t.id}`).slice(0, 60)
      if (t.status === 'completed' && !isNaN(done)) {
        evs.push({
          id: `t-ok-${t.id}`, time: done, kind: 'task_completed',
          title: `任务完成：${cmd}`,
          detail: `exit=${t.exit_code ?? 0} · ${hostnameOf(t.session_id)}`,
          sessionId: t.session_id, hostname: hostnameOf(t.session_id), severity: 'ok',
        })
      } else if ((t.status === 'failed' || t.status === 'timeout') && !isNaN(done)) {
        evs.push({
          id: `t-err-${t.id}`, time: done, kind: 'task_failed',
          title: `任务失败：${cmd}`,
          detail: `${t.status} · ${hostnameOf(t.session_id)}`,
          sessionId: t.session_id, hostname: hostnameOf(t.session_id), severity: 'err',
        })
      } else if (!isNaN(created)) {
        evs.push({
          id: `t-p-${t.id}`, time: created, kind: 'task_pending',
          title: `任务下发：${cmd}`,
          detail: `${t.status} · ${hostnameOf(t.session_id)}`,
          sessionId: t.session_id, hostname: hostnameOf(t.session_id), severity: 'warn',
        })
      }
    }

    // 日志：登录审计（success/fail）
    for (const l of logs) {
      const t = new Date(l.timestamp).getTime()
      if (isNaN(t)) continue
      const isLogin = (l.message || '').toLowerCase().includes('login')
      const ok = (l.level || '').toLowerCase() !== 'warning'
      if (isLogin) {
        evs.push({
          id: `log-${l.id}-${t}`, time: t, kind: 'login',
          title: ok ? '登录成功' : '登录失败',
          detail: (l.message || '').slice(0, 80),
          severity: ok ? 'info' : 'err',
        })
      }
    }

    // 按时间倒序
    evs.sort((a, b) => b.time - a.time)
    return evs
  }, [sessions, tasks, logs])

  // 筛选
  const filtered = useMemo(() => {
    return events.filter((e) => {
      if (kindFilter !== 'all' && e.kind !== kindFilter) return false
      if (sessionFilter !== 'all' && e.sessionId !== sessionFilter) return false
      return true
    }).slice(0, limit)
  }, [events, kindFilter, sessionFilter, limit])

  const hostnameMap = useMemo(() => {
    const m = new Map<string, string>()
    for (const s of sessions) m.set(s.id, s.hostname || s.id)
    return m
  }, [sessions])

  const kindLabel: Record<string, string> = {
    all: '全部', session_online: '会话上线', session_offline: '会话离线',
    task_completed: '任务完成', task_failed: '任务失败', task_pending: '任务下发', login: '登录',
  }

  const kindIcon = (k: string) => {
    switch (k) {
      case 'session_online': return <Users size={14} />
      case 'task_completed': return <CheckCircle2 size={14} />
      case 'task_failed': return <XCircle size={14} />
      case 'task_pending': return <ListOrdered size={14} />
      case 'login': return <LogIn size={14} />
      default: return <Clock size={14} />
    }
  }

  const fmtTime = (t: number) => {
    const d = new Date(t)
    return d.toLocaleString('zh-CN', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  }

  // 按天分组
  const groups = useMemo(() => {
    const g: { day: string; events: TimelineEvent[] }[] = []
    for (const e of filtered) {
      const day = new Date(e.time).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
      const last = g[g.length - 1]
      if (last && last.day === day) last.events.push(e)
      else g.push({ day, events: [e] })
    }
    return g
  }, [filtered])

  return (
    <div className="timeline-page">
      <div className="timeline-header">
        <div className="timeline-title">
          <Clock size={20} />
          <h1>行动时间线</h1>
          <span className="timeline-count">{filtered.length} 条事件</span>
        </div>
        <div className="timeline-actions">
          <div className="timeline-filter">
            <Filter size={14} />
            <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
              {Object.entries(kindLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div className="timeline-filter">
            <Users size={14} />
            <select value={sessionFilter} onChange={(e) => setSessionFilter(e.target.value)}>
              <option value="all">全部会话</option>
              {[...hostnameMap.entries()].map(([id, hn]) => (
                <option key={id} value={id}>{hn}</option>
              ))}
            </select>
          </div>
          <button className="timeline-refresh" onClick={fetchAll} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> 刷新
          </button>
        </div>
      </div>

      <div className="timeline-body">
        {loading && events.length === 0 ? (
          <div className="timeline-empty"><RefreshCw size={20} className="spin" /> 加载中...</div>
        ) : groups.length === 0 ? (
          <div className="timeline-empty"><Clock size={20} /> 暂无事件</div>
        ) : (
          groups.map((g) => (
            <div key={g.day} className="timeline-day">
              <div className="timeline-day-label">{g.day}</div>
              <div className="timeline-events">
                {g.events.map((e) => (
                  <div key={e.id} className={`timeline-event sev-${e.severity}`}>
                    <div className="timeline-marker">{kindIcon(e.kind)}</div>
                    <div className="timeline-event-main">
                      <div className="timeline-event-title">{e.title}</div>
                      <div className="timeline-event-detail">{e.detail}</div>
                    </div>
                    <div className="timeline-event-time">{fmtTime(e.time)}</div>
                    <span className={`timeline-kind-tag kind-${e.kind}`}>{kindLabel[e.kind] || e.kind}</span>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </div>

      {filtered.length >= limit && (
        <div className="timeline-more">
          <button onClick={() => setLimit((l) => l + 50)}>
            <ChevronDown size={14} /> 加载更多
          </button>
        </div>
      )}
    </div>
  )
}
