import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Trash2, Monitor, Network } from 'lucide-react'
import { sessionApi } from '../api'
import type { Session } from '../types'

interface SessionTableProps {
  sessions: Session[]
  selectedSession: Session | null
  onSelectSession: (session: Session) => void
  onSessionsChange: (sessions: Session[]) => void
  /** 嵌入模式：不渲染外层 sessions-page 和 page-header */
  embedded?: boolean
  /** 外部搜索过滤词（由父组件管理搜索） */
  searchFilter?: string
}

export function SessionTable({
  sessions,
  selectedSession,
  onSelectSession,
  onSessionsChange,
  embedded: _embedded = false,
  searchFilter = '',
}: SessionTableProps) {
  const navigate = useNavigate()

  const filteredSessions = Array.isArray(sessions)
    ? sessions
        .filter(
          (s) =>
            !searchFilter ||
            s.hostname?.toLowerCase().includes(searchFilter.toLowerCase()) ||
            s.username?.toLowerCase().includes(searchFilter.toLowerCase()) ||
            s.id.includes(searchFilter)
        )
        .sort(
          (a, b) => new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime()
        )
    : []

  const [confirmDelete, setConfirmDelete] = useState<Session | null>(null)
  const [deleting, setDeleting] = useState(false)

  // 删除主机：后端会先向植入端推送"exit"任务令其停止运行，再移除会话记录
  const doDelete = async (session: Session) => {
    setDeleting(true)
    try {
      await sessionApi.delete(session.id)
      onSessionsChange(sessions.filter((s) => s.id !== session.id))
      setConfirmDelete(null)
    } catch (error) {
      console.error('Failed to delete session:', error)
    } finally {
      setDeleting(false)
    }
  }

  const [editingId, setEditingId] = useState<string | null>(null)
  const [editingValue, setEditingValue] = useState('')

  const startEdit = (session: Session) => {
    setEditingId(session.id)
    setEditingValue(session.comment || '')
  }

  const saveEdit = async (id: string) => {
    try {
      await sessionApi.update(id, editingValue)
      onSessionsChange(
        sessions.map((s) => (s.id === id ? { ...s, comment: editingValue } : s))
      )
    } catch (error) {
      console.error('Failed to update session comment:', error)
    }
    setEditingId(null)
    setEditingValue('')
  }

  // 每秒触发一次重渲染，让心跳秒数实时走动
  const [, setTick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [])

  const getStatusBadge = (status: string) => {
    const map: Record<string, { label: string; class: string }> = {
      active: { label: '活跃', class: 'success' },
      dead: { label: '离线', class: 'danger' },
      sleep: { label: '休眠', class: 'warning' },
    }
    return map[status] || { label: status, class: '' }
  }

  const getHeartbeat = (lastSeen: string) => {
    if (!lastSeen) return { text: '-', className: '' }
    const seconds = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 1000)
    if (seconds < 0) return { text: '0s', className: 'heartbeat-fresh' }
    if (seconds < 30) return { text: `${seconds}s`, className: 'heartbeat-fresh' }
    if (seconds < 60) return { text: `${seconds}s`, className: 'heartbeat-normal' }
    if (seconds < 90) return { text: `${seconds}s`, className: 'heartbeat-warning' }
    return { text: `${seconds}s`, className: 'heartbeat-danger' }
  }

  const tableEl = (
    <div className="sessions-list-panel">
      <table className="sessions-table">
        <thead>
          <tr><th>#</th><th>备注</th><th>状态</th><th>主机名</th><th>用户</th><th>进程ID</th><th>内网IP</th><th>操作系统</th><th>心跳</th><th>操作</th></tr>
        </thead>
        <tbody>
          {filteredSessions.map((session, index) => (
            <tr
              key={session.id}
              className={selectedSession?.id === session.id ? 'selected' : ''}
              onClick={() => onSelectSession(session)}
            >
              <td><span className="session-index">{index + 1}</span></td>
              <td>
                <div className="comment-cell" onClick={(e) => e.stopPropagation()}>
                  {editingId === session.id ? (
                    <input
                      className="comment-input"
                      value={editingValue}
                      onChange={(e) => setEditingValue(e.target.value)}
                      onBlur={() => saveEdit(session.id)}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.currentTarget.blur() } if (e.key === 'Escape') { setEditingId(null); setEditingValue('') } }}
                      autoFocus
                      placeholder="添加备注"
                    />
                  ) : (
                    <span className="comment-text" title="点击编辑备注" onClick={() => startEdit(session)}>
                      {session.comment || <span className="comment-placeholder">点击添加</span>}
                    </span>
                  )}
                </div>
              </td>
              <td>
                <span className={`status-badge ${getStatusBadge(session.status || '').class}`}>{getStatusBadge(session.status || '').label}</span>
                {session.listener?.startsWith('relay') && (
                  <span
                    className="status-badge"
                    title="经中继链回连（Beacon Mesh）"
                    style={{ marginLeft: 4, background: 'rgba(140,90,255,0.15)', color: '#b48cff', border: '1px solid rgba(140,90,255,0.4)' }}
                  >
                    {session.listener === 'relay' ? '中继' : `中继×${session.listener.slice(5)}`}
                  </span>
                )}
              </td>
              <td><div className="hostname-cell"><Monitor size={16} /><span>{session.hostname || '-'}</span></div></td>
              <td><div className="user-cell"><span className="username">{session.username || '-'}</span><span className="domain">@{session.domain || '-'}</span></div></td>
              <td><span className="mono">{session.pid || '-'}</span></td>
              <td><span className="mono">{session.remote_addr ? session.remote_addr.split(':')[0] : '-'}</span></td>
              <td><div className="os-cell"><span>{session.os || '-'}</span></div></td>
              <td><span className={`heartbeat ${getHeartbeat(session.last_seen).className}`}>{getHeartbeat(session.last_seen).text}</span></td>
              <td><div className="actions">
                <button className="action-btn" title="创建SOCKS5代理" onClick={(e) => { e.stopPropagation(); navigate(`/tunnels?session=${session.id}`) }}><Network size={16} /></button>
                <button className="action-btn danger" title="删除" onClick={(e) => { e.stopPropagation(); setConfirmDelete(session) }}><Trash2 size={16} /></button>
              </div></td>
            </tr>
          ))}
        </tbody>
      </table>
      {filteredSessions.length === 0 && <div className="empty-state"><Network size={48} /><p>暂无会话</p></div>}
    </div>
  )

  return (
    <>
      {tableEl}
      {confirmDelete && (
        <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget && !deleting) setConfirmDelete(null) }}>
          <div className="modal confirm-modal">
            <div className="modal-header">
              <h2>删除主机</h2>
              <button className="close-btn" onClick={() => setConfirmDelete(null)}>×</button>
            </div>
            <div className="modal-body">
              <p className="confirm-text">
                确定要删除主机 <strong>{confirmDelete.hostname || confirmDelete.id}</strong> 吗？
              </p>
              <p className="confirm-warning">
                删除后将发送停止指令，植入端会停止运行，该主机会话记录将被移除，此操作不可恢复。
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn" disabled={deleting} onClick={() => setConfirmDelete(null)}>取消</button>
              <button className="btn btn-danger" disabled={deleting} onClick={() => doDelete(confirmDelete)}>
                {deleting ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
