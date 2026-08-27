import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams } from 'react-router-dom'
import { Search, RefreshCw } from 'lucide-react'
import { SessionTable } from '../components/SessionTable'
import { SessionDetail } from '../components/SessionDetail'
import { sessionApi } from '../api'
import { useUIStore } from '../stores/uiStore'
import type { Session } from '../types'
import type { WSEvent } from '../hooks/useWebSocket'
import './Sessions.css'

export function Sessions() {
  const { id } = useParams<{ id: string }>()
  const [sessions, setSessions] = useState<Session[]>([])
  // 选中会话 + 搜索词提升到全局 store：切换页面后返回时保留状态
  const selectedSession = useUIStore((s) => s.selectedSession)
  const setSelectedSession = useUIStore((s) => s.setSelectedSession)
  const search = useUIStore((s) => s.sessionSearch)
  const setSearch = useUIStore((s) => s.setSessionSearch)
  const [loading, setLoading] = useState(false)
  const wsConnectedRef = useRef(false)
  // ref 镜像选中会话：fetchSessions 读取最新值但不重建回调（避免 WS 重连抖动）
  const selectedRef = useRef<Session | null>(null)
  useEffect(() => { selectedRef.current = selectedSession }, [selectedSession])

  const fetchSessions = useCallback(async () => {
    setLoading(true)
    try {
      const response = await sessionApi.list()
      const data = response?.data?.sessions || []
      const list = Array.isArray(data) ? data : []
      setSessions(list)
      // 同步右侧详情面板数据（心跳/最后在线等字段）
      const cur = selectedRef.current
      if (cur) {
        const updated = list.find((s) => s.id === cur.id)
        if (updated) {
          setSelectedSession({ ...cur, ...updated })
        }
      }
    } catch (error) {
      console.error('Failed to fetch sessions:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  // WebSocket connection for real-time session updates
  useEffect(() => {
    const token = localStorage.getItem('toshell-token')
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/ws/events?token=${token}`
    let reconnectTimer: ReturnType<typeof setTimeout>
    let reconnectAttempts = 0
    const maxReconnectAttempts = 5
    let ws: WebSocket | null = null
    // 僵尸重连防护：组件卸载后禁止任何重连/回调（防旧 WS 复活 + setState）
    let disposed = false

    const connect = () => {
      if (disposed) return
      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        if (disposed) { ws?.close(); return }
        wsConnectedRef.current = true
        reconnectAttempts = 0
      }

      ws.onmessage = (e) => {
        if (disposed) return
        try {
          const event = JSON.parse(e.data) as WSEvent
          switch (event.type) {
            case 'session_online': {
              const payload = event.payload as { id: string; hostname: string; username: string; os: string; arch: string; status: string }
              setSessions(prev => {
                const exists = prev.find(s => s.id === payload.id)
                if (exists) {
                  return prev.map(s => s.id === payload.id ? { ...s, status: 'active', last_seen: new Date().toISOString() } : s)
                }
                // New session - fetch full list for complete data
                fetchSessions()
                return prev
              })
              break
            }
            case 'session_offline': {
              const payload = event.payload as { id: string }
              setSessions(prev =>
                prev.map(s => s.id === payload.id ? { ...s, status: 'dead' } : s)
              )
              // Clear selection if selected session went offline
              if (selectedRef.current?.id === payload.id) {
                setSelectedSession(null)
              }
              break
            }
          }
        } catch {
          // ignore parse errors
        }
      }

      ws.onclose = () => {
        if (disposed) return
        wsConnectedRef.current = false
        if (reconnectAttempts < maxReconnectAttempts) {
          reconnectAttempts++
          reconnectTimer = setTimeout(connect, 3000)
        }
      }
    }

    connect()

    return () => {
      disposed = true
      wsConnectedRef.current = false
      clearTimeout(reconnectTimer)
      ws?.close()
    }
  }, [fetchSessions])

  // 定期刷新会话列表（始终执行，用于刷新心跳 last_seen / 在线状态；
  // 后端心跳只更新 LastSeen 不推送事件，仅靠 WebSocket 无法刷新心跳列）
  useEffect(() => {
    fetchSessions()
    const interval = setInterval(fetchSessions, 10000)
    return () => clearInterval(interval)
  }, [fetchSessions])

  // URL 带会话 ID（如从驾驶舱跳转 /sessions/:id）：列表就绪后自动选中该会话
  useEffect(() => {
    if (!id) return
    if (sessions.length === 0) return
    const target = sessions.find((s) => s.id === id)
    if (target) {
      setSelectedSession({ ...selectedRef.current, ...target })
    }
  }, [id, sessions, setSelectedSession])

  return (
    <div className="sessions-page">
      {/* 搜索栏 */}
      <div className="page-header">
        <div className="search-box">
          <Search size={18} className="search-icon" />
          <input
            type="text"
            placeholder="搜索主机名、用户名或会话ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="header-actions">
          <button className="refresh-btn" onClick={fetchSessions} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
            刷新
          </button>
        </div>
      </div>

      {/* 表格 + 详情面板（并排布局） */}
      <div className="sessions-container">
        <SessionTable
          sessions={sessions}
          selectedSession={selectedSession}
          onSelectSession={setSelectedSession}
          onSessionsChange={setSessions}
          embedded
          searchFilter={search}
        />
        {selectedSession && (
          <SessionDetail
            session={selectedSession}
            onClose={() => setSelectedSession(null)}
          />
        )}
      </div>
    </div>
  )
}
