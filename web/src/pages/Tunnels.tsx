import { useEffect, useState, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Plus, Trash2, RefreshCw, ArrowRight, ArrowLeft, Network, Server, Activity, X, CheckCircle, Loader2 } from 'lucide-react'
import { sessionApi } from '../api'
import { useTunnelStore } from '../stores/tunnel'
import { useToast, ToastContainer } from '../components/Toast'
import type { Session } from '../types'
import type { WSEvent } from '../hooks/useWebSocket'
import './Tunnels.css'

export function Tunnels() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [formData, setFormData] = useState({
    session_id: '',
    local_port: 1080,
  })
  const [creating, setCreating] = useState(false)
  const [closingId, setClosingId] = useState<string | null>(null)
  const [showTunnelDetails, setShowTunnelDetails] = useState(false)
  const [selectedServer, setSelectedServer] = useState<any>(null)
  const wsConnectedRef = useRef(false)

  const { servers, loading, fetchTunnels, createTunnel, closeTunnel } = useTunnelStore()
  const toast = useToast()

  const [searchParams, setSearchParams] = useSearchParams()

  // 从会话列表跳转而来：读取 ?session= 参数，自动选中对应会话并展开创建面板
  useEffect(() => {
    const sid = searchParams.get('session')
    if (sid) {
      setFormData(prev => ({ ...prev, session_id: sid }))
      setShowCreate(true)
      // 消费完参数后清理 URL，避免刷新页面时重复触发
      setSearchParams({}, { replace: true })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, setSearchParams])

  const fetchSessions = useCallback(async () => {
    try {
      const response = await sessionApi.list()
      setSessions(response.data?.sessions || [])
    } catch (error) {
      console.error('Failed to fetch sessions:', error)
    }
  }, [])

  // WebSocket connection for real-time updates
  useEffect(() => {
    const token = localStorage.getItem('toshell-token')
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/ws/events?token=${token}`
    let reconnectTimer: ReturnType<typeof setTimeout>
    let reconnectAttempts = 0
    const maxReconnectAttempts = 5
    let ws: WebSocket | null = null

    const connect = () => {
      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        wsConnectedRef.current = true
        reconnectAttempts = 0
      }

      ws.onmessage = (e) => {
        try {
          const event = JSON.parse(e.data) as WSEvent
          switch (event.type) {
            case 'session_online':
            case 'session_offline':
              // Session state changed, refresh sessions list
              fetchSessions()
              break
            case 'task_completed':
            case 'task_failed':
              // Tasks changed, may affect tunnel state
              fetchTunnels()
              break
          }
        } catch {
          // ignore parse errors
        }
      }

      ws.onclose = () => {
        wsConnectedRef.current = false
        if (reconnectAttempts < maxReconnectAttempts) {
          reconnectAttempts++
          reconnectTimer = setTimeout(connect, 3000)
        }
      }
    }

    connect()

    return () => {
      wsConnectedRef.current = false
      clearTimeout(reconnectTimer)
      ws?.close()
    }
  }, [fetchSessions, fetchTunnels])

  useEffect(() => {
    fetchSessions()
    fetchTunnels()
  }, [fetchSessions, fetchTunnels])

  // Polling fallback when WebSocket is disconnected
  useEffect(() => {
    if (servers.length > 0) {
      const interval = setInterval(() => {
        if (!wsConnectedRef.current) {
          fetchTunnels()
        }
      }, 5000)
      return () => clearInterval(interval)
    }
  }, [servers.length, fetchTunnels])

  const handleCreateSOCKS5 = async () => {
    if (!formData.session_id) {
      toast.warning('请选择一个会话')
      return
    }

    setCreating(true)
    const result = await createTunnel(formData.session_id, formData.local_port)
    setCreating(false)

    if (result.success) {
      setShowCreate(false)
      toast.success(`SOCKS5代理已启动，端口: ${result.local_port}`)
      setFormData({ session_id: '', local_port: 1080 })
    } else {
      toast.error(`创建失败: ${result.error}`)
    }
  }

  const handleCloseSOCKS5 = async (sessionId: string) => {
    setClosingId(sessionId)
    const result = await closeTunnel(sessionId)
    setClosingId(null)

    if (result.success) {
      toast.success('SOCKS5代理已关闭')
    } else {
      toast.error(`关闭失败: ${result.error}`)
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
    return (bytes / 1024 / 1024).toFixed(2) + ' MB'
  }

  const activeSessions = sessions.filter(s => s.status === 'active')
  const totalConnections = servers.reduce((sum, s) => sum + s.tunnels.length, 0)
  const totalBytesIn = servers.reduce((sum, s) => sum + s.tunnels.reduce((s2, t) => s2 + t.bytes_in, 0), 0)
  const totalBytesOut = servers.reduce((sum, s) => sum + s.tunnels.reduce((s2, t) => s2 + t.bytes_out, 0), 0)

  return (
    <div className="tunnels-page">
      <ToastContainer toasts={toast.toasts} removeToast={toast.removeToast} />

      <div className="page-header">
        <h1>隧道代理</h1>
        <div className="header-actions">
          <button className="btn-secondary" onClick={fetchTunnels} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} /> 刷新
          </button>
          <button className="btn-primary" onClick={() => setShowCreate(true)}>
            <Plus size={16} /> 创建SOCKS5代理
          </button>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-icon">
            <Network size={24} />
          </div>
          <div className="stat-card-content">
            <span className="stat-card-value">{servers.length}</span>
            <span className="stat-card-label">代理服务</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon">
            <Activity size={24} />
          </div>
          <div className="stat-card-content">
            <span className="stat-card-value">{totalConnections}</span>
            <span className="stat-card-label">活动连接</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon upload">
            <ArrowRight size={24} />
          </div>
          <div className="stat-card-content">
            <span className="stat-card-value">{formatBytes(totalBytesOut)}</span>
            <span className="stat-card-label">上行流量</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon download">
            <ArrowLeft size={24} />
          </div>
          <div className="stat-card-content">
            <span className="stat-card-value">{formatBytes(totalBytesIn)}</span>
            <span className="stat-card-label">下行流量</span>
          </div>
        </div>
      </div>

      {showCreate && (
        <div className="create-panel">
          <div className="create-panel-header">
            <h3>创建SOCKS5代理隧道</h3>
            <button className="btn-close" onClick={() => setShowCreate(false)}>
              <X size={18} />
            </button>
          </div>
          <div className="form-grid">
            <div className="form-group">
              <label>选择会话</label>
              <select
                value={formData.session_id}
                onChange={(e) => setFormData({ ...formData, session_id: e.target.value })}
              >
                <option value="">请选择会话</option>
                {activeSessions.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.hostname} ({s.username}@{s.os}) - {s.id.slice(0, 8)}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>本地端口</label>
              <input
                type="number"
                value={formData.local_port}
                onChange={(e) => setFormData({ ...formData, local_port: parseInt(e.target.value) || 1080 })}
                placeholder="1080"
              />
            </div>
          </div>
          <p className="form-hint">
            创建SOCKS5代理后，可通过该代理访问植入端的内网资源。<br/>
            使用方法: 配置代理为 socks5://127.0.0.1:{formData.local_port}
          </p>
          <div className="form-actions">
            <button className="btn-secondary" onClick={() => setShowCreate(false)}>取消</button>
            <button 
              className="btn-primary" 
              onClick={handleCreateSOCKS5} 
              disabled={!formData.session_id || creating}
            >
              {creating ? (
                <>
                  <Loader2 size={16} className="spin" /> 创建中...
                </>
              ) : (
                <>
                  <CheckCircle size={16} /> 创建代理
                </>
              )}
            </button>
          </div>
        </div>
      )}

      <div className="tunnel-cards">
        {servers.length === 0 ? (
          <div className="empty-state">
            <Network size={48} />
            <p>暂无SOCKS5代理</p>
            <span>点击"创建SOCKS5代理"开始使用</span>
          </div>
        ) : (
          servers.map((server) => (
            <div key={server.session_id} className="socks5-card">
              <div className="socks5-header">
                <div className="socks5-info">
                  <Network size={20} />
                  <span>SOCKS5代理</span>
                  <span className="socks5-port">端口: {server.local_port}</span>
                </div>
                <div className="socks5-actions">
                  <span className="socks5-status active">
                    <span className="status-dot"></span>
                    运行中
                  </span>
                  <button 
                    className="btn-secondary"
                    onClick={() => {
                      setSelectedServer(server);
                      setShowTunnelDetails(true);
                    }}
                  >
                    <Activity size={14} />
                    活动连接 ({server.tunnels.length})
                  </button>
                  <button 
                    className="btn-danger" 
                    onClick={() => handleCloseSOCKS5(server.session_id)}
                    disabled={closingId === server.session_id}
                  >
                    {closingId === server.session_id ? (
                      <Loader2 size={14} className="spin" />
                    ) : (
                      <Trash2 size={14} />
                    )}
                    停止
                  </button>
                </div>
              </div>
              <div className="socks5-session">
                会话: {server.session_id.slice(0, 16)}...
              </div>
            </div>
          ))
        )}
      </div>

      {/* 活动连接详细信息弹出窗口 */}
      {showTunnelDetails && selectedServer && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>活动连接详情</h3>
              <button className="btn-close" onClick={() => setShowTunnelDetails(false)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body">
              <div className="server-info">
                <div className="info-item">
                  <span className="info-label">代理端口:</span>
                  <span className="info-value">{selectedServer.local_port}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">会话ID:</span>
                  <span className="info-value">{selectedServer.session_id.slice(0, 20)}...</span>
                </div>
                <div className="info-item">
                  <span className="info-label">活动连接数:</span>
                  <span className="info-value">{selectedServer.tunnels.length}</span>
                </div>
              </div>
              
              <div className="tunnel-details-list">
                {selectedServer.tunnels.length === 0 ? (
                  <p className="no-connections">暂无活动连接</p>
                ) : (
                  selectedServer.tunnels.map((tunnel: any) => (
                    <div key={tunnel.id} className={`tunnel-detail-item ${tunnel.active ? 'active' : 'inactive'}`}>
                      <div className="tunnel-detail-header">
                        <div className="tunnel-target">
                          <Server size={16} />
                          <span>{tunnel.target_addr}:{tunnel.target_port}</span>
                        </div>
                        <span className={`tunnel-status ${tunnel.active ? 'active' : 'inactive'}`}>
                          {tunnel.active ? '活动' : '非活动'}
                        </span>
                      </div>
                      <div className="tunnel-detail-stats">
                        <div className="stat-row">
                          <span className="stat-label">创建时间:</span>
                          <span className="stat-value">{new Date(tunnel.created_at).toLocaleString()}</span>
                        </div>
                        <div className="stat-row">
                          <span className="stat-label">上行流量:</span>
                          <span className="stat-value">{formatBytes(tunnel.bytes_out)}</span>
                        </div>
                        <div className="stat-row">
                          <span className="stat-label">下行流量:</span>
                          <span className="stat-value">{formatBytes(tunnel.bytes_in)}</span>
                        </div>
                        <div className="stat-row">
                          <span className="stat-label">总流量:</span>
                          <span className="stat-value">{formatBytes(tunnel.bytes_in + tunnel.bytes_out)}</span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-primary" onClick={() => setShowTunnelDetails(false)}>
                关闭
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
