import { useEffect, useState, useCallback, useRef } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
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
    // 认证可选：留空 = 不启用认证（保持历史行为）。口令只用于创建请求，不回显。
    auth_user: '',
    auth_pass: '',
    // v1.4.1：备注随隧道一起落库，服务端重启恢复后仍能在列表里看到。
    remark: '',
  })
  const [creating, setCreating] = useState(false)
  const [closingId, setClosingId] = useState<string | null>(null)
  const [showTunnelDetails, setShowTunnelDetails] = useState(false)
  const [selectedServer, setSelectedServer] = useState<any>(null)
  const wsConnectedRef = useRef(false)

  const { servers, loading, fetchTunnels, createTunnel, closeTunnel } = useTunnelStore()
  const toast = useToast()

  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()

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
    // 认证字段要么都填、要么都不填；只填一半时明确提示，不把半截配置发给服务端。
    const user = formData.auth_user.trim()
    const pass = formData.auth_pass
    if ((user && !pass) || (!user && pass)) {
      toast.warning('启用认证时用户名与口令都必须填写；留空则不加认证')
      return
    }

    setCreating(true)
    const remark = formData.remark.trim()
    const result = await createTunnel(formData.session_id, formData.local_port, user, pass, remark || undefined)
    setCreating(false)

    if (result.success) {
      // 兼容性 fail-closed：请求了认证但服务端回执没有 auth_enabled=true
      // （老服务端会静默忽略 auth_user/auth_pass）→ 立即停掉这个"裸奔"代理，
      // 明确告知而不是留下一个以为有认证、实际无认证的入口。
      if (user && !result.auth_enabled) {
        await closeTunnel(formData.session_id)
        toast.error('服务端未启用代理认证（服务端版本可能不支持）：已自动停止该代理，避免无认证暴露。请升级服务端后重试。')
        return
      }
      setShowCreate(false)
      toast.success(
        result.auth_enabled
          ? `SOCKS5代理已启动，端口: ${result.local_port}（已启用用户名/口令认证）`
          : `SOCKS5代理已启动，端口: ${result.local_port}（未启用认证）`,
      )
      setFormData({ session_id: '', local_port: 1080, auth_user: '', auth_pass: '', remark: '' })
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
            <div className="form-group">
              <label>认证用户名（可选）</label>
              <input
                type="text"
                autoComplete="off"
                value={formData.auth_user}
                onChange={(e) => setFormData({ ...formData, auth_user: e.target.value })}
                placeholder="留空 = 不启用认证"
                maxLength={255}
              />
            </div>
            <div className="form-group">
              <label>认证口令（可选）</label>
              <input
                type="password"
                autoComplete="new-password"
                value={formData.auth_pass}
                onChange={(e) => setFormData({ ...formData, auth_pass: e.target.value })}
                placeholder="与用户名成对填写"
                maxLength={255}
              />
            </div>
            <div className="form-group">
              <label>备注（可选）</label>
              <input
                type="text"
                autoComplete="off"
                value={formData.remark}
                onChange={(e) => setFormData({ ...formData, remark: e.target.value })}
                placeholder="例如：内网 10.0.0.0/8 出口"
                maxLength={200}
              />
            </div>
          </div>
          <p className="form-hint">
            创建SOCKS5代理后，可通过该代理访问植入端的内网资源。<br/>
            使用方法: 配置代理为 socks5://127.0.0.1:{formData.local_port}
            {formData.auth_user ? `（认证用户 ${formData.auth_user}，口令需在客户端填写）` : ''}<br/>
            认证为可选：<b>仅 SOCKS5 客户端需要填</b>，留空即无认证（老客户端照旧可用）。
            口令只用于配置代理监听器，保存后不会回显；日志里只记录"是否启用认证"。<br/>
            代理已持久化：<b>服务端重启后会自动恢复</b>，恢复出来的条目会标注"已恢复"，无需手工重建。
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
                  <span className={`socks5-auth ${server.auth_enabled ? 'on' : 'off'}`}>
                    {server.auth_enabled ? '认证: 已启用' : '无认证'}
                  </span>
                </div>
                <div className="socks5-actions">
                  {/* 状态（v1.4.1 追加字段）：运行态优先；老服务端没有这些字段时按运行中展示 */}
                  {server.status === 'error' ? (
                    <span className="socks5-status error" title={server.last_error || '恢复失败'}>
                      <span className="status-dot"></span>
                      恢复失败
                    </span>
                  ) : server.listening === false ? (
                    <span className="socks5-status inactive" title={server.last_error || '当前未监听'}>
                      <span className="status-dot"></span>
                      未监听
                    </span>
                  ) : (
                    <span className="socks5-status active">
                      <span className="status-dot"></span>
                      运行中
                    </span>
                  )}
                  {server.restored && (
                    <span className="socks5-auth on" title="服务端重启后按数据库自动恢复，无需手工重建">
                      已恢复
                    </span>
                  )}
                  {server.persisted === false && (
                    <span className="socks5-auth off" title="未落库：服务端重启后会丢失，请检查数据库/加密密钥">
                      未持久化
                    </span>
                  )}
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
                {/* v1.4.3 #16：直接显示归属会话的主机名/用户，会话多了不用再逐个点开对 session_id */}
                {server.session_host ? (
                  <>
                    <button
                      type="button"
                      className="socks5-session-link"
                      title="打开该会话详情"
                      onClick={() => navigate(`/sessions/${server.session_id}`)}
                    >
                      {server.session_host}
                      {server.session_user ? ` · ${server.session_user}` : ''}
                    </button>
                    <span className="socks5-session-id">会话: {server.session_id.slice(0, 16)}...</span>
                    {server.session_alive === false && (
                      <span className="socks5-session-dead" title="该会话已下线，代理已不可用">
                        会话已下线
                      </span>
                    )}
                  </>
                ) : (
                  <>
                    会话: {server.session_id.slice(0, 16)}...{' '}
                    <span className="socks5-session-dead" title="会话管理器里查不到该会话（服务端重启后从库恢复的代理常见）">
                      会话已下线
                    </span>
                  </>
                )}
              </div>
              {server.remark && (
                <div className="socks5-remark">备注: {server.remark}</div>
              )}
              {server.status === 'error' && server.last_error && (
                <div className="socks5-error">
                  恢复失败原因: {server.last_error}
                  （该条已标记 error，其余代理不受影响；释放端口后重启服务端即可重试）
                </div>
              )}
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
                  <span className="info-label">状态:</span>
                  <span className="info-value">
                    {selectedServer.status === 'error'
                      ? '恢复失败（详见列表里的原因）'
                      : selectedServer.listening === false
                        ? '未监听'
                        : '运行中'}
                    {selectedServer.restored ? ' · 重启后自动恢复' : ''}
                    {selectedServer.persisted === false ? ' · 未持久化（重启会丢）' : ''}
                  </span>
                </div>
                {selectedServer.remark && (
                  <div className="info-item">
                    <span className="info-label">备注:</span>
                    <span className="info-value">{selectedServer.remark}</span>
                  </div>
                )}
                <div className="info-item">
                  <span className="info-label">归属会话:</span>
                  <span className="info-value">
                    {selectedServer.session_host
                      ? `${selectedServer.session_host}${selectedServer.session_user ? ' · ' + selectedServer.session_user : ''}`
                      : '已下线（查不到该会话）'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">会话ID:</span>
                  <span className="info-value">{selectedServer.session_id.slice(0, 20)}...</span>
                </div>
                <div className="info-item">
                  <span className="info-label">活动连接数:</span>
                  <span className="info-value">{selectedServer.tunnels.length}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">客户端认证:</span>
                  <span className="info-value">
                    {selectedServer.auth_enabled ? '已启用（SOCKS5 用户名/口令）' : '未启用'}
                  </span>
                </div>
                {selectedServer.auth_enabled && (
                  <div className="info-item">
                    <span className="info-label">客户端填法:</span>
                    <span className="info-value">
                      socks5://用户名:口令@127.0.0.1:{selectedServer.local_port}
                      （口令不会回显，请使用创建时设置的凭据）
                    </span>
                  </div>
                )}
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
