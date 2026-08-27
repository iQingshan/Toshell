import { useState, useEffect, useCallback } from 'react'
import { Plus, Power, Play, Pencil, Trash2, Radio, RefreshCw } from 'lucide-react'
import { listenerApi } from '../api'
import type { ListenerInfo } from '../types'
import './Listeners.css'

export function Listeners() {
  const [listeners, setListeners] = useState<ListenerInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [form, setForm] = useState({
    name: '',
    type: 'tcp',
    protocol: 'tcp',
    bind_addr: '0.0.0.0',
    bind_port: 0,
    public_addr: '',
  })

  const fetchListeners = useCallback(async () => {
    try {
      const response = await listenerApi.list()
      const data = response?.data?.listeners || []
      setListeners(Array.isArray(data) ? data : [])
    } catch (error) {
      console.error('Failed to fetch listeners:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setLoading(true)
    fetchListeners()
    const interval = setInterval(fetchListeners, 5000)
    return () => clearInterval(interval)
  }, [fetchListeners])

  const handleCreate = async () => {
    if (!form.name.trim() || form.bind_port <= 0) return
    setActionLoading('create')
    try {
      await listenerApi.create(form)
      setShowModal(false)
      setEditingId(null)
      resetForm()
      fetchListeners()
    } catch (error) {
      console.error('Failed to create listener:', error)
    } finally {
      setActionLoading(null)
    }
  }

  const handleUpdate = async () => {
    if (!editingId || !form.name.trim() || form.bind_port <= 0) return
    setActionLoading('update')
    try {
      await listenerApi.update(editingId, form)
      setShowModal(false)
      setEditingId(null)
      resetForm()
      fetchListeners()
    } catch (error) {
      console.error('Failed to update listener:', error)
    } finally {
      setActionLoading(null)
    }
  }

  const handleStart = async (id: string) => {
    setActionLoading(`start-${id}`)
    try {
      await listenerApi.start(id)
      fetchListeners()
    } catch (error) {
      console.error('Failed to start listener:', error)
    } finally {
      setActionLoading(null)
    }
  }

  const handleStop = async (id: string) => {
    setActionLoading(`stop-${id}`)
    try {
      await listenerApi.stop(id)
      fetchListeners()
    } catch (error) {
      console.error('Failed to stop listener:', error)
    } finally {
      setActionLoading(null)
    }
  }

  const handleDelete = async (id: string) => {
    setActionLoading(`delete-${id}`)
    try {
      await listenerApi.delete(id)
      setDeleteConfirm(null)
      fetchListeners()
    } catch (error) {
      console.error('Failed to delete listener:', error)
    } finally {
      setActionLoading(null)
    }
  }

  const resetForm = () => {
    setForm({ name: '', type: 'tcp', protocol: 'tcp', bind_addr: '0.0.0.0', bind_port: 0, public_addr: '' })
  }

  const openCreateModal = () => {
    setEditingId(null)
    resetForm()
    setShowModal(true)
  }

  const openEditModal = (listener: ListenerInfo) => {
    setEditingId(listener.id)
    // 类型直通：tcp / http / websocket
    const type = listener.type === 'http' ? 'http' : listener.type === 'websocket' ? 'websocket' : 'tcp'
    setForm({
      name: listener.name,
      type,
      protocol: type === 'http' ? 'http' : type === 'websocket' ? 'websocket' : 'tcp',
      bind_addr: listener.bind_addr,
      bind_port: listener.bind_port,
      public_addr: listener.public_addr || '',
    })
    setShowModal(true)
  }

  const formatTime = (ts: number) => {
    return new Date(ts * 1000).toLocaleString()
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'running':
        return <span className="status-badge status-running">运行中</span>
      case 'stopped':
        return <span className="status-badge status-stopped">已停止</span>
      case 'error':
        return <span className="status-badge status-error">错误</span>
      default:
        return <span className="status-badge">{status}</span>
    }
  }

  return (
    <div className="listeners-page">
      <div className="page-header">
        <div className="page-title-area">
          <Radio size={20} />
          <h2>监听器</h2>
          <span className="count-badge">{listeners.length}</span>
        </div>
        <div className="header-actions">
          <button className="refresh-btn" onClick={fetchListeners} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
            刷新
          </button>
          <button className="create-btn" onClick={openCreateModal}>
            <Plus size={16} />
            创建监听器
          </button>
        </div>
      </div>

      <div className="listeners-table-container">
        {loading && listeners.length === 0 ? (
          <div className="empty-state">加载中...</div>
        ) : listeners.length === 0 ? (
          <div className="empty-state">
            <Radio size={48} className="empty-icon" />
            <p>暂无监听器</p>
            <button className="create-btn" onClick={openCreateModal}>
              <Plus size={16} />
              创建第一个监听器
            </button>
          </div>
        ) : (
          <table className="listeners-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>类型</th>
                <th>地址</th>
                <th>状态</th>
                <th>连接数</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {listeners.map((listener) => (
                <tr key={listener.id}>
                  <td className="name-cell">{listener.name}</td>
                  <td>
                    <span className={`badge ${listener.type === 'http' ? 'badge-http' : listener.type === 'websocket' ? 'badge-ws' : listener.type === 'mqtt' ? 'badge-mqtt' : 'badge-tcp'}`}>
                      {listener.type === 'http' ? 'HTTP' : listener.type === 'websocket' ? 'WS' : listener.type === 'mqtt' ? 'MQTT' : 'TCP'}
                    </span>
                  </td>
                  <td className="addr-cell">
                    {listener.public_addr
                      ? `${listener.public_addr}:${listener.bind_port}`
                      : `${listener.bind_addr}:${listener.bind_port}`}
                  </td>
                  <td>{getStatusBadge(listener.status)}</td>
                  <td>{listener.connections}</td>
                  <td className="time-cell">{formatTime(listener.created_at)}</td>
                  <td className="actions-cell">
                    {listener.status === 'running' ? (
                      <button
                        className="action-btn stop-btn"
                        onClick={() => handleStop(listener.id)}
                        disabled={actionLoading === `stop-${listener.id}`}
                        title="停止"
                      >
                        <Power size={14} />
                      </button>
                    ) : (
                      <button
                        className="action-btn start-btn"
                        onClick={() => handleStart(listener.id)}
                        disabled={actionLoading === `start-${listener.id}`}
                        title="启动"
                      >
                        <Play size={14} />
                      </button>
                    )}
                    <button
                      className="action-btn edit-btn"
                      onClick={() => openEditModal(listener)}
                      title="编辑"
                    >
                      <Pencil size={14} />
                    </button>
                    <button
                      className="action-btn delete-btn"
                      onClick={() => setDeleteConfirm(listener.id)}
                      disabled={actionLoading === `delete-${listener.id}`}
                      title="删除"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* 删除确认对话框 */}
      {deleteConfirm && (
        <div className="modal-overlay" onClick={() => setDeleteConfirm(null)}>
          <div className="modal confirm-modal" onClick={(e) => e.stopPropagation()}>
            <h3>确认删除</h3>
            <p>确定要删除此监听器吗？此操作不可撤销。</p>
            <div className="modal-actions">
              <button
                className="cancel-btn"
                onClick={() => setDeleteConfirm(null)}
              >
                取消
              </button>
              <button
                className="delete-confirm-btn"
                onClick={() => handleDelete(deleteConfirm)}
                disabled={actionLoading === `delete-${deleteConfirm}`}
              >
                {actionLoading === `delete-${deleteConfirm}` ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 创建/编辑监听器模态框 */}
      {showModal && (
        <div
          className="modal-overlay"
          onClick={() => { setShowModal(false); setEditingId(null); resetForm() }}
        >
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{editingId ? '编辑监听器' : '创建监听器'}</h3>
            <div className="form-group">
              <label>名称</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="例如: Listener-1"
              />
            </div>
            <div className="form-group">
              <label>类型</label>
              <select
                value={form.type}
                onChange={(e) => {
                  const t = e.target.value
                  // 类型决定回连通道：TCP（二进制帧，轻量）/ HTTP（轮询，可选 HTTPS）
                  // / WebSocket（WS 升级，可穿透部分 WAF/代理白名单）/ MQTT（pub/sub）
                  setForm({ ...form, type: t, protocol: t === 'http' ? 'http' : t === 'websocket' ? 'websocket' : t === 'mqtt' ? 'mqtt' : 'tcp' })
                }}
              >
                <option value="tcp">TCP（二进制帧协议，轻量，推荐）</option>
                <option value="http">HTTP（轮询通道，可配 TLS 变 HTTPS）</option>
                <option value="websocket">WebSocket（WS 升级，穿透白名单）</option>
                <option value="mqtt">MQTT（内嵌 / 外部 broker，pub/sub 通道）</option>
              </select>
              <p className="form-hint">
                TCP：自定义加密帧协议，植入端体积小（约 3.4MB）、全功能；地址填 host:port。
                HTTP：HTTPS 请求形态，可配合「域前置」过域名白名单出口；地址填 https://host:port。
                WebSocket：TSHL 帧 + AES-GCM，传输层为 WS 升级，可穿透部分代理/WAF；植入端地址填 ws://host:port。
                MQTT：走 MQTT pub/sub（默认内嵌 broker），可复用现有 MQTT 基建；地址填 mqtt://host:port。
              </p>
            </div>
            <div className="form-group">
              <label>绑定地址</label>
              <input
                type="text"
                value={form.bind_addr}
                onChange={(e) => setForm({ ...form, bind_addr: e.target.value })}
                placeholder="0.0.0.0"
              />
            </div>
            <div className="form-group">
              <label>绑定端口</label>
              <input
                type="number"
                value={form.bind_port || ''}
                onChange={(e) => setForm({ ...form, bind_port: parseInt(e.target.value) || 0 })}
                placeholder="例如: 8080"
                min={1}
                max={65535}
              />
            </div>
            <div className="form-group">
              <label>公网地址（可选，用于载荷连接）</label>
              <input
                type="text"
                value={form.public_addr}
                onChange={(e) => setForm({ ...form, public_addr: e.target.value })}
                placeholder="例如: 203.0.113.10 或 c2.example.com"
              />
              <p className="form-hint">留空时载荷将使用绑定地址；绑定 0.0.0.0 时回退到 localhost。</p>
            </div>
            <div className="modal-actions">
              <button
                className="cancel-btn"
                onClick={() => { setShowModal(false); setEditingId(null); resetForm() }}
              >
                取消
              </button>
              {editingId ? (
                <button
                  className="create-submit-btn"
                  onClick={handleUpdate}
                  disabled={actionLoading === 'update' || !form.name.trim() || form.bind_port <= 0}
                >
                  {actionLoading === 'update' ? '保存中...' : '保存'}
                </button>
              ) : (
                <button
                  className="create-submit-btn"
                  onClick={handleCreate}
                  disabled={actionLoading === 'create' || !form.name.trim() || form.bind_port <= 0}
                >
                  {actionLoading === 'create' ? '创建中...' : '创建'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
