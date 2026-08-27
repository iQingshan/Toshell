import { useState, useEffect } from 'react'
import {
  FileCode, Download, Trash2, RefreshCw,
  Shield, Cpu, Monitor, Server, Copy, CheckCircle2,
} from 'lucide-react'
import axios from 'axios'
import { useToast, ToastContainer } from '../components/Toast'
import { DownloadProgress } from '../components/DownloadProgress'
import './Builds.css'

interface StoredImplant {
  id: string
  name: string
  format: string
  os: string
  arch: string
  protocol: string
  server_url: string
  size: number
  sha256: string
  filename: string
  created_at: number
}

export function Implants() {
  const [implants, setImplants] = useState<StoredImplant[]>([])
  const [loading, setLoading] = useState(true)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  // 下载进度：按载荷 id 标记当前下载
  const [dlProgress, setDlProgress] = useState<{ id: string; percent: number; loaded: number; total: number; done?: boolean } | null>(null)
  const toast = useToast()

  const api = axios.create({
    baseURL: '/api/v1',
    headers: { 'Content-Type': 'application/json' },
  })
  api.interceptors.request.use((config) => {
    const token = localStorage.getItem('toshell-token')
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
  })

  const fetchImplants = async () => {
    setLoading(true)
    try {
      const res = await api.get<{ implants: StoredImplant[] }>('/implants/stored')
      setImplants(res.data.implants || [])
    } catch (err) {
      console.error('Failed to fetch implants:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchImplants()
  }, [])

  const handleDownload = async (imp: StoredImplant) => {
    const id = imp.id
    setDlProgress({ id, percent: 0, loaded: 0, total: 0 })
    try {
      const res = await api.get(`/implants/stored/${id}`, {
        responseType: 'blob',
        onDownloadProgress: (e) => {
          setDlProgress(prev => ({
            id,
            percent: e.total ? Math.min(100, Math.round((e.loaded / e.total) * 100)) : (prev?.percent ?? 0),
            loaded: e.loaded,
            total: e.total || 0,
          }))
        },
      })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = imp.filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      // 下载完成后短暂显示"下载完成"再收起
      setDlProgress({ id, percent: 100, loaded: res.data.size, total: res.data.size, done: true })
      setTimeout(() => setDlProgress(prev => (prev?.id === id ? null : prev)), 900)
      toast.success(`下载成功: ${imp.filename}`)
    } catch (err) {
      console.error('Download failed:', err)
      setDlProgress(prev => (prev?.id === id ? null : prev))
      toast.error('下载失败')
    }
  }

  const handleDelete = async (imp: StoredImplant) => {
    try {
      await api.delete(`/implants/${imp.id}`)
      setImplants(prev => prev.filter(i => i.id !== imp.id))
      toast.success(`已删除: ${imp.name}`)
    } catch (err) {
      console.error('Delete failed:', err)
      toast.error('删除失败')
    }
  }

  const copySHA256 = (sha256: string) => {
    navigator.clipboard.writeText(sha256)
    setCopiedId(sha256)
    setTimeout(() => setCopiedId(null), 1500)
  }

  const formatTime = (ts: number) => {
    const d = new Date(ts * 1000)
    return d.toLocaleString('zh-CN')
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const OS_ICON: Record<string, React.ReactNode> = {
    windows: <Monitor size={14} />,
    linux: <Server size={14} />,
    darwin: <Cpu size={14} />,
  }

  return (
    <div className="builds-page">
      <ToastContainer toasts={toast.toasts} removeToast={toast.removeToast} />
      <div className="page-header">
        <div className="header-title">
          <FileCode size={24} />
          <h1>载荷列表</h1>
          <span style={{
            marginLeft: 12, padding: '2px 10px', borderRadius: 12,
            background: 'var(--color-primary-muted)', color: 'var(--color-primary)',
            fontSize: 13, fontWeight: 500,
          }}>
            {implants.length} 个载荷
          </span>
        </div>
        <div className="header-actions">
          <button className="btn btn-secondary" onClick={fetchImplants}>
            <RefreshCw size={16} className={loading ? 'spinning' : ''} />
            刷新
          </button>
        </div>
      </div>

      <div className="builds-content">
        {implants.length === 0 && !loading ? (
          <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--color-text-muted)' }}>
            <FileCode size={48} style={{ marginBottom: 16, opacity: 0.4 }} />
            <p style={{ fontSize: 16, marginBottom: 8 }}>暂无载荷记录</p>
            <p style={{ fontSize: 13 }}>
              前往 <a href="/builds" style={{ color: 'var(--color-primary)' }}>载荷生成</a> 页面创建新载荷
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {implants.map((imp) => (
              <div key={imp.id} className="build-result-card" style={{ padding: '20px 24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                      <h3 style={{ margin: 0 }}>{imp.name}</h3>
                      <span style={{
                        padding: '2px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                        background: 'var(--color-bg)', border: '1px solid var(--color-border)',
                        color: 'var(--color-text-secondary)', textTransform: 'uppercase',
                      }}>
                        {imp.format}
                      </span>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        padding: '2px 8px', borderRadius: 4, fontSize: 11,
                        background: 'var(--color-bg)', border: '1px solid var(--color-border)',
                        color: 'var(--color-text-secondary)',
                      }}>
                        {OS_ICON[imp.os] || <Cpu size={14} />}
                        {imp.os}/{imp.arch}
                      </span>
                    </div>

                    <div className="result-info" style={{ marginBottom: 0 }}>
                      <div className="result-item">
                        <span className="result-label">大小</span>
                        <span className="result-value">{formatSize(imp.size)}</span>
                      </div>
                      <div className="result-item">
                        <span className="result-label">协议</span>
                        <span className="result-value">{imp.protocol.toUpperCase()}</span>
                      </div>
                      <div className="result-item server-url">
                        <span className="result-label">服务器</span>
                        <span className="result-value">{imp.server_url}</span>
                      </div>
                      <div className="result-item">
                        <span className="result-label">创建时间</span>
                        <span className="result-value">{formatTime(imp.created_at)}</span>
                      </div>
                    </div>

                    {imp.sha256 && (
                      <div style={{
                        marginTop: 10, display: 'flex', alignItems: 'center', gap: 8,
                        fontSize: 12, fontFamily: 'var(--font-mono)',
                        color: 'var(--color-text-muted)',
                      }}>
                        <Shield size={12} />
                        <span style={{ opacity: 0.7 }}>SHA256:</span>
                        <code style={{
                          padding: '1px 6px', borderRadius: 3,
                          background: 'var(--color-bg)', fontSize: 11,
                        }}>
                          {imp.sha256.substring(0, 16)}...
                        </code>
                        <button
                          onClick={() => copySHA256(imp.sha256)}
                          style={{
                            background: 'none', border: 'none', cursor: 'pointer',
                            color: copiedId === imp.sha256 ? 'var(--color-success)' : 'var(--color-text-muted)',
                            padding: 0, display: 'flex',
                          }}
                          title="复制 SHA256"
                        >
                          {copiedId === imp.sha256 ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="build-result-actions" style={{ marginTop: 12 }}>
                  <button className="btn btn-primary" onClick={() => handleDownload(imp)}>
                    <Download size={16} />
                    下载
                  </button>
                  <button className="btn btn-danger" onClick={() => handleDelete(imp)}>
                    <Trash2 size={16} />
                    删除
                  </button>
                </div>
                {dlProgress?.id === imp.id && (
                  <DownloadProgress percent={dlProgress.percent} loaded={dlProgress.loaded} total={dlProgress.total} done={dlProgress.done} />
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
