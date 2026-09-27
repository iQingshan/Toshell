import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Monitor, FolderOpen, Cpu, Network, Terminal, Upload, Shield, Camera, KeyRound, ShieldCheck, Zap, MonitorPlay, Share2, X, Layers, Info } from 'lucide-react'
import { format } from 'date-fns'
import type { Session } from '../types'
import { FileManager } from './FileManager'
import { ProcessList } from './ProcessList'
import { ProcessInjectionTab } from './ProcessInjection'
import { TerminalComponent } from './Terminal'
import { PersistencePanel } from './PersistencePanel'
import { ScreenshotPanel } from './ScreenshotPanel'
import { CredentialsPanel } from './CredentialsPanel'
import { AVDetectTab } from './AVDetectTab'
import { AVOpsPanel } from './AVOpsPanel'
import { FilelessExecPanel } from './FilelessExecPanel'
import { ScreenStreamPanel } from './ScreenStreamPanel'
import { RelayPanel } from './RelayPanel'
import { pluginApi, sessionApi } from '../api'
import { Badge } from './ui'
import './SessionDetail.css'

export type DetailTab = 'info' | 'files' | 'process' | 'injection' | 'shell' | 'bof' | 'persistence' | 'screenshot' | 'credentials' | 'av' | 'avops' | 'fileless' | 'screenstream' | 'relay'

/** 面板声明：key 只是**数据键**（服务端 tabs 里的键、state/URL 里用的键）。 */
export interface TabSpec {
  key: DetailTab
  label: string
  icon: React.ReactNode
  /** 面板内容组件：也放进声明表，省掉 JSX 里再写一遍 `effectiveTab === 'xxx' && <X/>` 链 */
  render: (session: Session) => React.ReactNode
  /**
   * 可用性来源。**缺省 = 与服务端同名**：`GET /api/v1/sessions/{id}/capabilities` 的
   * `tabs[key] === true` 才渲染（服务端 internal/common/features 的 tabFeatures 白名单
   * 才是能力的唯一事实来源，前端不再自己按 OS 推一遍）。
   */
  capability?: {
    /** 依赖的服务端能力键（tabs 里的键） */
    key: string
    /** true = 服务端 tabs 白名单里**没有**这个键，本条是前端本地补充规则（必须写 why） */
    local: true
    why: string
  }
}

/**
 * tab key → 标题 / 图标 / 组件 / 依赖能力 的**唯一**声明表。
 *
 * 允许在这里列全量：**是否渲染完全由服务端能力决定**（见 resolveTabs），这张表只回答
 * "服务端说这个面板可用时，它长什么样、装的是哪个组件"。新增面板 = 在这里加一行。
 */
const TAB_SPECS: TabSpec[] = [
  { key: 'info', label: '信息', icon: <Monitor size={14} />, render: (s) => <SessionInfoTab session={s} /> },
  { key: 'files', label: '文件', icon: <FolderOpen size={14} />, render: (s) => <FileManager session={s} /> },
  { key: 'process', label: '进程', icon: <Cpu size={14} />, render: (s) => <ProcessList session={s} /> },
  { key: 'injection', label: '注入', icon: <Network size={14} />, render: (s) => <ProcessInjectionTab session={s} /> },
  { key: 'shell', label: 'Shell', icon: <Terminal size={14} />, render: (s) => (
    <TerminalComponent
      wsPath={`/api/v1/sessions/${s.id}/shell`}
      title={`Shell - ${s.hostname}`}
      titleHighlight={s.hostname}
      sessionId={s.id}
      showNewTab
    />
  ) },
  { key: 'bof', label: '插件', icon: <Upload size={14} />, render: (s) => <SessionPluginTab session={s} /> },
  { key: 'persistence', label: '持久化', icon: <Shield size={14} />, render: (s) => <PersistencePanel session={s} /> },
  { key: 'screenshot', label: '截图', icon: <Camera size={14} />, render: (s) => <ScreenshotPanel session={s} /> },
  { key: 'credentials', label: '凭据', icon: <KeyRound size={14} />, render: (s) => <CredentialsPanel session={s} /> },
  { key: 'av', label: '杀软', icon: <ShieldCheck size={14} />, render: (s) => <AVDetectTab session={s} /> },
  {
    key: 'avops',
    label: '对抗分级',
    icon: <Layers size={14} />,
    render: (s) => <AVOpsPanel session={s} />,
    // 为什么需要一条**本地**规则：avops（AV-Ops 分级对抗，v1.4.0 S6）是前端新增的
    // "杀软"分级入口，而服务端 features.Tabs() 的 tabFeatures 白名单里**没有**
    // 'avops' 键 —— 它是能力扩展通道而不是独立操作面板，服务端永远不会下发
    // tabs.avops。所以它不能只靠服务端 tabs 判断，这里显式把可用性挂到 'av'
    // 能力上：会话没有杀软能力就不显示对抗分级面板。
    // （面板自身仍会处理接口 404/403：老服务端没有 /av-ops 时给说明而不是白屏。）
    capability: { key: 'av', local: true, why: 'AV-Ops 是「杀软」面板的分级扩展，服务端 tabs 白名单里没有 avops 键，可用性跟随 av 能力' },
  },
  { key: 'fileless', label: '内存', icon: <Zap size={14} />, render: (s) => <FilelessExecPanel session={s} /> },
  { key: 'screenstream', label: '屏幕流', icon: <MonitorPlay size={14} />, render: (s) => <ScreenStreamPanel session={s} /> },
  { key: 'relay', label: '中继', icon: <Share2 size={14} />, render: (s) => <RelayPanel session={s} /> },
]

/** 服务端能力清单状态：server=拿到了 tabs；loading=请求中；degraded=老服务端或接口失败 */
export type CapStatus = 'loading' | 'server' | 'degraded'

/**
 * 服务端能力清单 → 可用面板（**唯一的判定入口**）。
 *
 * - 正常（status=server）：严格按服务端 `capabilities.tabs` 过滤声明表，
 *   `tabs[key] === true` 才渲染；`capability.local` 的键走声明表里写明的本地规则。
 * - 退化（请求中 / tabs 缺失 / 404、403 / 网络错误）：显示**全部**面板，与引入能力清单
 *   之前的行为一致 —— 不猜、不变空页面。注意这不是静默降级：调用方会渲染一条不显眼的
 *   说明（`.detail-tabs-note`）。
 */
export function resolveTabs(status: CapStatus, tabs: Record<string, boolean>): { specs: TabSpec[]; degraded: boolean } {
  if (status !== 'server') {
    return { specs: TAB_SPECS, degraded: status === 'degraded' }
  }
  const specs = TAB_SPECS.filter((spec) => tabs[spec.capability?.key ?? spec.key] === true)
  // 服务端明确说"一个面板都不可用"（tabs 全 false）：保持空列表、由 UI 说明原因，
  // 而不是假装什么都能用（fail-closed，与 Go 侧 features 的口径一致）。
  return { specs, degraded: false }
}

interface SessionDetailProps {
  session: Session
  onClose: () => void
}

export function SessionDetail({ session, onClose }: SessionDetailProps) {
  const [activeTab, setActiveTab] = useState<DetailTab>('info')
  // 服务端能力清单（capabilities.tabs）：可用面板集合的**唯一来源**
  const [capStatus, setCapStatus] = useState<CapStatus>('loading')
  const [capTabs, setCapTabs] = useState<Record<string, boolean>>({})
  const [capError, setCapError] = useState('')
  const tabsRef = useRef<HTMLDivElement | null>(null)
  const tabRefs = useRef<Partial<Record<DetailTab, HTMLButtonElement | null>>>({})
  // 两端是否还有被滚出去的内容（用于渐隐提示；数量少到放得下时两个都是 false）
  const [scrollHints, setScrollHints] = useState({ left: false, right: false })

  // 取服务端能力清单。失败（老服务端 404 / 403 / 网络错误）或 200 但没有 tabs 字段
  // 一律进 degraded：显示全部面板 + 一条说明，绝不静默降级、也不变成空页面。
  useEffect(() => {
    let alive = true
    setCapStatus('loading')
    setCapTabs({})
    setCapError('')
    sessionApi
      .getCapabilities(session.id)
      .then((r) => {
        if (!alive) return
        const tabs = r.data?.tabs
        if (tabs && typeof tabs === 'object') {
          setCapTabs(tabs)
          setCapStatus('server')
        } else {
          setCapStatus('degraded')
        }
      })
      .catch((e: any) => {
        if (!alive) return
        const code = e?.response?.status
        setCapError(code ? `HTTP ${code}` : e instanceof Error ? e.message : String(e))
        setCapStatus('degraded')
      })
    return () => {
      alive = false
    }
  }, [session.id])

  const { specs: availableTabs, degraded } = useMemo(
    () => resolveTabs(capStatus, capTabs),
    [capStatus, capTabs],
  )

  // activeTab 指向的面板已不可用（例如切到没有杀软能力的会话）就回退到第一个可用面板：
  // 常态下第一个就是 'info'，与旧行为一致；但不再假设 'info' 一定存在。
  const effectiveTab: DetailTab = availableTabs.some((t) => t.key === activeTab)
    ? activeTab
    : availableTabs[0]?.key ?? 'info'
  const activeSpec = availableTabs.find((t) => t.key === effectiveTab) ?? null

  /** 切换面板；focus=true 时把焦点移到对应 tab（键盘导航用） */
  const selectTab = useCallback((key: DetailTab, focus = false) => {
    setActiveTab(key)
    if (focus) {
      // tabIndex 随选中态变化，等本次提交之后再聚焦
      requestAnimationFrame(() => tabRefs.current[key]?.focus())
    }
  }, [])

  /** 左右方向键在 tab 间移动（WAI-ARIA tablist 惯例），Home/End 跳首尾 */
  const onTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, idx: number) => {
    const n = availableTabs.length
    let next = -1
    if (e.key === 'ArrowRight') next = (idx + 1) % n
    else if (e.key === 'ArrowLeft') next = (idx - 1 + n) % n
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = n - 1
    if (next < 0) return
    e.preventDefault()
    selectTab(availableTabs[next].key, true)
  }

  /** 重新计算两端渐隐（放得下 / 滚到边界时不留渐隐） */
  const updateScrollHints = useCallback(() => {
    const el = tabsRef.current
    if (!el) return
    const max = el.scrollWidth - el.clientWidth
    setScrollHints({ left: el.scrollLeft > 2, right: max > 2 && el.scrollLeft < max - 2 })
  }, [])

  useEffect(() => {
    const el = tabsRef.current
    updateScrollHints()
    if (!el) return
    el.addEventListener('scroll', updateScrollHints, { passive: true })
    window.addEventListener('resize', updateScrollHints)
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(updateScrollHints) : null
    ro?.observe(el)
    return () => {
      el.removeEventListener('scroll', updateScrollHints)
      window.removeEventListener('resize', updateScrollHints)
      ro?.disconnect()
    }
  }, [updateScrollHints, availableTabs.length, session.id])

  // 选中的 tab 必须留在可见区：tab 多了以后单行横滚，"切到视野外的面板"会看不出当前在哪一页
  useEffect(() => {
    const strip = tabsRef.current
    const el = tabRefs.current[effectiveTab]
    if (!strip || !el) return
    const pad = 8
    const stripBox = strip.getBoundingClientRect()
    const box = el.getBoundingClientRect()
    if (box.left < stripBox.left + pad) {
      strip.scrollBy({ left: box.left - stripBox.left - pad, behavior: 'smooth' })
    } else if (box.right > stripBox.right - pad) {
      strip.scrollBy({ left: box.right - stripBox.right + pad, behavior: 'smooth' })
    }
  }, [effectiveTab, availableTabs.length, session.id])

  const getStatusBadge = (status: string) => {
    const statusMap: Record<string, { label: string; class: string }> = {
      active: { label: '活跃', class: 'success' },
      dead: { label: '离线', class: 'danger' },
      sleep: { label: '休眠', class: 'warning' },
    }
    return statusMap[status] || { label: status, class: '' }
  }

  // 非侵入式说明：只在"降级显示全部面板"或"服务端一个面板都没给"时出现
  const capNote = availableTabs.length === 0
    ? '服务端未报告任何可用面板（capabilities.tabs 为空）'
    : degraded
      ? '能力清单不可用，已显示全部面板'
      : ''
  const capNoteTitle = availableTabs.length === 0
    ? 'GET /api/v1/sessions/{id}/capabilities 返回的 tabs 全为 false：该会话没有服务端认可的操作面板'
    : `GET /api/v1/sessions/{id}/capabilities 未给出 tabs（老服务端或接口失败${capError ? `：${capError}` : ''}），已退化到显示全部面板（与旧版行为一致）`

  // Esc 关闭详情面板
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="session-detail-panel">
      <div className="detail-header">
        <div style={{ minWidth: 0 }}>
          <div className="detail-title">
            <Monitor size={20} />
            <h3>{session.hostname}</h3>
            <Badge tone={session.status === 'active' ? 'ok' : session.status === 'sleep' ? 'warn' : 'danger'}>
              <span className="ui-dot" />
              {getStatusBadge(session.status || '').label}
            </Badge>
          </div>
          {/* 次要信息：面板顶部就能看出"这是哪台机器、什么系统、地址是什么" */}
          <div className="detail-meta">
            <span>{session.os || '未知系统'}{session.arch ? ` / ${session.arch}` : ''}</span>
            {(session as { remote_addr?: string }).remote_addr && (
              <span>· {(session as { remote_addr?: string }).remote_addr}</span>
            )}
            {session.process_name && <span>· {session.process_name}</span>}
            {session.username && <span>· {session.username}</span>}
          </div>
        </div>
        <button className="close-btn" onClick={onClose} title="关闭详情（Esc）">
          <X size={18} />
        </button>
      </div>

      {/* tab 条：**集合来自服务端能力**（TAB_SPECS + resolveTabs），这里不再写死
          `{cond && <Tab/>}`；布局随数量自适应 —— 单行不换行，放不下就横向滚动
          （细滚动条 + 两端渐隐），当前选中的 tab 自动滚进可见区。 */}
      <div
        ref={tabsRef}
        className={
          'detail-tabs' +
          (availableTabs.length > 8 ? ' detail-tabs-dense' : '') +
          (scrollHints.left ? ' can-scroll-left' : '') +
          (scrollHints.right ? ' can-scroll-right' : '')
        }
        role="tablist"
        aria-label="会话面板"
      >
        {availableTabs.map((spec, idx) => {
          const selected = effectiveTab === spec.key
          return (
            <button
              key={spec.key}
              ref={(el) => {
                tabRefs.current[spec.key] = el
              }}
              type="button"
              role="tab"
              id={`detail-tab-${spec.key}`}
              className={`tab-btn ${selected ? 'active' : ''}`}
              aria-selected={selected}
              aria-controls={selected ? `detail-tabpanel-${spec.key}` : undefined}
              tabIndex={selected ? 0 : -1}
              title={spec.label}
              onClick={() => selectTab(spec.key)}
              onKeyDown={(e) => onTabKeyDown(e, idx)}
            >
              {spec.icon} {spec.label}
            </button>
          )
        })}
      </div>

      {/* 降级/空清单说明：不显眼，但不静默 */}
      {capNote && (
        <div className="detail-tabs-note" title={capNoteTitle}>
          <Info size={12} />
          <span>{capNote}</span>
        </div>
      )}

      <div
        className="detail-content"
        /* 有可用面板时才挂 tabpanel 语义：tabs 为空时没有可关联的 tab，不留下悬空引用 */
        role={activeSpec ? 'tabpanel' : undefined}
        id={activeSpec ? `detail-tabpanel-${effectiveTab}` : undefined}
        aria-labelledby={activeSpec ? `detail-tab-${effectiveTab}` : undefined}
      >
        {activeSpec?.render(session)}
      </div>
    </div>
  )
}

/** Session 信息 Tab */
function SessionInfoTab({ session }: { session: Session }) {
  const [comment, setComment] = useState(session.comment || '')
  const [uacBusy, setUacBusy] = useState(false)
  const [uacMsg, setUacMsg] = useState('')

  const runUAC = async () => {
    setUacBusy(true)
    setUacMsg('')
    try {
      const r = await sessionApi.privescUAC(session.id)
      setUacMsg(r.data?.message || '提权任务已下发（等待新会话上线）')
    } catch (e: any) {
      setUacMsg('提权失败: ' + (e?.response?.data?.error || (e instanceof Error ? e.message : String(e))))
    } finally {
      setUacBusy(false)
    }
  }

  return (
    <div className="info-tab">
      <div className="info-grid">
        <div className="info-item">
          <span className="info-label">会话ID</span>
          <span className="info-value mono">{session.id}</span>
        </div>
        <div className="info-item">
          <span className="info-label">主机名</span>
          <span className="info-value">{session.hostname}</span>
        </div>
        <div className="info-item">
          <span className="info-label">用户名</span>
          <span className="info-value">{session.username}</span>
        </div>
        <div className="info-item">
          <span className="info-label">域</span>
          <span className="info-value">{session.domain || '-'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">操作系统</span>
          <span className="info-value">{session.os}</span>
        </div>
        <div className="info-item">
          <span className="info-label">架构</span>
          <span className="info-value">{session.arch}</span>
        </div>
        <div className="info-item">
          <span className="info-label">PID</span>
          <span className="info-value mono">{session.pid || '-'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">进程名</span>
          <span className="info-value mono">{session.process_name || '-'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">远程地址</span>
          <span className="info-value mono">{session.remote_addr || '-'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">监听器</span>
          <span className="info-value">{session.listener || '-'}</span>
        </div>
        <div className="info-item full">
          <span className="info-label">链路</span>
          <span
            className="info-value"
            style={{ color: session.listener?.startsWith('relay') ? '#b48cff' : undefined }}
          >
            {session.listener?.startsWith('relay')
              ? `经中继链回连 · ${session.listener === 'relay' ? 1 : parseInt(session.listener.slice(5)) || 1} 跳${session.parent_relay ? ` · 父中继: ${session.parent_relay}` : ''}`
              : '直连团队服务器'}
          </span>
        </div>
        <div className="info-item full">
          <span className="info-label">IP地址</span>
          <span className="info-value mono">
            {session.ip_addresses?.join(', ') || '-'}
          </span>
        </div>
        <div className="info-item">
          <span className="info-label">首次上线</span>
          <span className="info-value">
            {session.first_seen
              ? format(new Date(session.first_seen), 'yyyy-MM-dd HH:mm:ss')
              : '-'}
          </span>
        </div>
        <div className="info-item">
          <span className="info-label">最后活动</span>
          <span className="info-value">
            {session.last_seen
              ? format(new Date(session.last_seen), 'yyyy-MM-dd HH:mm:ss')
              : '-'}
          </span>
        </div>
        <div className="info-item full">
          <span className="info-label">备注</span>
          <input
            type="text"
            className="comment-input"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="为该会话添加备注..."
          />
        </div>
        {session.os === 'windows' && (
          <div className="info-item full">
            <span className="info-label">提权</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <button className="btn-small btn-primary" onClick={runUAC} disabled={uacBusy} title="fodhelper UAC 绕过：以高完整性内存执行 shellcode 回连上线（需会话为管理员权限）">
                <Zap size={13} /> {uacBusy ? '提权中...' : 'UAC 提权（内存执行并上线）'}
              </button>
              {uacMsg && <span style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)' }}>{uacMsg}</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

/** Session 插件 Tab（内联实现，避免额外依赖） */
function SessionPluginTab({ session }: { session: Session }) {
  const [plugins, setPlugins] = useState<
    { id: string; name: string; type: string; size: number }[]
  >([])
  const [selectedPlugin, setSelectedPlugin] = useState('')
  const [args, setArgs] = useState('')
  const [loading, setLoading] = useState(false)
  const [output, setOutput] = useState('')

  useEffect(() => {
    fetchPlugins()
  }, [])

  const fetchPlugins = async () => {
    try {
      const response = await fetch('/api/v1/plugins', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('toshell-token')}`,
        },
      })
      const data = await response.json()
      setPlugins(data.plugins || [])
    } catch (error) {
      console.error('Failed to fetch plugins:', error)
    }
  }

  const pollTaskResult = async (taskId: number): Promise<string | null> => {
    // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
    const intervals = [0, 200, 300, 500, 1000, 2000]
    for (let i = 0; i < 60; i++) {
      try {
        const response = await fetch(`/api/v1/tasks/${taskId}`, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('toshell-token')}`,
          },
        })
        const task = await response.json()
        if (task.status === 'completed') return task.output
        if (task.status === 'failed') return task.error || '执行失败'
      } catch (e) {}
      await new Promise((r) => setTimeout(r, intervals[Math.min(i, intervals.length - 1)]))
    }
    return '执行超时'
  }

  const handleExecute = async () => {
    if (!selectedPlugin) return
    setLoading(true)
    const plugin = plugins.find((p) => p.id === selectedPlugin)
    setOutput(
      `正在加载插件: ${plugin?.name || selectedPlugin}\n类型: ${plugin?.type || 'unknown'}\n参数: ${args || '(无)'}\n\n正在执行...`
    )
    try {
      const response = await pluginApi.load(session.id, selectedPlugin, args)
      if (response?.data?.task_id) {
        const result = await pollTaskResult(response.data.task_id)
        if (result) {
          setOutput((prev) => prev + '\n\n执行完成!\n输出:\n' + result)
        } else {
          setOutput((prev) => prev + '\n\n执行失败')
        }
      }
    } catch (error: any) {
      setOutput(
        (prev) =>
          prev +
          '\n\n错误: ' +
          (error.response?.data?.error || error.message)
      )
    } finally {
      setLoading(false)
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  }

  return (
    <div className="plugin-tab">
      <div className="plugin-select">
        <label>选择插件:</label>
        <select
          value={selectedPlugin}
          onChange={(e) => setSelectedPlugin(e.target.value)}
        >
          <option value="">-- 请选择插件 --</option>
          {plugins.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.type.toUpperCase()}, {formatSize(p.size)})
            </option>
          ))}
        </select>
        <button className="btn-small" onClick={fetchPlugins}>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
          </svg>
        </button>
      </div>
      <div className="plugin-args">
        <label>参数 (可选):</label>
        <input
          type="text"
          value={args}
          onChange={(e) => setArgs(e.target.value)}
          placeholder="插件参数..."
        />
      </div>
      <button
        className="btn-primary"
        onClick={handleExecute}
        disabled={!selectedPlugin || loading}
      >
        {loading ? '执行中...' : '执行插件'}
      </button>
      <div className="plugin-output">
        <pre>{output || '插件执行输出将显示在这里...'}</pre>
      </div>
    </div>
  )
}
